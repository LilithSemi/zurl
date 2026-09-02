//! RFC 9204 Appendix B, worked example by worked example.
//!
//! The appendix is one exchange between an encoder and a decoder, run over
//! five sections. It gives the octets of every encoder instruction, every
//! encoded field section, and every decoder instruction, and it gives the
//! state of the dynamic table after each step, with the absolute index of
//! each entry and the size of the whole table. This file checks all of it,
//! byte for byte and entry for entry. It holds no implementation of its
//! own.
//!
//! **The five examples are one connection.** So they run on one decoder in
//! order, the way a real connection does, and the table is checked at
//! every step. A section decoded on its own decodes to something else,
//! which is the point of the dynamic table.
//!
//! **Every octet here is the RFC's own.** The hex dumps are copied out of
//! the appendix and read by `hex` at compile time, so what these tests
//! compare against is what the document says and not what this package
//! produces.
//!
//! This file also holds the round trip property: what `encoder` writes,
//! `Decoder` reads back as the same field list.

const std = @import("std");

const Decoder = @import("Decoder.zig");
const DynamicTable = @import("DynamicTable.zig");
const decoder_stream = @import("decoder_stream.zig");
const encoder = @import("encoder.zig");
const encoder_stream = @import("encoder_stream.zig");
const field = @import("field.zig");
const integer = @import("integer.zig");
const prefix = @import("prefix.zig");
const string = @import("string.zig");

const Allocator = std.mem.Allocator;
const testing = std.testing;

/// The dynamic table capacity RFC 9204 Appendix B sets, and the one the
/// decoder in these tests agrees to.
const example_capacity = 220;

/// MaxEntries for that capacity, which is what the field section prefix
/// folds the Required Insert Count with.
const example_max_entries = example_capacity / 32;

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

// The octets of Appendix B, as the document prints them.

/// B.1, stream 0.
const b1_section = hex(
    \\0000
    \\510b 2f69 6e64 6578
    \\2e68 746d 6c
);

/// B.2, the encoder stream.
const b2_encoder = hex(
    \\3fbd01
    \\c00f 7777 772e 6578
    \\616d 706c 652e 636f
    \\6d
    \\c10c 2f73 616d 706c
    \\652f 7061 7468
);

/// B.2, stream 4.
const b2_section = hex(
    \\0381
    \\10
    \\11
);

/// B.2, the decoder stream.
const b2_decoder = hex("84");

/// B.3, the encoder stream.
const b3_encoder = hex(
    \\4a63 7573 746f 6d2d
    \\6b65 790c 6375 7374
    \\6f6d 2d76 616c 7565
);

/// B.3, the decoder stream.
const b3_decoder = hex("01");

/// B.4, the encoder stream.
const b4_encoder = hex("02");

/// B.4, stream 8.
const b4_section = hex(
    \\0500
    \\80
    \\c1
    \\81
);

/// B.4, the decoder stream.
const b4_decoder = hex("48");

/// B.5, the encoder stream.
const b5_encoder = hex(
    \\810d 6375 7374 6f6d
    \\2d76 616c 7565 32
);

/// One row of a dynamic table listing in the appendix.
const Row = struct {
    /// The Abs column, which is the absolute index of RFC 9204 section
    /// 3.2.4.
    abs: u64,
    name: []const u8,
    value: []const u8,
};

/// Checks the decoder's dynamic table against the listing the appendix
/// prints after a step.
fn expectTable(decoder: Decoder, rows: []const Row, want_size: usize) !void {
    const none: ?DynamicTable.Entry = null;
    try testing.expectEqual(@as(u64, rows.len), decoder.table.count());
    try testing.expectEqual(want_size, decoder.table.size);
    for (rows) |row| {
        const entry = decoder.table.get(row.abs) orelse return error.MissingEntry;
        try testing.expectEqualStrings(row.name, entry.name);
        try testing.expectEqualStrings(row.value, entry.value);
    }
    // Nothing sits on either side of the listing.
    if (rows.len != 0 and rows[0].abs != 0) {
        try testing.expectEqual(none, decoder.table.get(rows[0].abs - 1));
    }
    try testing.expectEqual(none, decoder.table.get(decoder.table.inserted));
}

/// Checks one field line against the interpretation column.
fn expectField(list: field.List, index: usize, name: []const u8, value: []const u8) !void {
    try testing.expect(list.fields.items.len > index);
    try testing.expectEqualStrings(name, list.fields.items[index].name);
    try testing.expectEqualStrings(value, list.fields.items[index].value);
}

/// The decoder these examples run on, at the capacity the appendix uses.
fn exampleDecoder() Decoder {
    return .init(.{ .table_capacity_max = example_capacity });
}

test "RFC 9204 Appendix B, the whole exchange in order on one decoder" {
    const gpa = testing.allocator;
    var decoder = exampleDecoder();
    defer decoder.deinit(gpa);

    var scratch: [integer.encoded_len_max]u8 = undefined;

    // B.1. A literal field line with a static name reference, on a
    // connection where nothing has touched the dynamic table.
    {
        var section = try decoder.decodeSection(gpa, b1_section);
        defer section.deinit(gpa);

        try testing.expectEqual(@as(usize, 1), section.list.fields.items.len);
        try expectField(section.list, 0, ":path", "/index.html");
        try testing.expectEqual(@as(u64, 0), section.required_insert_count);
        try expectTable(decoder, &.{}, 0);

        // RFC 9204 section 4.4.1: a Required Insert Count of zero gets no
        // Section Acknowledgment.
        try testing.expectEqual(
            @as(?decoder_stream.Instruction, null),
            decoder.takeSectionAcknowledgment(0, &section),
        );
    }

    // B.2. Set the capacity, insert two entries with a static name
    // reference, then a field section that names both.
    {
        try testing.expectEqual(b2_encoder.len, try decoder.readEncoderStream(gpa, b2_encoder));
        try testing.expectEqual(@as(usize, example_capacity), decoder.table.capacity);
        try expectTable(decoder, &.{
            .{ .abs = 0, .name = ":authority", .value = "www.example.com" },
            .{ .abs = 1, .name = ":path", .value = "/sample/path" },
        }, 106);

        var section = try decoder.decodeSection(gpa, b2_section);
        defer section.deinit(gpa);

        try testing.expectEqual(@as(u64, 2), section.required_insert_count);
        try testing.expectEqual(@as(u64, 0), section.base);
        try testing.expectEqual(@as(usize, 2), section.list.fields.items.len);
        try expectField(section.list, 0, ":authority", "www.example.com");
        try expectField(section.list, 1, ":path", "/sample/path");
        // A field line representation changes no table.
        try expectTable(decoder, &.{
            .{ .abs = 0, .name = ":authority", .value = "www.example.com" },
            .{ .abs = 1, .name = ":path", .value = "/sample/path" },
        }, 106);

        // The decoder stream: Section Acknowledgment for stream 4, which
        // implicitly acknowledges both inserts.
        const ack = decoder.takeSectionAcknowledgment(4, &section).?;
        try testing.expectEqualSlices(u8, b2_decoder, decoder_stream.write(ack, &scratch));
        try testing.expectEqual(@as(u64, 2), decoder.reported_inserts);
        try testing.expectEqual(
            @as(?decoder_stream.Instruction, null),
            decoder.takeInsertCountIncrement(),
        );
    }

    // B.3. A speculative insert with a literal name, and no field section.
    {
        try testing.expectEqual(b3_encoder.len, try decoder.readEncoderStream(gpa, b3_encoder));
        try expectTable(decoder, &.{
            .{ .abs = 0, .name = ":authority", .value = "www.example.com" },
            .{ .abs = 1, .name = ":path", .value = "/sample/path" },
            .{ .abs = 2, .name = "custom-key", .value = "custom-value" },
        }, 160);

        // The decoder stream: Insert Count Increment of one.
        const increment = decoder.takeInsertCountIncrement().?;
        try testing.expectEqualSlices(u8, b3_decoder, decoder_stream.write(increment, &scratch));
        try testing.expectEqual(@as(u64, 3), decoder.reported_inserts);
    }

    // B.4. A duplicate, then a field section that names the duplicate, a
    // static entry, and a dynamic entry, and then a stream cancellation.
    {
        try testing.expectEqual(b4_encoder.len, try decoder.readEncoderStream(gpa, b4_encoder));
        try expectTable(decoder, &.{
            .{ .abs = 0, .name = ":authority", .value = "www.example.com" },
            .{ .abs = 1, .name = ":path", .value = "/sample/path" },
            .{ .abs = 2, .name = "custom-key", .value = "custom-value" },
            .{ .abs = 3, .name = ":authority", .value = "www.example.com" },
        }, 217);

        var section = try decoder.decodeSection(gpa, b4_section);
        defer section.deinit(gpa);

        try testing.expectEqual(@as(u64, 4), section.required_insert_count);
        try testing.expectEqual(@as(u64, 4), section.base);
        try testing.expectEqual(@as(usize, 3), section.list.fields.items.len);
        try expectField(section.list, 0, ":authority", "www.example.com");
        try expectField(section.list, 1, ":path", "/");
        try expectField(section.list, 2, "custom-key", "custom-value");

        // The decoder stream: Stream Cancellation for stream 8. The
        // section was not processed, so there is no acknowledgment.
        const cancel = Decoder.streamCancellation(8);
        try testing.expectEqualSlices(u8, b4_decoder, decoder_stream.write(cancel, &scratch));
    }

    // B.5. An insert with a dynamic name reference, which evicts the
    // oldest entry.
    {
        try testing.expectEqual(b5_encoder.len, try decoder.readEncoderStream(gpa, b5_encoder));
        try expectTable(decoder, &.{
            .{ .abs = 1, .name = ":path", .value = "/sample/path" },
            .{ .abs = 2, .name = "custom-key", .value = "custom-value" },
            .{ .abs = 3, .name = ":authority", .value = "www.example.com" },
            .{ .abs = 4, .name = "custom-key", .value = "custom-value2" },
        }, 215);
    }
}

test "RFC 9204 B.1, this encoder writes the RFC's own octets" {
    var out: [64]u8 = undefined;
    const fields = [_]field.Field{.{ .name = ":path", .value = "/index.html" }};
    const written = encoder.encode(&fields, .{ .coding = .raw }, &out);

    try testing.expectEqualSlices(u8, b1_section, written);
}

test "RFC 9204 B.2 and B.5, the encoder stream writer writes the RFC's own octets" {
    var out: [64]u8 = undefined;
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(testing.allocator);
    const gpa = testing.allocator;

    try stream.appendSlice(gpa, encoder_stream.writeSetCapacity(220, &out));
    try stream.appendSlice(gpa, encoder_stream.writeInsertWithNameReference(
        .static,
        0,
        "www.example.com",
        .raw,
        &out,
    ));
    try stream.appendSlice(gpa, encoder_stream.writeInsertWithNameReference(
        .static,
        1,
        "/sample/path",
        .raw,
        &out,
    ));
    try testing.expectEqualSlices(u8, b2_encoder, stream.items);

    try testing.expectEqualSlices(
        u8,
        b3_encoder,
        encoder_stream.writeInsertWithLiteralName("custom-key", "custom-value", .raw, &out),
    );
    try testing.expectEqualSlices(u8, b4_encoder, encoder_stream.writeDuplicate(2, &out));
    try testing.expectEqualSlices(
        u8,
        b5_encoder,
        encoder_stream.writeInsertWithNameReference(.dynamic, 1, "custom-value2", .raw, &out),
    );
}

test "RFC 9204 B.2 through B.4, the decoder stream writer writes the RFC's own octets" {
    var out: [integer.encoded_len_max]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        b2_decoder,
        decoder_stream.write(.{ .section_acknowledgment = 4 }, &out),
    );
    try testing.expectEqualSlices(
        u8,
        b3_decoder,
        decoder_stream.write(.{ .insert_count_increment = 1 }, &out),
    );
    try testing.expectEqualSlices(
        u8,
        b4_decoder,
        decoder_stream.write(.{ .stream_cancellation = 8 }, &out),
    );
}

test "RFC 9204 B.2, the field section means nothing without the encoder stream" {
    const gpa = testing.allocator;
    var decoder = exampleDecoder();
    defer decoder.deinit(gpa);

    // The same octets against a table the encoder stream never built. This
    // decoder allows no blocked stream, so it says so rather than waiting.
    try testing.expectError(error.Blocked, decoder.decodeSection(gpa, b2_section));
}

test "RFC 9204 B.4, the field section means nothing without the duplicate" {
    const gpa = testing.allocator;
    var decoder = exampleDecoder();
    defer decoder.deinit(gpa);

    _ = try decoder.readEncoderStream(gpa, b2_encoder);
    _ = try decoder.readEncoderStream(gpa, b3_encoder);
    try testing.expectEqual(@as(u64, 3), decoder.table.inserted);

    // The section needs four inserts and only three have arrived.
    try testing.expectError(error.Blocked, decoder.decodeSection(gpa, b4_section));
}

test "the encoder stream of Appendix B is read one octet at a time" {
    const gpa = testing.allocator;
    var whole = exampleDecoder();
    defer whole.deinit(gpa);
    var dripped = exampleDecoder();
    defer dripped.deinit(gpa);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    try stream.appendSlice(gpa, b2_encoder);
    try stream.appendSlice(gpa, b3_encoder);
    try stream.appendSlice(gpa, b4_encoder);
    try stream.appendSlice(gpa, b5_encoder);

    _ = try whole.readEncoderStream(gpa, stream.items);

    var taken: usize = 0;
    var seen: usize = 0;
    while (seen < stream.items.len) {
        seen += 1;
        taken += try dripped.readEncoderStream(gpa, stream.items[taken..seen]);
    }

    try testing.expectEqual(stream.items.len, taken);
    try testing.expectEqual(whole.table.inserted, dripped.table.inserted);
    try testing.expectEqual(whole.table.dropped, dripped.table.dropped);
    try testing.expectEqual(whole.table.size, dripped.table.size);

    var abs = whole.table.dropped;
    while (abs < whole.table.inserted) : (abs += 1) {
        try testing.expectEqualStrings(whole.table.get(abs).?.name, dripped.table.get(abs).?.name);
        try testing.expectEqualStrings(whole.table.get(abs).?.value, dripped.table.get(abs).?.value);
    }
}

/// The field lists the round trip runs over.
const round_trip_cases = [_][]const field.Field{
    &.{},
    &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    },
    &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/html; charset=utf-8" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    },
    &.{
        .{ .name = "custom-key", .value = "custom-value" },
        .{ .name = "x-empty", .value = "" },
        .{ .name = "cookie", .value = "a=1" },
        .{ .name = "cookie", .value = "b=2" },
    },
    &.{
        .{ .name = "authorization", .value = "Bearer abc", .never_indexed = true },
        .{ .name = "x-secret", .value = "s", .never_indexed = true },
        .{ .name = ":method", .value = "GET", .never_indexed = true },
    },
};

test "what this encoder writes, this decoder reads back" {
    const gpa = testing.allocator;
    for (round_trip_cases) |fields| {
        inline for ([_]string.Coding{ .raw, .huffman_when_shorter }) |coding| {
            const block = try encoder.encodeAlloc(gpa, fields, .{ .coding = coding });
            defer gpa.free(block);

            var decoder: Decoder = .init(.{});
            defer decoder.deinit(gpa);

            var section = try decoder.decodeSection(gpa, block);
            defer section.deinit(gpa);

            try testing.expectEqual(fields.len, section.list.fields.items.len);
            for (fields, section.list.fields.items) |want, got| {
                try testing.expectEqualStrings(want.name, got.name);
                try testing.expectEqualStrings(want.value, got.value);
                try testing.expectEqual(want.never_indexed, got.never_indexed);
            }
        }
    }
}

test "a value holding every octet value round-trips" {
    const gpa = testing.allocator;
    var all: [256]u8 = undefined;
    for (&all, 0..) |*slot, index| slot.* = @intCast(index);

    const fields = [_]field.Field{.{ .name = "x-octets", .value = &all }};
    inline for ([_]string.Coding{ .raw, .huffman_when_shorter }) |coding| {
        const block = try encoder.encodeAlloc(gpa, &fields, .{ .coding = coding });
        defer gpa.free(block);

        var decoder: Decoder = .init(.{});
        defer decoder.deinit(gpa);

        var section = try decoder.decodeSection(gpa, block);
        defer section.deinit(gpa);
        try testing.expectEqualSlices(u8, &all, section.list.fields.items[0].value);
    }
}

test "a field list as long as the count bound round-trips, and one longer does not" {
    const gpa = testing.allocator;
    var fields: [Decoder.field_count_max]field.Field = undefined;
    for (&fields) |*slot| slot.* = .{ .name = ":method", .value = "GET" };

    const block = try encoder.encodeAlloc(gpa, &fields, .{});
    defer gpa.free(block);

    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    var section = try decoder.decodeSection(gpa, block);
    defer section.deinit(gpa);
    try testing.expectEqual(@as(usize, Decoder.field_count_max), section.list.fields.items.len);

    var one_more: [Decoder.field_count_max + 1]field.Field = undefined;
    for (&one_more) |*slot| slot.* = .{ .name = ":method", .value = "GET" };

    const longer = try encoder.encodeAlloc(gpa, &one_more, .{});
    defer gpa.free(longer);
    try testing.expectError(error.TooManyHeaderFields, decoder.decodeSection(gpa, longer));
}

test "the static table is reachable from a section this encoder writes" {
    // Every entry of RFC 9204 Appendix A goes out as one indexed field
    // line, and comes back as itself.
    const gpa = testing.allocator;
    const static_table = @import("static_table.zig");

    for (static_table.entries) |entry| {
        const fields = [_]field.Field{.{ .name = entry.name, .value = entry.value }};
        const block = try encoder.encodeAlloc(gpa, &fields, .{});
        defer gpa.free(block);

        var decoder: Decoder = .init(.{});
        defer decoder.deinit(gpa);

        var section = try decoder.decodeSection(gpa, block);
        defer section.deinit(gpa);

        try testing.expectEqualStrings(entry.name, section.list.fields.items[0].name);
        try testing.expectEqualStrings(entry.value, section.list.fields.items[0].value);
    }
}

// The round trip above only reaches what this build's encoder writes, and
// this encoder never inserts. So every section it makes has a Required
// Insert Count of zero and a Base of zero, and the four things that need a
// dynamic table are untouched by it: a non-zero Base, a post-base index,
// the fold of RFC 9204 section 4.5.1.1, and eviction. The tests below build
// those sections by hand, the way a peer's encoder would.

/// Writes a Set Dynamic Table Capacity and `count` inserts with a literal
/// name into `out`, which the caller owns.
///
/// Entry `i` is named "n" and the `i`-th lower case letter, so the name
/// says the absolute index it took.
fn buildInserts(gpa: Allocator, count: usize, out: *std.ArrayList(u8)) !void {
    std.debug.assert(count <= 26);
    var scratch: [64]u8 = undefined;
    try out.appendSlice(gpa, encoder_stream.writeSetCapacity(example_capacity, &scratch));

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const letter: u8 = @intCast('a' + i);
        const name = [_]u8{ 'n', letter };
        const value = [_]u8{ 'v', letter };
        try out.appendSlice(
            gpa,
            encoder_stream.writeInsertWithLiteralName(&name, &value, .raw, &scratch),
        );
    }
}

test "a section over the dynamic table round-trips at a non-zero Base and past it" {
    const gpa = testing.allocator;
    var decoder = exampleDecoder();
    defer decoder.deinit(gpa);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    try buildInserts(gpa, 3, &stream);
    try testing.expectEqual(stream.items.len, try decoder.readEncoderStream(gpa, stream.items));
    try testing.expectEqual(@as(u64, 3), decoder.table.inserted);
    try testing.expectEqual(@as(u64, 0), decoder.table.dropped);

    // Required Insert Count 3 and Base 2. Absolute index 2 sits at the
    // Base, so only a post-base index reaches it.
    var scratch: [64]u8 = undefined;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, prefix.encode(
        .{ .required_insert_count = 3, .base = 2 },
        example_max_entries,
        &scratch,
    ));
    // Section 4.5.2, an indexed field line at dynamic relative index 0,
    // which is absolute index Base - 1 = 1.
    try block.append(gpa, 0x80);
    // Section 4.5.3, an indexed field line at post-base index 0, which is
    // absolute index Base = 2.
    try block.append(gpa, 0x10);
    // Section 4.5.5, a literal field line at post-base name reference 0.
    try block.append(gpa, 0x00);
    try block.appendSlice(gpa, string.encode(8, 0, "over", .raw, &scratch));
    // Section 4.5.4, a literal field line at dynamic name reference 1,
    // which is absolute index 0.
    try block.append(gpa, 0x41);
    try block.appendSlice(gpa, string.encode(8, 0, "under", .raw, &scratch));

    var section = try decoder.decodeSection(gpa, block.items);
    defer section.deinit(gpa);

    try testing.expectEqual(@as(u64, 3), section.required_insert_count);
    try testing.expectEqual(@as(u64, 2), section.base);
    try testing.expectEqual(@as(usize, 4), section.list.fields.items.len);
    try expectField(section.list, 0, "nb", "vb");
    try expectField(section.list, 1, "nc", "vc");
    try expectField(section.list, 2, "nc", "over");
    try expectField(section.list, 3, "na", "under");

    // The section named dynamic entries, so it owes the peer one
    // acknowledgment and no more.
    try testing.expectEqual(
        @as(?decoder_stream.Instruction, .{ .section_acknowledgment = 0 }),
        decoder.takeSectionAcknowledgment(0, &section),
    );
    try testing.expectEqual(
        @as(?decoder_stream.Instruction, null),
        decoder.takeSectionAcknowledgment(0, &section),
    );
}

test "a post-base index at or past the Required Insert Count is a fault" {
    const gpa = testing.allocator;
    var decoder = exampleDecoder();
    defer decoder.deinit(gpa);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    try buildInserts(gpa, 3, &stream);
    _ = try decoder.readEncoderStream(gpa, stream.items);

    var scratch: [64]u8 = undefined;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, prefix.encode(
        .{ .required_insert_count = 3, .base = 2 },
        example_max_entries,
        &scratch,
    ));
    // Post-base index 1 is absolute index 3, which the Required Insert
    // Count of 3 says the section does not need. RFC 9204 section 2.2.3.
    try block.append(gpa, 0x11);

    try testing.expectError(error.InvalidPostBaseIndex, decoder.decodeSection(gpa, block.items));
}

test "a Required Insert Count past the fold unfolds, and an evicted entry is a fault" {
    const gpa = testing.allocator;
    var decoder = exampleDecoder();
    defer decoder.deinit(gpa);

    // Twenty inserts of 36 bytes each into a table of 220. Six live at a
    // time, so fourteen are evicted, and the insert count runs past the
    // fold of 2 * MaxEntries = 12.
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    try buildInserts(gpa, 20, &stream);
    _ = try decoder.readEncoderStream(gpa, stream.items);

    try testing.expectEqual(@as(u64, 20), decoder.table.inserted);
    try testing.expectEqual(@as(u64, 14), decoder.table.dropped);
    try testing.expectEqual(@as(u64, 6), decoder.table.count());
    try testing.expectEqual(@as(u64, 6), decoder.table.maxEntries());

    // The fold: 20 goes on the wire as (20 % 12) + 1 = 9, and only this
    // side's own insert count turns 9 back into 20.
    try testing.expectEqual(@as(u64, 9), prefix.encodeInsertCount(20, example_max_entries));

    var scratch: [64]u8 = undefined;
    var head: [8]u8 = undefined;
    const written = prefix.encode(
        .{ .required_insert_count = 20, .base = 20 },
        example_max_entries,
        &head,
    );
    try testing.expectEqualSlices(u8, &.{ 0x09, 0x00 }, written);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, written);
    // Relative index 0 is absolute index 19, the newest entry, and
    // relative index 5 is absolute index 14, the oldest one still there.
    try block.append(gpa, 0x80);
    try block.append(gpa, 0x85);
    // A literal field line whose name comes from absolute index 14 too.
    try block.append(gpa, 0x45);
    try block.appendSlice(gpa, string.encode(8, 0, "late", .raw, &scratch));

    var section = try decoder.decodeSection(gpa, block.items);
    defer section.deinit(gpa);

    try testing.expectEqual(@as(u64, 20), section.required_insert_count);
    try testing.expectEqual(@as(u64, 20), section.base);
    try expectField(section.list, 0, "nt", "vt");
    try expectField(section.list, 1, "no", "vo");
    try expectField(section.list, 2, "no", "late");

    // Relative index 6 is absolute index 13, which eviction took.
    var gone: std.ArrayList(u8) = .empty;
    defer gone.deinit(gpa);
    try gone.appendSlice(gpa, written);
    try gone.append(gpa, 0x86);
    try testing.expectError(error.InvalidDynamicIndex, decoder.decodeSection(gpa, gone.items));
}

// This build's `zig build` has no fuzz step, so the two functions that read
// peer octets get a fixed pseudo-random spread instead. The seed is fixed,
// so a failure is reproducible. What they prove is what a fuzz target
// proves: no input reaches a panic, an out of bounds read, or a leak, and
// every refusal is a named error.

test "no octets make decodeSection do anything but a field list or a named fault" {
    const gpa = testing.allocator;
    var decoder = exampleDecoder();
    defer decoder.deinit(gpa);

    // Give the table entries, so a dynamic reference has somewhere to land.
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    try buildInserts(gpa, 4, &stream);
    _ = try decoder.readEncoderStream(gpa, stream.items);

    var prng: std.Random.DefaultPrng = .init(0x9204);
    const random = prng.random();

    var buffer: [64]u8 = undefined;
    var lists: usize = 0;
    var faults: usize = 0;
    var round: usize = 0;
    while (round < 20000) : (round += 1) {
        const len = random.uintLessThan(usize, buffer.len + 1);
        random.bytes(buffer[0..len]);

        var section = decoder.decodeSection(gpa, buffer[0..len]) catch {
            faults += 1;
            continue;
        };
        section.deinit(gpa);
        lists += 1;
    }

    // A decode never changes the table, so the spread cannot have moved it.
    try testing.expectEqual(@as(u64, 4), decoder.table.inserted);
    try testing.expectEqual(@as(usize, 20000), lists + faults);
    // Both answers really happen, so neither branch is untested.
    try testing.expect(lists > 0);
    try testing.expect(faults > 0);
}

test "no octets make the encoder stream do anything but apply or name a fault" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x4392);
    const random = prng.random();

    const limits: encoder_stream.Limits = .forCapacity(example_capacity);
    var scratch: [integer.encoded_len_max]u8 = undefined;
    const set_capacity = encoder_stream.writeSetCapacity(example_capacity, &scratch);

    var buffer: [48]u8 = undefined;
    var applied: usize = 0;
    var faults: usize = 0;
    var round: usize = 0;
    while (round < 4000) : (round += 1) {
        const len = random.uintLessThan(usize, buffer.len + 1);
        random.bytes(buffer[0..len]);

        var table: DynamicTable = .init(.{ .capacity_max = example_capacity });
        defer table.deinit(gpa);
        _ = try encoder_stream.apply(gpa, &table, set_capacity, limits);

        const used = encoder_stream.apply(gpa, &table, buffer[0..len], limits) catch {
            faults += 1;
            continue;
        };
        // What it did not take is a part instruction the caller holds.
        try testing.expect(used <= len);
        applied += 1;
    }

    try testing.expectEqual(@as(usize, 4000), applied + faults);
    try testing.expect(applied > 0);
    try testing.expect(faults > 0);
}
