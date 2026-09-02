//! QPACK, the field compression of HTTP/3. RFC 9204.
//!
//! This package turns a field list into an encoded field section and back.
//! It does no I/O, it holds no socket, and it knows nothing about QUIC
//! streams, HTTP/3 frames, or a connection. A caller hands it octets and
//! gets values, the way it hands `zurl-core` a url and gets a `Url`.
//!
//! **This package imports nothing else of ours.** Not `zurl-core`, not
//! `zurl-quic`, not the front package. QPACK is a codec with a published
//! specification and published test vectors, and it needs no url rule, no
//! error taxonomy, and no trust root to be right. A build that wants QPACK
//! and nothing else takes this one file tree. The engine that sits over it
//! is what maps `Decoder.Error` onto `zurl_core.Error`, the way
//! `zurl-http/errors.zig` already does for HTTP/1.1.
//!
//! **It does not import `zurl-hpack` either, though the two overlap.** RFC
//! 9204 borrows HPACK's prefixed integer and HPACK's Huffman table. The
//! integer needed a wider ceiling here, 62 bits against 32, because RFC
//! 9204 section 4.1.1 requires it. The string literal needed a new shape,
//! because RFC 9204 section 4.1.2 lets one start part way through an
//! octet. Only the Huffman table is the same, and a copy of it is proved
//! complete and canonical when this file tree compiles, so a wrong copy is
//! a build failure and never a wire fault.
//!
//! **This package is not HTTP/3.** There is no QUIC here, no frame layer,
//! no stream state machine, and no engine.
//!
//! A decoder belongs to a connection, and it carries the dynamic table
//! that the peer's encoder stream built:
//!
//!     var decoder: zurl_qpack.Decoder = .init(.{ .table_capacity_max = 4096 });
//!     defer decoder.deinit(gpa);
//!
//!     _ = try decoder.readEncoderStream(gpa, encoder_stream_bytes);
//!
//!     var section = try decoder.decodeSection(gpa, request_stream_bytes);
//!     defer section.deinit(gpa);
//!     const status = section.list.get(":status");
//!
//! An encode holds nothing, so it needs no such object:
//!
//!     const bytes = try zurl_qpack.encoder.encodeAlloc(gpa, &fields, .{});
//!     defer gpa.free(bytes);
//!
//! **This encoder never inserts into the dynamic table**, so it sends no
//! encoder instructions and needs no encoder stream. RFC 9204 section 4.2
//! allows that. `encoder_stream` holds the writers a later encoder would
//! need, and `Decoder` reads every instruction a peer can send.
//!
//! **This decoder never blocks.** It sends SETTINGS_QPACK_BLOCKED_STREAMS
//! of zero, and a field section that names a dynamic entry which has not
//! arrived is `error.Blocked` rather than a wait. See `Decoder` for what
//! that buys and what it costs.
//!
//! **An encoded field section is untrusted input.** Every bound this build
//! puts on one is a named constant with a test that reaches it, and every
//! fault is a named error. `Decoder` owns that list. Nothing in this
//! package allocates without a bound.

const std = @import("std");

/// The RFC this package implements.
pub const rfc = "RFC 9204";

pub const field = @import("zurl-qpack/field.zig");
pub const Field = field.Field;
pub const FieldList = field.List;

pub const integer = @import("zurl-qpack/integer.zig");
pub const huffman = @import("zurl-qpack/huffman.zig");
pub const string = @import("zurl-qpack/string.zig");
pub const Coding = string.Coding;

pub const static_table = @import("zurl-qpack/static_table.zig");
pub const DynamicTable = @import("zurl-qpack/DynamicTable.zig");
pub const prefix = @import("zurl-qpack/prefix.zig");

pub const encoder_stream = @import("zurl-qpack/encoder_stream.zig");
pub const decoder_stream = @import("zurl-qpack/decoder_stream.zig");
pub const DecoderInstruction = decoder_stream.Instruction;

pub const Decoder = @import("zurl-qpack/Decoder.zig");
pub const Section = Decoder.Section;
pub const encoder = @import("zurl-qpack/encoder.zig");

/// Every fault a decode can report. See `Decoder.Error` for what each one
/// means.
pub const Error = Decoder.Error;

/// How many streams this side lets a peer block on the dynamic table,
/// which is what it sends as SETTINGS_QPACK_BLOCKED_STREAMS. Zero.
pub const blocked_streams_max = Decoder.blocked_streams_max;

test "the package names the RFC it implements" {
    try std.testing.expectEqualStrings("RFC 9204", rfc);
}

test "the front package reaches a decode and an encode in one line each" {
    const gpa = std.testing.allocator;

    const fields = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":authority", .value = "www.example.com" },
    };
    const bytes = try encoder.encodeAlloc(gpa, &fields, .{});
    defer gpa.free(bytes);

    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    var section = try decoder.decodeSection(gpa, bytes);
    defer section.deinit(gpa);

    try std.testing.expectEqualStrings("GET", section.list.get(":method").?);
    try std.testing.expectEqualStrings("www.example.com", section.list.get(":authority").?);
}

test "this side blocks on nothing" {
    try std.testing.expectEqual(@as(u64, 0), blocked_streams_max);
}

test {
    _ = field;
    _ = integer;
    _ = huffman;
    _ = string;
    _ = static_table;
    _ = DynamicTable;
    _ = prefix;
    _ = encoder_stream;
    _ = decoder_stream;
    _ = Decoder;
    _ = encoder;
    _ = @import("zurl-qpack/rfc9204_test.zig");
}
