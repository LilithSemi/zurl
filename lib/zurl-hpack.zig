//! HPACK, the header compression of HTTP/2. RFC 7541.
//!
//! This package turns a header list into a header block and back. It does
//! no I/O, it holds no socket, and it knows nothing about frames, streams,
//! or a connection. A caller hands it octets and gets values, the way it
//! hands `zurl-core` a url and gets a `Url`.
//!
//! **This package imports nothing else of ours.** Not `zurl-core`, not
//! `zurl-net`, not the front package. HPACK is a codec with a published
//! specification and published test vectors, and it needs no url rule, no
//! error taxonomy, and no trust root to be right. A build that wants HPACK
//! and nothing else takes this one file tree. The engine that sits over
//! it is what maps `Decoder.Error` onto `zurl_core.Error`, the way
//! `zurl-http/errors.zig` already does for HTTP/1.1.
//!
//! **This package is not HTTP/2.** There is no frame layer here, no stream
//! state machine, and no engine. `zurl-h2` is the frames and
//! `zurl-http/h2.zig` is the engine, and that engine is the one file that
//! imports both.
//!
//! A decoder belongs to a connection, and it carries the dynamic table
//! that every block on that connection built:
//!
//!     var decoder: zurl_hpack.Decoder = .init(.{ .table_capacity_max = 4096 });
//!     defer decoder.deinit(gpa);
//!
//!     var list = try decoder.decode(gpa, block);
//!     defer list.deinit(gpa);
//!     const status = list.get(":status");
//!
//! An encode holds nothing, so it needs no such object:
//!
//!     const block = try zurl_hpack.encoder.encodeAlloc(gpa, &fields, .{});
//!     defer gpa.free(block);
//!
//! **A header block is untrusted input.** Every bound this build puts on
//! one is a named constant with a test that reaches it, and every fault is
//! a named error. `Decoder` owns that list. Nothing in this package
//! allocates without a bound.

const std = @import("std");

/// The RFC this package implements.
pub const rfc = "RFC 7541";

pub const field = @import("zurl-hpack/field.zig");
pub const Field = field.Field;
pub const FieldList = field.List;

pub const integer = @import("zurl-hpack/integer.zig");
pub const huffman = @import("zurl-hpack/huffman.zig");
pub const string = @import("zurl-hpack/string.zig");
pub const Coding = string.Coding;

pub const static_table = @import("zurl-hpack/static_table.zig");
pub const DynamicTable = @import("zurl-hpack/DynamicTable.zig");

pub const Decoder = @import("zurl-hpack/Decoder.zig");
pub const encoder = @import("zurl-hpack/encoder.zig");

/// Every fault a decode can report. See `Decoder.Error` for what each one
/// means.
pub const Error = Decoder.Error;

test "the package names the RFC it implements" {
    try std.testing.expectEqualStrings("RFC 7541", rfc);
}

test "the front package reaches a decode and an encode in one line each" {
    const gpa = std.testing.allocator;

    const fields = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":authority", .value = "www.example.com" },
    };
    const block = try encoder.encodeAlloc(gpa, &fields, .{});
    defer gpa.free(block);

    var decoder: Decoder = .init(.{});
    defer decoder.deinit(gpa);

    var list = try decoder.decode(gpa, block);
    defer list.deinit(gpa);

    try std.testing.expectEqualStrings("GET", list.get(":method").?);
    try std.testing.expectEqualStrings("www.example.com", list.get(":authority").?);
}

test {
    _ = field;
    _ = integer;
    _ = huffman;
    _ = string;
    _ = static_table;
    _ = DynamicTable;
    _ = Decoder;
    _ = encoder;
    _ = @import("zurl-hpack/rfc7541_test.zig");
}
