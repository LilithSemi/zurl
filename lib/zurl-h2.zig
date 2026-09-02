//! The frame layer of HTTP/2. RFC 9113.
//!
//! This package turns octets into frames and frames back into octets. It
//! owns the 9-octet header, the payload of every type of section 6, the
//! padding rule, the `CONTINUATION` order rule, the connection preface,
//! the `SETTINGS` parameters with their defaults and ranges, and the
//! error codes with the difference between a stream error and a
//! connection error.
//!
//! **This package is not an HTTP/2 engine.** There is no stream state
//! machine here, no request, no response, and no connection. It never
//! opens a socket. `FrameReader` reads from a `std.Io.Reader` a caller
//! hands it, and every writer here writes into a buffer or a
//! `std.Io.Writer` a caller hands it. Nothing decides to reply, to close,
//! or to retry.
//!
//! **`zurl-http/h2.zig` is what imports this.** That file is the
//! connection engine: it holds the stream state, the flow-control
//! windows, and the HPACK tables, and it turns the frames here into
//! transfers. zurl offers `h2` in its ALPN now, so an `https` hop whose
//! peer chose `h2` runs over this package.
//!
//! It imports `zurl-core` for nothing and `zurl-hpack` for nothing: a
//! frame carries a header block fragment as octets, and only the engine
//! above knows when a block is whole and ready to decompress. The engine
//! is also what maps `zurl_h2.Error` onto `zurl_core.Error`, the way
//! `zurl-http/errors.zig` already does for HTTP/1.1.
//!
//! Reading a connection needs one `FrameReader`, which owns one payload
//! buffer:
//!
//!     var fr: zurl_h2.FrameReader = try .init(gpa, .{});
//!     defer fr.deinit(gpa);
//!
//!     const got = try fr.next(reader);
//!     switch (got.payload) {
//!         .data => |d| ...,
//!         .unknown => {}, // RFC 9113 section 4.1 says to ignore it
//!         else => ...,
//!     }
//!
//! Writing needs no object, because a frame holds nothing:
//!
//!     var out: [zurl_h2.frame.header_len + 8]u8 = undefined;
//!     const bytes = (zurl_h2.Ping{ .opaque_data = nonce }).encode(&out);
//!
//! **Every octet comes from the peer.** Every bound this build puts on a
//! frame is a named constant with a test that reaches it, and every fault
//! is a named error with an `ErrorCode` and a `Scope`. `errors.classify`
//! owns that mapping. The payload buffer of a `FrameReader` is the only
//! allocation in this package, it is sized to the frame size this
//! endpoint advertised, and a larger frame is refused on its header
//! alone.

const std = @import("std");

/// The RFC this package implements.
pub const rfc = "RFC 9113";

pub const errors = @import("zurl-h2/errors.zig");
pub const Error = errors.Error;
pub const ErrorCode = errors.ErrorCode;
pub const Scope = errors.Scope;
pub const Fault = errors.Fault;
pub const classify = errors.classify;

pub const frame = @import("zurl-h2/frame.zig");
pub const Type = frame.Type;
pub const Header = frame.Header;
pub const flag = frame.flag;

pub const settings = @import("zurl-h2/settings.zig");
pub const Settings = settings.Settings;

pub const payload = @import("zurl-h2/payload.zig");
pub const Frame = payload.Frame;
pub const Payload = payload.Payload;
pub const Data = payload.Data;
pub const Headers = payload.Headers;
pub const Priority = payload.Priority;
pub const RstStream = payload.RstStream;
pub const SettingsFrame = payload.Settings;
pub const PushPromise = payload.PushPromise;
pub const Ping = payload.Ping;
pub const Goaway = payload.Goaway;
pub const WindowUpdate = payload.WindowUpdate;
pub const Continuation = payload.Continuation;

pub const continuation = @import("zurl-h2/continuation.zig");
pub const Sequencer = continuation.Sequencer;

pub const window = @import("zurl-h2/window.zig");
pub const Window = window.Window;

pub const preface = @import("zurl-h2/preface.zig");
pub const FrameReader = @import("zurl-h2/FrameReader.zig");

test "the package names the RFC it implements" {
    try std.testing.expectEqualStrings("RFC 9113", rfc);
}

test "the front package reaches a write and a read in a few lines each" {
    const gpa = std.testing.allocator;

    var out: [frame.header_len + Ping.payload_len]u8 = undefined;
    const bytes = (Ping{ .opaque_data = .{ 8, 7, 6, 5, 4, 3, 2, 1 } }).encode(&out);

    var fr: FrameReader = try .init(gpa, .{});
    defer fr.deinit(gpa);

    var r: std.Io.Reader = .fixed(bytes);
    const got = try fr.next(&r);
    try std.testing.expectEqual(Type.ping, got.header.type);
    try std.testing.expectEqual([_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 }, got.payload.ping.opaque_data);
}

test "the front package reaches the error taxonomy in one line" {
    try std.testing.expectEqual(
        Fault{ .code = .frame_size_error, .scope = .connection },
        classify(error.FrameTooLarge, 0),
    );
}

test {
    _ = errors;
    _ = frame;
    _ = settings;
    _ = payload;
    _ = continuation;
    _ = window;
    _ = preface;
    _ = FrameReader;
    _ = @import("zurl-h2/rfc9113_test.zig");
}
