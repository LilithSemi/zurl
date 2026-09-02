//! Parsing and policy for zurl. This package does no I/O.
//!
//! Every function here takes bytes and returns values. No function opens a
//! file or a socket. This makes each rule testable with a table.

const std = @import("std");

/// The version of the zurl library.
pub const version: std.SemanticVersion = .{ .major = 0, .minor = 1, .patch = 0 };

pub const errors = @import("zurl-core/errors.zig");
pub const Error = errors.Error;
pub const Diagnostics = @import("zurl-core/Diagnostics.zig");
pub const redact = @import("zurl-core/redact.zig");
pub const url = @import("zurl-core/url.zig");
pub const Url = url.Url;
pub const redirect = @import("zurl-core/redirect.zig");
pub const tls = @import("zurl-core/tls.zig");
pub const netrc = @import("zurl-core/netrc.zig");
pub const auth = @import("zurl-core/auth.zig");
pub const config = @import("zurl-core/config.zig");
pub const ca = @import("zurl-core/ca.zig");
pub const cookie = @import("zurl-core/cookie.zig");

/// The public suffix list, and the domains no single site owns.
/// `cookie.resolveDomain` is the one caller.
pub const psl = @import("zurl-core/psl.zig");

/// What a proxy url says, and which hosts reach no proxy at all. `-x`,
/// `--noproxy`, and the proxy environment variables.
pub const proxy = @import("zurl-core/proxy.zig");

test "the library reports its version" {
    try std.testing.expectEqual(@as(u32, 0), version.major);
    try std.testing.expectEqual(@as(u32, 1), version.minor);
}

test {
    _ = errors;
    _ = Diagnostics;
    _ = redact;
    _ = url;
    _ = redirect;
    _ = tls;
    _ = netrc;
    _ = auth;
    _ = config;
    _ = ca;
    _ = cookie;
    _ = psl;
    _ = proxy;
}
