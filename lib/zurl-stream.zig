//! std.Io.Reader decorators that carry the zurl transfer features.
//!
//! A decorator wraps a source reader and adds one behaviour: progress
//! reporting, hashing, a rate limit, or a stall watchdog. They compose, so a
//! protocol engine contains no timeout code.

const std = @import("std");

pub const Progress = @import("zurl-stream/Progress.zig");
pub const Reporter = Progress.Reporter;
pub const hashing = @import("zurl-stream/hashing.zig");
pub const Hashing = hashing.Hashing;
pub const Throttle = @import("zurl-stream/Throttle.zig");
pub const Stall = @import("zurl-stream/Stall.zig");
pub const Speedometer = @import("zurl-stream/Speedometer.zig");

test {
    _ = Progress;
    _ = hashing;
    _ = Throttle;
    _ = Stall;
    _ = Speedometer;
    _ = @import("zurl-stream/compose_test.zig");
}
