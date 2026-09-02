//! The flow-control window bound of RFC 9113 sections 6.9 and 6.9.1.
//!
//! This file owns one number and the two rules that move it: a
//! `WINDOW_UPDATE` adds to it, and a payload takes from it. It owns no
//! stream table, no scheduler, and no decision about when to send. Those
//! belong to the engine.
//!
//! The window is signed. RFC 9113 section 6.9.2 lets a new
//! `SETTINGS_INITIAL_WINDOW_SIZE` shrink every open window at once, and
//! the result can go below 0 when a peer already sent more than the new
//! size allows. The RFC says that is legal and is not an error, so the
//! type holds it rather than refusing it.

const std = @import("std");
const errors = @import("errors.zig");

const Error = errors.Error;

/// The largest a window may reach. RFC 9113 section 6.9.1.
pub const size_max: i32 = (1 << 31) - 1;

/// The window that every stream and the connection start with, before a
/// `SETTINGS` frame says otherwise. RFC 9113 section 6.9.2.
pub const size_initial: i32 = 65535;

/// One flow-control window.
pub const Window = struct {
    available: i32 = size_initial,

    pub fn init(size: i32) Window {
        return .{ .available = size };
    }

    /// Adds a `WINDOW_UPDATE` increment.
    ///
    /// An increment of 0 and an increment that takes the window above
    /// 2^31-1 are both faults, per RFC 9113 sections 6.9 and 6.9.1. The
    /// window is unchanged after either one.
    pub fn increase(self: *Window, increment: u31) Error!void {
        if (increment == 0) return error.WindowUpdateZero;
        // The sum is computed at 64 bits, so the check runs before any
        // wrap can happen. `available` can be negative here, which is
        // why a plain comparison against the remaining room is wrong.
        const sum = @as(i64, self.available) + @as(i64, increment);
        if (sum > size_max) return error.WindowOverflow;
        self.available = @intCast(sum);
    }

    /// Takes the octets of one payload out of the window.
    ///
    /// **A check and not an assert, and `u64` and not `u31`.**
    ///
    /// Sending more than the window allows is this build's own fault, not
    /// a peer's, and the old code said so with `std.debug.assert`. But an
    /// assert is compiled out of `ReleaseFast` and `ReleaseSmall`, which
    /// is what ships, so the guard was there in the tests and gone in the
    /// binary, and `available -= octets` would have run past zero.
    ///
    /// The parameter is `u64` because the caller's count is a `usize` and
    /// narrowing it first only moves the question. An `@intCast` to `u31`
    /// at the call site was sound while the precondition held, and the
    /// precondition was the assert that the shipped build removed. Taking
    /// the wide type and checking it here leaves one rule in one place.
    ///
    /// `available` can be negative, RFC 9113 section 6.9.2, so the
    /// comparison is made in `i64` where both sides fit.
    pub fn consume(self: *Window, octets: u64) Error!void {
        if (self.available < 0) return error.FlowControlExceeded;
        if (octets > @as(u64, @intCast(self.available))) return error.FlowControlExceeded;
        self.available -= @intCast(octets);
    }

    /// Moves the window by a change of `SETTINGS_INITIAL_WINDOW_SIZE`.
    /// RFC 9113 section 6.9.2.
    ///
    /// A decrease can take the window below 0, and the RFC says that is
    /// not an error. An increase that takes it above 2^31-1 is a fault.
    pub fn applyInitialSizeChange(self: *Window, delta: i32) Error!void {
        const sum = @as(i64, self.available) + @as(i64, delta);
        if (sum > size_max) return error.WindowOverflow;
        // A window cannot fall below -(2^31-1), because the old size and
        // the new size are each at or below 2^31-1.
        self.available = @intCast(sum);
    }
};

const testing = std.testing;

test "a window starts at the 65535 of RFC 9113 section 6.9.2" {
    const w: Window = .{};
    try testing.expectEqual(@as(i32, 65535), w.available);
    try testing.expectEqual(@as(i32, 65535), size_initial);
    try testing.expectEqual(@as(i32, 2147483647), size_max);
}

test "an increment adds, and the window reaches 2^31-1 exactly" {
    var w: Window = .init(0);
    try w.increase(1);
    try testing.expectEqual(@as(i32, 1), w.available);
    try w.increase(size_max - 1);
    try testing.expectEqual(size_max, w.available);
}

test "a WINDOW_UPDATE of zero is a fault and moves nothing" {
    var w: Window = .{};
    try testing.expectError(error.WindowUpdateZero, w.increase(0));
    try testing.expectEqual(@as(i32, 65535), w.available);
}

test "an increment one past 2^31-1 is a fault and moves nothing" {
    var w: Window = .init(size_max - 1);
    try testing.expectError(error.WindowOverflow, w.increase(2));
    try testing.expectEqual(size_max - 1, w.available);

    var full: Window = .init(size_max);
    try testing.expectError(error.WindowOverflow, full.increase(1));
    try testing.expectEqual(size_max, full.available);
}

test "the largest possible increment on the largest possible window is a fault" {
    var w: Window = .init(size_max);
    try testing.expectError(error.WindowOverflow, w.increase(std.math.maxInt(u31)));
}

test "a window that is already negative takes an increment without a fault" {
    var w: Window = .init(-1000);
    try w.increase(2000);
    try testing.expectEqual(@as(i32, 1000), w.available);
}

test "consume takes octets out" {
    var w: Window = .init(100);
    try w.consume(40);
    try testing.expectEqual(@as(i32, 60), w.available);
    try w.consume(60);
    try testing.expectEqual(@as(i32, 0), w.available);
}

test "a send past the window is refused and moves nothing" {
    // **The guard this test exists for was an assert**, so it was there in
    // a `Debug` build and gone in the one that ships. See `consume`.
    var w: Window = .init(10);
    try testing.expectError(error.FlowControlExceeded, w.consume(11));
    try testing.expectEqual(@as(i32, 10), w.available);

    // The boundary itself is allowed, and empties the window.
    try w.consume(10);
    try testing.expectEqual(@as(i32, 0), w.available);

    // An empty window takes nothing more, and one octet is enough to say so.
    try testing.expectError(error.FlowControlExceeded, w.consume(1));
    try testing.expectEqual(@as(i32, 0), w.available);
}

test "a window below zero refuses every send" {
    // RFC 9113 section 6.9.2 lets a `SETTINGS_INITIAL_WINDOW_SIZE` change
    // take a window below zero. Nothing may go out until an increment
    // brings it back, and a subtraction from a negative window would have
    // run further from zero rather than refusing.
    var w: Window = .init(-1);
    try testing.expectError(error.FlowControlExceeded, w.consume(0));
    try testing.expectError(error.FlowControlExceeded, w.consume(1));
    try testing.expectEqual(@as(i32, -1), w.available);
}

test "a count far above the window is refused rather than narrowed" {
    // The old call site narrowed the caller's `usize` with `@intCast` to
    // `u31` before `consume` saw it, and that cast was sound only while
    // the assert held. `consume` takes the wide type now, so a count this
    // large is a refusal and never a wrapped small number.
    var w: Window = .init(1000);
    try testing.expectError(error.FlowControlExceeded, w.consume(std.math.maxInt(u64)));
    try testing.expectEqual(@as(i32, 1000), w.available);
}

test "a smaller INITIAL_WINDOW_SIZE can take a window below zero" {
    // RFC 9113 section 6.9.2 says this is legal and is not an error.
    var w: Window = .init(100);
    try w.applyInitialSizeChange(-1000);
    try testing.expectEqual(@as(i32, -900), w.available);
}

test "a larger INITIAL_WINDOW_SIZE that runs the window over is a fault" {
    var w: Window = .init(size_max);
    try testing.expectError(error.WindowOverflow, w.applyInitialSizeChange(1));
    try testing.expectEqual(size_max, w.available);
}
