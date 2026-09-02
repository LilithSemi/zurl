//! The `SETTINGS` parameters, their defaults, and their legal ranges.
//! RFC 9113 sections 6.5, 6.5.1, and 6.5.2.
//!
//! This file owns the six parameters a client cares about, the value each
//! one has before a peer says otherwise, and the range each one must stay
//! inside. It reads and writes a `SETTINGS` payload, and it applies one
//! onto a `Settings` value.
//!
//! This file owns no policy. It never decides to send a `SETTINGS` frame,
//! it never waits for an `ACK`, and it never applies a new
//! `INITIAL_WINDOW_SIZE` to a stream. Those need a connection, and this
//! package has none.
//!
//! **A `SETTINGS` payload is untrusted.** A length that is not a whole
//! number of entries, an `ACK` with a payload, and a value outside its
//! range are each a named error. An identifier this build does not know
//! is not an error: RFC 9113 section 6.5.2 says a receiver must ignore
//! it, so `apply` counts it and moves on.

const std = @import("std");
const errors = @import("errors.zig");

const Error = errors.Error;

/// The octets of one identifier and value pair. RFC 9113 section 6.5.1.
pub const entry_len: usize = 6;

/// The identifiers of RFC 9113 section 6.5.2.
///
/// The enum is non-exhaustive because the registry can grow and an
/// unknown identifier must be ignored rather than refused.
pub const Id = enum(u16) {
    header_table_size = 0x01,
    enable_push = 0x02,
    max_concurrent_streams = 0x03,
    initial_window_size = 0x04,
    max_frame_size = 0x05,
    max_header_list_size = 0x06,
    _,

    /// The name from RFC 9113 section 6.5.2, or null when this build does
    /// not know the identifier.
    pub fn name(id: Id) ?[]const u8 {
        return switch (id) {
            .header_table_size => "SETTINGS_HEADER_TABLE_SIZE",
            .enable_push => "SETTINGS_ENABLE_PUSH",
            .max_concurrent_streams => "SETTINGS_MAX_CONCURRENT_STREAMS",
            .initial_window_size => "SETTINGS_INITIAL_WINDOW_SIZE",
            .max_frame_size => "SETTINGS_MAX_FRAME_SIZE",
            .max_header_list_size => "SETTINGS_MAX_HEADER_LIST_SIZE",
            _ => null,
        };
    }

    /// True when this build knows the identifier and will apply it.
    pub fn isKnown(id: Id) bool {
        return name(id) != null;
    }
};

/// The largest `SETTINGS_INITIAL_WINDOW_SIZE`. RFC 9113 section 6.5.2.
pub const initial_window_size_max: u32 = (1 << 31) - 1;

/// The smallest `SETTINGS_MAX_FRAME_SIZE`. RFC 9113 section 6.5.2. Every
/// endpoint must accept a frame this big, so no peer may ask for less.
pub const max_frame_size_min: u32 = 16384;

/// The largest `SETTINGS_MAX_FRAME_SIZE`. RFC 9113 section 6.5.2. This is
/// the width of the length field, so nothing bigger fits a frame header.
pub const max_frame_size_max: u32 = (1 << 24) - 1;

/// One identifier and value pair, as it goes on the wire.
pub const Entry = struct {
    id: Id,
    value: u32,

    pub fn encode(self: Entry, out: *[entry_len]u8) void {
        std.mem.writeInt(u16, out[0..2], @intFromEnum(self.id), .big);
        std.mem.writeInt(u32, out[2..6], self.value, .big);
    }

    pub fn parse(bytes: *const [entry_len]u8) Entry {
        return .{
            .id = @enumFromInt(std.mem.readInt(u16, bytes[0..2], .big)),
            .value = std.mem.readInt(u32, bytes[2..6], .big),
        };
    }
};

/// The six parameters, each at its RFC 9113 section 6.5.2 default.
///
/// `null` on the two optional fields means the RFC's "unlimited". A
/// caller that needs a number for one of them must pick its own, because
/// the protocol gives none.
pub const Settings = struct {
    /// RFC 9113 section 6.5.2. The HPACK dynamic table size, in octets.
    header_table_size: u32 = 4096,
    /// RFC 9113 section 6.5.2. A client that sends 0 refuses server push.
    enable_push: bool = true,
    /// RFC 9113 section 6.5.2. `null` is the RFC's "initially there is no
    /// limit".
    max_concurrent_streams: ?u32 = null,
    /// RFC 9113 section 6.5.2. The starting flow-control window of every
    /// new stream, in octets.
    initial_window_size: u31 = 65535,
    /// RFC 9113 section 6.5.2. The largest payload this endpoint accepts.
    max_frame_size: u24 = 16384,
    /// RFC 9113 section 6.5.2. `null` is the RFC's "unlimited".
    max_header_list_size: ?u32 = null,

    /// The value of every parameter before either peer sends a
    /// `SETTINGS` frame.
    pub const initial: Settings = .{};

    /// How many entries `apply` took and how many it ignored.
    ///
    /// The ignored count is what makes the ignore path observable. A
    /// peer that sends nothing this build knows is a fact worth having,
    /// and a silent skip would hide it.
    pub const Applied = struct {
        taken: usize = 0,
        ignored: usize = 0,
    };

    /// Applies one entry.
    ///
    /// An identifier this build does not know is ignored, per RFC 9113
    /// section 6.5.2. A value outside the range of a known identifier is
    /// a fault, and the `Settings` is left as it was.
    pub fn applyEntry(self: *Settings, entry: Entry) Error!bool {
        switch (entry.id) {
            .header_table_size => self.header_table_size = entry.value,
            .enable_push => switch (entry.value) {
                0 => self.enable_push = false,
                1 => self.enable_push = true,
                else => return error.SettingsEnablePushInvalid,
            },
            .max_concurrent_streams => self.max_concurrent_streams = entry.value,
            .initial_window_size => {
                if (entry.value > initial_window_size_max) {
                    return error.SettingsInitialWindowSizeInvalid;
                }
                self.initial_window_size = @intCast(entry.value);
            },
            .max_frame_size => {
                if (entry.value < max_frame_size_min or entry.value > max_frame_size_max) {
                    return error.SettingsMaxFrameSizeInvalid;
                }
                self.max_frame_size = @intCast(entry.value);
            },
            .max_header_list_size => self.max_header_list_size = entry.value,
            _ => return false,
        }
        return true;
    }

    /// Applies a whole `SETTINGS` payload.
    ///
    /// `payload` must already have had its length checked by
    /// `checkPayloadLen`, which `Frame.parse` does. This asserts that,
    /// because reaching it with a ragged payload would be this build's
    /// own bug.
    ///
    /// On a fault the `Settings` holds the entries before the bad one.
    /// RFC 9113 section 6.5 makes every range fault a connection error,
    /// so no caller keeps using the value after one.
    pub fn apply(self: *Settings, payload: []const u8) Error!Applied {
        std.debug.assert(payload.len % entry_len == 0);

        var result: Applied = .{};
        var offset: usize = 0;
        while (offset + entry_len <= payload.len) : (offset += entry_len) {
            const entry = Entry.parse(payload[offset..][0..entry_len]);
            if (try self.applyEntry(entry)) result.taken += 1 else result.ignored += 1;
        }
        return result;
    }

    /// The entries that differ from `base`, in identifier order.
    ///
    /// This is what a client sends: a `SETTINGS` frame carries only the
    /// parameters it wants changed, and the peer keeps its defaults for
    /// the rest.
    pub fn changesFrom(self: Settings, base: Settings) EntryList {
        var list: EntryList = .{};
        if (self.header_table_size != base.header_table_size) {
            list.append(.{ .id = .header_table_size, .value = self.header_table_size });
        }
        if (self.enable_push != base.enable_push) {
            list.append(.{ .id = .enable_push, .value = @intFromBool(self.enable_push) });
        }
        if (self.max_concurrent_streams) |value| {
            if (base.max_concurrent_streams != value) {
                list.append(.{ .id = .max_concurrent_streams, .value = value });
            }
        }
        if (self.initial_window_size != base.initial_window_size) {
            list.append(.{ .id = .initial_window_size, .value = self.initial_window_size });
        }
        if (self.max_frame_size != base.max_frame_size) {
            list.append(.{ .id = .max_frame_size, .value = self.max_frame_size });
        }
        if (self.max_header_list_size) |value| {
            if (base.max_header_list_size != value) {
                list.append(.{ .id = .max_header_list_size, .value = value });
            }
        }
        return list;
    }
};

/// How many entries a `SETTINGS` frame from this build can carry.
///
/// `Settings` has six fields, so six is every one of them at once. The
/// list needs no allocator for that reason.
pub const entry_count_max: usize = 6;

/// The largest `SETTINGS` payload this build writes.
pub const payload_len_max: usize = entry_count_max * entry_len;

/// A fixed list of entries. It holds every parameter this build knows and
/// no more, so it never allocates and never grows.
pub const EntryList = struct {
    buf: [entry_count_max]Entry = undefined,
    len: usize = 0,

    /// Adds one entry. The caller must not add more than
    /// `entry_count_max`, and only this file's own code adds at all, so
    /// an overrun is a bug here and not a peer's doing.
    pub fn append(self: *EntryList, entry: Entry) void {
        std.debug.assert(self.len < entry_count_max);
        self.buf[self.len] = entry;
        self.len += 1;
    }

    pub fn slice(self: *const EntryList) []const Entry {
        return self.buf[0..self.len];
    }

    /// Writes the entries into `out` and returns the octets used. `out`
    /// must hold `payload_len_max`.
    pub fn encode(self: *const EntryList, out: []u8) []u8 {
        std.debug.assert(out.len >= payload_len_max);
        var offset: usize = 0;
        for (self.slice()) |entry| {
            entry.encode(out[offset..][0..entry_len]);
            offset += entry_len;
        }
        return out[0..offset];
    }
};

/// Checks one entry's value against its range, and changes nothing.
///
/// `Frame.parse` runs this over every entry, so a range fault is found
/// where the frame is read and not later where it is applied. The check
/// is `applyEntry` on a value that is thrown away, so the two can never
/// drift apart.
pub fn checkEntry(entry: Entry) Error!void {
    var scratch: Settings = .initial;
    _ = try scratch.applyEntry(entry);
}

/// Checks every entry of a `SETTINGS` payload. `payload` must already
/// have passed `checkPayloadLen`.
pub fn checkPayload(payload: []const u8) Error!void {
    std.debug.assert(payload.len % entry_len == 0);
    var offset: usize = 0;
    while (offset + entry_len <= payload.len) : (offset += entry_len) {
        try checkEntry(Entry.parse(payload[offset..][0..entry_len]));
    }
}

/// Checks the length of a `SETTINGS` payload against RFC 9113 section
/// 6.5.
///
/// `ack` is the `ACK` flag off the frame header. An `ACK` carries no
/// payload, and any other `SETTINGS` carries a whole number of entries.
pub fn checkPayloadLen(len: usize, ack: bool) Error!void {
    if (ack) {
        if (len != 0) return error.SettingsAckNotEmpty;
        return;
    }
    if (len % entry_len != 0) return error.SettingsLengthInvalid;
}

const testing = std.testing;

test "the defaults are the values of RFC 9113 section 6.5.2" {
    const s: Settings = .initial;
    try testing.expectEqual(@as(u32, 4096), s.header_table_size);
    try testing.expectEqual(true, s.enable_push);
    try testing.expectEqual(@as(?u32, null), s.max_concurrent_streams);
    try testing.expectEqual(@as(u31, 65535), s.initial_window_size);
    try testing.expectEqual(@as(u24, 16384), s.max_frame_size);
    try testing.expectEqual(@as(?u32, null), s.max_header_list_size);
}

test "the identifiers carry the numbers of RFC 9113 section 6.5.2" {
    try testing.expectEqual(@as(u16, 0x01), @intFromEnum(Id.header_table_size));
    try testing.expectEqual(@as(u16, 0x02), @intFromEnum(Id.enable_push));
    try testing.expectEqual(@as(u16, 0x03), @intFromEnum(Id.max_concurrent_streams));
    try testing.expectEqual(@as(u16, 0x04), @intFromEnum(Id.initial_window_size));
    try testing.expectEqual(@as(u16, 0x05), @intFromEnum(Id.max_frame_size));
    try testing.expectEqual(@as(u16, 0x06), @intFromEnum(Id.max_header_list_size));
    try testing.expect(!(@as(Id, @enumFromInt(0x07))).isKnown());
    try testing.expect(!(@as(Id, @enumFromInt(0x00))).isKnown());
}

test "one entry round-trips through its six octets" {
    const entry: Entry = .{ .id = .max_frame_size, .value = 16384 };
    var out: [entry_len]u8 = undefined;
    entry.encode(&out);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x05, 0x00, 0x00, 0x40, 0x00 }, &out);
    try testing.expectEqual(entry, Entry.parse(&out));
}

test "a payload of every known parameter applies and changes each field" {
    var list: EntryList = .{};
    list.append(.{ .id = .header_table_size, .value = 8192 });
    list.append(.{ .id = .enable_push, .value = 0 });
    list.append(.{ .id = .max_concurrent_streams, .value = 100 });
    list.append(.{ .id = .initial_window_size, .value = 1 << 20 });
    list.append(.{ .id = .max_frame_size, .value = 32768 });
    list.append(.{ .id = .max_header_list_size, .value = 65536 });

    var buf: [payload_len_max]u8 = undefined;
    const payload = list.encode(&buf);
    try testing.expectEqual(payload_len_max, payload.len);

    var s: Settings = .initial;
    const applied = try s.apply(payload);
    try testing.expectEqual(@as(usize, 6), applied.taken);
    try testing.expectEqual(@as(usize, 0), applied.ignored);

    try testing.expectEqual(@as(u32, 8192), s.header_table_size);
    try testing.expectEqual(false, s.enable_push);
    try testing.expectEqual(@as(?u32, 100), s.max_concurrent_streams);
    try testing.expectEqual(@as(u31, 1 << 20), s.initial_window_size);
    try testing.expectEqual(@as(u24, 32768), s.max_frame_size);
    try testing.expectEqual(@as(?u32, 65536), s.max_header_list_size);

    // The same values now differ from nothing, so nothing is sent.
    try testing.expectEqual(@as(usize, 0), s.changesFrom(s).len);
}

test "an unknown identifier is ignored and counted, not refused" {
    const payload = [_]u8{
        0x00, 0xff, 0x00, 0x00, 0x00, 0x07, // identifier 0x00ff, unknown
        0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE 16384
    };
    var s: Settings = .initial;
    const applied = try s.apply(&payload);
    try testing.expectEqual(@as(usize, 1), applied.taken);
    try testing.expectEqual(@as(usize, 1), applied.ignored);
    try testing.expectEqual(@as(u24, 16384), s.max_frame_size);
}

test "a SETTINGS length that is not a multiple of six is a fault" {
    try testing.expectError(error.SettingsLengthInvalid, checkPayloadLen(1, false));
    try testing.expectError(error.SettingsLengthInvalid, checkPayloadLen(5, false));
    try testing.expectError(error.SettingsLengthInvalid, checkPayloadLen(7, false));
    try testing.expectError(error.SettingsLengthInvalid, checkPayloadLen(11, false));
    try checkPayloadLen(0, false);
    try checkPayloadLen(6, false);
    try checkPayloadLen(12, false);
}

test "a SETTINGS ACK with a payload is a fault, and an empty one is not" {
    try testing.expectError(error.SettingsAckNotEmpty, checkPayloadLen(6, true));
    try testing.expectError(error.SettingsAckNotEmpty, checkPayloadLen(1, true));
    try checkPayloadLen(0, true);
}

test "ENABLE_PUSH takes 0 and 1 and refuses everything else" {
    var s: Settings = .initial;
    try testing.expect(try s.applyEntry(.{ .id = .enable_push, .value = 0 }));
    try testing.expectEqual(false, s.enable_push);
    try testing.expect(try s.applyEntry(.{ .id = .enable_push, .value = 1 }));
    try testing.expectEqual(true, s.enable_push);

    try testing.expectError(
        error.SettingsEnablePushInvalid,
        s.applyEntry(.{ .id = .enable_push, .value = 2 }),
    );
    try testing.expectError(
        error.SettingsEnablePushInvalid,
        s.applyEntry(.{ .id = .enable_push, .value = std.math.maxInt(u32) }),
    );
    // The refused value did not land.
    try testing.expectEqual(true, s.enable_push);
}

test "INITIAL_WINDOW_SIZE takes 2^31-1 and refuses 2^31" {
    var s: Settings = .initial;
    try testing.expect(try s.applyEntry(.{
        .id = .initial_window_size,
        .value = initial_window_size_max,
    }));
    try testing.expectEqual(@as(u31, initial_window_size_max), s.initial_window_size);

    try testing.expectError(
        error.SettingsInitialWindowSizeInvalid,
        s.applyEntry(.{ .id = .initial_window_size, .value = initial_window_size_max + 1 }),
    );
    try testing.expectError(
        error.SettingsInitialWindowSizeInvalid,
        s.applyEntry(.{ .id = .initial_window_size, .value = std.math.maxInt(u32) }),
    );
    try testing.expectEqual(@as(u31, initial_window_size_max), s.initial_window_size);
}

test "MAX_FRAME_SIZE takes 16384 to 16777215 and refuses either side" {
    var s: Settings = .initial;
    try testing.expect(try s.applyEntry(.{ .id = .max_frame_size, .value = max_frame_size_min }));
    try testing.expectEqual(@as(u24, 16384), s.max_frame_size);
    try testing.expect(try s.applyEntry(.{ .id = .max_frame_size, .value = max_frame_size_max }));
    try testing.expectEqual(@as(u24, 16777215), s.max_frame_size);

    try testing.expectError(
        error.SettingsMaxFrameSizeInvalid,
        s.applyEntry(.{ .id = .max_frame_size, .value = max_frame_size_min - 1 }),
    );
    try testing.expectError(
        error.SettingsMaxFrameSizeInvalid,
        s.applyEntry(.{ .id = .max_frame_size, .value = 0 }),
    );
    try testing.expectError(
        error.SettingsMaxFrameSizeInvalid,
        s.applyEntry(.{ .id = .max_frame_size, .value = max_frame_size_max + 1 }),
    );
    try testing.expectError(
        error.SettingsMaxFrameSizeInvalid,
        s.applyEntry(.{ .id = .max_frame_size, .value = std.math.maxInt(u32) }),
    );
    try testing.expectEqual(@as(u24, 16777215), s.max_frame_size);
}

test "HEADER_TABLE_SIZE and MAX_HEADER_LIST_SIZE take every 32-bit value" {
    // RFC 9113 section 6.5.2 gives neither one a range.
    var s: Settings = .initial;
    try testing.expect(try s.applyEntry(.{ .id = .header_table_size, .value = 0 }));
    try testing.expectEqual(@as(u32, 0), s.header_table_size);
    try testing.expect(try s.applyEntry(.{
        .id = .header_table_size,
        .value = std.math.maxInt(u32),
    }));
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), s.header_table_size);
    try testing.expect(try s.applyEntry(.{
        .id = .max_header_list_size,
        .value = std.math.maxInt(u32),
    }));
    try testing.expectEqual(@as(?u32, std.math.maxInt(u32)), s.max_header_list_size);
}

test "an entry after a bad one is never applied" {
    const payload = [_]u8{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x02, // ENABLE_PUSH 2, out of range
        0x00, 0x05, 0x00, 0x01, 0x00, 0x00, // MAX_FRAME_SIZE 65536
    };
    var s: Settings = .initial;
    try testing.expectError(error.SettingsEnablePushInvalid, s.apply(&payload));
    try testing.expectEqual(@as(u24, 16384), s.max_frame_size);
}

test "changesFrom sends only what differs from the peer's defaults" {
    var wanted: Settings = .initial;
    wanted.enable_push = false;
    wanted.initial_window_size = 1 << 20;
    wanted.max_header_list_size = 16384;

    const list = wanted.changesFrom(.initial);
    try testing.expectEqualSlices(Entry, &.{
        .{ .id = .enable_push, .value = 0 },
        .{ .id = .initial_window_size, .value = 1 << 20 },
        .{ .id = .max_header_list_size, .value = 16384 },
    }, list.slice());

    var buf: [payload_len_max]u8 = undefined;
    const payload = list.encode(&buf);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x06, 0x00, 0x00, 0x40, 0x00,
    }, payload);

    // What was written applies back to the same values.
    var s: Settings = .initial;
    _ = try s.apply(payload);
    try testing.expectEqual(wanted, s);
}

test "an empty payload applies nothing and is not a fault" {
    var s: Settings = .initial;
    const applied = try s.apply(&.{});
    try testing.expectEqual(@as(usize, 0), applied.taken);
    try testing.expectEqual(@as(usize, 0), applied.ignored);
    try testing.expectEqual(Settings.initial, s);
}
