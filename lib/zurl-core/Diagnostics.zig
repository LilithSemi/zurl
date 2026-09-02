//! The detail that goes with a returned error.
//!
//! An error value says what class of fault happened. It cannot say which host,
//! which status, or which certificate. A caller that wants that detail passes
//! a pointer to one of these. Recovery is never silent, so every recovered
//! fault writes here or to a log.
//!
//! **A url cannot enter a `Diagnostics` unmasked.** There is no `url`
//! field to assign. `record` is the only writer, it copies the text into
//! `url_storage` through `redact.copy`, and `url` is the only reader. A
//! path that wants to name a url in a failure therefore masks the
//! password whether or not its author remembered to, and a path added
//! later cannot skip the step, because the compiler gives it nowhere else
//! to put the text.

const Diagnostics = @This();

const std = @import("std");
const Error = @import("errors.zig").Error;
const curlCode = @import("errors.zig").curlCode;
const redact = @import("redact.zig");

/// How large a url this `Diagnostics` can hold in `url_storage`. Generous
/// past any url a person would type. A longer one loses its tail, not its
/// masked password: `record` masks the password before it copies anything,
/// and the password sits near the front, right after the scheme.
pub const url_storage_len = 2048;

/// How large a message this `Diagnostics` can hold in `message_storage`.
/// Room for a sentence and a file path beside it. A longer message loses
/// its tail, because a diagnostic that says less is a cost, and a
/// diagnostic that is not written at all is a fault.
pub const message_storage_len = 512;

/// Owned storage behind `url`. Read it through `url`, never directly:
/// only the first `url_len` bytes hold anything, and only `record` writes
/// here.
url_storage: [url_storage_len]u8 = undefined,
/// How many bytes of `url_storage` hold the masked url, or null when no
/// writer has named a url. Read it through `url`.
url_len: ?usize = null,
/// The host that zurl spoke to.
host: ?[]const u8 = null,
/// The last status that the server sent.
status: ?u16 = null,
/// A message from the protocol engine or from TLS.
///
/// Most writers record a constant, which lives as long as the program
/// does. A writer that must build a sentence, such as one that names the
/// certificate path that did not load, writes into `message_storage`
/// first. A `Diagnostics` therefore owns such a message, and another
/// transfer, which fills another `Diagnostics`, cannot overwrite it.
message: ?[]const u8 = null,
/// Owned storage behind `message`, for a writer that builds a sentence
/// instead of naming a constant. Read it through `message`, never
/// directly: only the first `message.len` bytes hold anything, and a
/// borrowed `message` points somewhere else.
message_storage: [message_storage_len]u8 = undefined,
/// The libcurl code for the error. `record` fills this.
curl_code: ?u32 = null,

/// The url the transfer used, with any userinfo password masked, or null
/// when no writer named one.
///
/// The value points into this `Diagnostics`'s own storage, so it stays
/// good for as long as the `Diagnostics` does, it survives a copy of the
/// whole struct, and another transfer, which fills another
/// `Diagnostics`, cannot overwrite it.
pub fn url(d: *const Diagnostics) ?[]const u8 {
    const len = d.url_len orelse return null;
    return d.url_storage[0..len];
}

/// The fields that a caller supplies to `record`. A null field leaves the
/// value in the `Diagnostics` unchanged.
pub const Detail = struct {
    /// The url text as the caller holds it, password and all. `record`
    /// masks it. Pass the raw text: masking it twice is not harmful, but
    /// a caller that must remember to mask is a caller that can forget.
    url: ?[]const u8 = null,
    host: ?[]const u8 = null,
    status: ?u16 = null,
    message: ?[]const u8 = null,
};

/// Writes `detail` and the libcurl code for `err` into `d`, then returns
/// `err`.
///
/// The return value lets a caller write `return Diagnostics.record(...)` in
/// one line, so no recovery path can forget to fill the diagnostics.
///
/// `host` and `message` are borrowed and must outlive the `Diagnostics`.
/// `url` is copied into the `Diagnostics`'s own storage, with the
/// userinfo password masked, so it need not outlive the call and cannot
/// reach a message unmasked.
pub fn record(d: ?*Diagnostics, err: Error, detail: Detail) Error {
    const target = d orelse return err;
    if (detail.url) |v| target.url_len = redact.copy(&target.url_storage, v).len;
    if (detail.host) |v| target.host = v;
    if (detail.status) |v| target.status = v;
    if (detail.message) |v| target.message = v;
    target.curl_code = curlCode(err);
    return err;
}

test "record fills the fields and returns the error unchanged" {
    var d: Diagnostics = .{};
    const returned = record(&d, error.HttpReturnedError, .{
        .url = "https://example.com/a",
        .host = "example.com",
        .status = 404,
    });
    try std.testing.expectError(error.HttpReturnedError, @as(Error!void, returned));
    try std.testing.expectEqualStrings("https://example.com/a", d.url().?);
    try std.testing.expectEqualStrings("example.com", d.host.?);
    try std.testing.expectEqual(@as(u16, 404), d.status.?);
    try std.testing.expectEqual(@as(u32, 22), d.curl_code.?);
}

test "record accepts a null diagnostics pointer" {
    const returned = record(null, error.CouldNotConnect, .{ .host = "example.com" });
    try std.testing.expectError(error.CouldNotConnect, @as(Error!void, returned));
}

/// Fills `d` and drops the error that `record` hands back.
///
/// Production code returns that error, so nothing outside a test wants
/// this. A test that only sets up a `Diagnostics` does.
fn fill(d: *Diagnostics, err: Error, detail: Detail) void {
    _ = @as(Error!void, record(d, err, detail)) catch {};
}

test "record keeps a field that the detail does not set" {
    var d: Diagnostics = .{};
    fill(&d, error.HttpReturnedError, .{ .url = "https://example.com/a" });
    const returned = record(&d, error.CouldNotConnect, .{ .host = "example.com" });
    try std.testing.expectError(error.CouldNotConnect, @as(Error!void, returned));
    try std.testing.expectEqualStrings("https://example.com/a", d.url().?);
}

test "record masks a password in any url it is given" {
    // This is the whole guarantee. `record` is the only writer of the
    // url, so a caller that hands it the raw text the user typed still
    // cannot put a password in a `Diagnostics`, and a caller added later
    // has nowhere else to put a url.
    var d: Diagnostics = .{};
    fill(&d, error.WriteError, .{ .url = "http://alice:hunter2@127.0.0.1:8080/x" });
    try std.testing.expectEqualStrings("http://alice:***@127.0.0.1:8080/x", d.url().?);
    try std.testing.expect(std.mem.indexOf(u8, d.url().?, "hunter2") == null);
}

test "a copied Diagnostics still reads back its own url" {
    // The url lives in the struct's own storage and is read by length, so
    // a copy of the whole struct does not leave the reader pointing at the
    // original. A slice field would have.
    var d: Diagnostics = .{};
    fill(&d, error.WriteError, .{ .url = "http://example.com/a" });
    const copied = d;
    try std.testing.expectEqualStrings("http://example.com/a", copied.url().?);
}

test "a Diagnostics no writer touched names no url" {
    const d: Diagnostics = .{};
    try std.testing.expectEqual(@as(?[]const u8, null), d.url());
}
