//! Turns a fault into one line on stderr.
//!
//! `src/main.zig` does wiring only, so the two places a fault becomes text
//! live here. Each function writes one line and keeps no state.
//!
//! The two faults carry their detail differently, and that is why there
//! are two functions. `Args` writes a whole sentence into `Args.Fault`
//! before it returns, so a usage fault only needs printing. A transfer
//! fault arrives as an error plus a `zurl_core.Diagnostics`, which holds
//! the parts and no sentence, so this file builds the sentence.

const std = @import("std");
const zurl_core = @import("zurl-core");

const safe = @import("safe.zig");

const Io = std.Io;

/// The line that follows every usage fault. curl prints the same
/// invitation. A user who reads only the fault does not know where to look
/// next.
pub const help_hint = "zurl: try 'zurl --help' for more information\n";

/// Writes the sentence for a usage fault, then `help_hint`.
///
/// `message` is `Args.Fault.message`, which already starts with `zurl: `.
/// An empty message means the caller gave `Args` no `Fault`, so this names
/// the error instead. A fault with a bare error name is poor, and a silent
/// exit is worse.
///
/// `err` is `anyerror` because two error sets reach this function:
/// `Args.ParseError` and the faults `main` finds itself, such as a config
/// path it cannot read. Neither set is a subset of the other, and this
/// function only reads the name.
pub fn writeUsageFault(w: *Io.Writer, err: anyerror, message: []const u8) Io.Writer.Error!void {
    if (message.len > 0) {
        try w.print("{s}\n", .{message});
    } else {
        try w.print("zurl: {s}\n", .{@errorName(err)});
    }
    try w.writeAll(help_hint);
}

/// Writes the sentence for a failed transfer.
///
/// The line opens with the libcurl code in parentheses, the way curl
/// writes it, so the number a user reads matches the exit code the shell
/// gets. Every part after the error name is optional: `Diagnostics` holds
/// only what the failing step knew, and a part it never filled is left
/// out rather than printed empty.
///
/// The code comes from `d.curl_code` when the failing step recorded one,
/// and from `err` when it did not. Both give the same number for the same
/// error, because `Diagnostics.record` fills `curl_code` from `curlCode`.
///
/// The line names the url when `Diagnostics` holds one, and the host when
/// it holds only that. A run with several urls needs to say which one
/// failed, and the steps below the url parser record the host alone: they
/// never see the text the user typed.
///
/// Every part that did not come from zurl's own source goes through
/// `safe.Text`. The url is masked already, because
/// `zurl_core.Diagnostics.record` is its only writer and it masks whatever
/// it is given, so this printer masks nothing new; what it adds is the
/// bound and the byte check, which the url, the host, and the message all
/// need. A url, a host name, and an operating-system error name each carry
/// bytes zurl did not choose.
pub fn writeTransferFailure(
    w: *Io.Writer,
    err: zurl_core.Error,
    d: *const zurl_core.Diagnostics,
) Io.Writer.Error!void {
    const code = d.curl_code orelse zurl_core.errors.curlCode(err);
    try w.print("zurl: ({d}) {s}", .{ code, @errorName(err) });
    if (d.url() orelse d.host) |target| try w.print(": {f}", .{safe.Text{
        .bytes = target,
        .max_len = zurl_core.Diagnostics.url_storage_len,
    }});
    if (d.status) |status| try w.print(": status {d}", .{status});
    if (d.message) |message| try w.print(": {f}", .{safe.Text{
        .bytes = message,
        .max_len = zurl_core.Diagnostics.message_storage_len,
    }});
    try w.writeByte('\n');
}

/// The line for a standard output that would not take what zurl wrote.
///
/// `main` writes this when the last flush of standard output fails. That
/// flush is the one write nothing below it can report: it drains bytes
/// that `--version`, `--help`, `-w`, or a body left in the buffer, and it
/// runs after every transfer has already returned its own exit code.
///
/// The sentence names no url. This runs once for the whole run, so there
/// is no one url to name, and `Diagnostics` is not in reach here.
/// `write_error_message` names the flag-free cause instead.
pub fn writeStdoutFault(w: *Io.Writer) Io.Writer.Error!void {
    try w.print(
        "zurl: ({d}) WriteError: {s}\n",
        .{ zurl_core.errors.curlCode(error.WriteError), stdout_write_message },
    );
}

/// Why the last flush of standard output failed. `writeStdoutFault` is
/// the only writer of it. A transfer that cannot write its own body names
/// the body instead, because it knows which url it was reading.
pub const stdout_write_message: []const u8 = "cannot write to standard output";

const testing = std.testing;

/// Fills `d` for a test and drops the error `record` hands back.
///
/// `zurl_core.Diagnostics.record` returns the error so a recovery path can
/// write `return record(...)` in one line. A test that only wants the
/// filled `Diagnostics` has no such line to write.
fn fill(
    d: *zurl_core.Diagnostics,
    err: zurl_core.Error,
    detail: zurl_core.Diagnostics.Detail,
) void {
    _ = @as(zurl_core.Error!void, zurl_core.Diagnostics.record(d, err, detail)) catch {};
}

test "a usage fault prints the parser's own sentence and the help hint" {
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);

    try writeUsageFault(&w, error.UnknownFlag, "zurl: unknown flag: '--nope'");

    try testing.expectEqualStrings(
        "zurl: unknown flag: '--nope'\n" ++ help_hint,
        w.buffered(),
    );
}

test "a usage fault with no sentence names the error instead" {
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);

    try writeUsageFault(&w, error.MissingArgument, "");

    try testing.expectEqualStrings("zurl: MissingArgument\n" ++ help_hint, w.buffered());
}

test "a transfer failure opens with the libcurl code and the error name" {
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    const d: zurl_core.Diagnostics = .{ .curl_code = 7 };

    try writeTransferFailure(&w, error.CouldNotConnect, &d);

    try testing.expectEqualStrings("zurl: (7) CouldNotConnect\n", w.buffered());
}

test "a transfer failure adds the url, the status, and the message it was given" {
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var d: zurl_core.Diagnostics = .{};
    fill(&d, error.HttpReturnedError, .{
        .url = "http://example.com/a",
        .status = 404,
        .message = "not found",
    });

    try writeTransferFailure(&w, error.HttpReturnedError, &d);

    try testing.expectEqualStrings(
        "zurl: (22) HttpReturnedError: http://example.com/a: status 404: not found\n",
        w.buffered(),
    );
}

test "a transfer failure names the host when the diagnostics hold no url" {
    // A connect failure records the host and never the url: the engine
    // works from a parsed `Url` and never sees the text the user typed.
    // A run with several urls still has to say which host failed.
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    const d: zurl_core.Diagnostics = .{ .host = "127.0.0.1", .curl_code = 7 };

    try writeTransferFailure(&w, error.CouldNotConnect, &d);

    try testing.expectEqualStrings("zurl: (7) CouldNotConnect: 127.0.0.1\n", w.buffered());
}

test "a transfer failure prefers the url over the host when it holds both" {
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var d: zurl_core.Diagnostics = .{};
    fill(&d, error.CouldNotConnect, .{
        .url = "http://example.com/a",
        .host = "example.com",
    });

    try writeTransferFailure(&w, error.CouldNotConnect, &d);

    try testing.expectEqualStrings("zurl: (7) CouldNotConnect: http://example.com/a\n", w.buffered());
}

test "a transfer failure carries no password, whatever url it was handed" {
    // The guarantee is in `Diagnostics.record`, which is the only writer
    // of the url and masks whatever it is given. This checks it holds at
    // the far end, where the line reaches the user.
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var d: zurl_core.Diagnostics = .{};
    fill(&d, error.WriteError, .{
        .url = "http://alice:hunter2@127.0.0.1:8080/x",
        .message = "cannot write the body to standard output",
    });

    try writeTransferFailure(&w, error.WriteError, &d);

    try testing.expectEqualStrings(
        "zurl: (23) WriteError: http://alice:***@127.0.0.1:8080/x: cannot write the body to standard output\n",
        w.buffered(),
    );
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "hunter2") == null);
}

test "a transfer failure sanitises a control byte in a host the peer chose" {
    // A host reaches this line from a redirect target or from a url the
    // user pasted. A raw escape byte there would let it colour the
    // terminal or draw a line of its own.
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    const d: zurl_core.Diagnostics = .{ .host = "ex\x1b[31mample", .curl_code = 7 };

    try writeTransferFailure(&w, error.CouldNotConnect, &d);

    try testing.expectEqualStrings("zurl: (7) CouldNotConnect: ex?[31mample\n", w.buffered());
}

test "the standard output fault names curl's own code for it" {
    var buffer: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);

    try writeStdoutFault(&w);

    try testing.expectEqualStrings(
        "zurl: (23) WriteError: cannot write to standard output\n",
        w.buffered(),
    );
}

test "a transfer failure reads the code from the error when the diagnostics hold none" {
    // A `Diagnostics` that no `record` call ever touched has a null
    // `curl_code`. The line must still carry curl's number, because the
    // exit code carries it too.
    var buffer: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    const d: zurl_core.Diagnostics = .{};

    try writeTransferFailure(&w, error.PeerFailedVerification, &d);

    try testing.expectEqualStrings("zurl: (60) PeerFailedVerification\n", w.buffered());
}
