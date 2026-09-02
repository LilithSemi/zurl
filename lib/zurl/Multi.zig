//! `Multi`: runs several transfers at once, each on its own `Client`.
//!
//! A `Client` cannot serve two transfers at once. `performHttp` rebuilds
//! its `body_stack` in place on every call, and a `Client` is not safe to
//! move once `perform` has opened an `Exchange`: `h1.Exchange` holds a
//! `*Connection` from that client's own pool. `Multi` gives every
//! concurrent slot its own `Client`, allocated once at `init` and
//! addressed by pointer for the rest of its life, the way curl's multi
//! interface owns many easy handles instead of sharing one.
//!
//! `Multi` builds on `download.toFile`, not `Client.perform`. A
//! `Response.body` stays valid only until its own client's next `perform`,
//! and it cannot outlive `run`, so a multi built on `perform` could not
//! hand a caller a body to read after `run` returns. `toFile` has no such
//! limit: it hashes and publishes the body itself and returns a plain
//! value, `download.Result`, that a caller keeps for as long as it likes.
//!
//! Every job names its own destination: `add` takes the `sub_path` a
//! transfer writes, resolved against the `dir` passed to `init`, and
//! `Outcome` echoes it back so a caller can tell which file holds which
//! result. `toFile` writes through a staging file and publishes only on
//! success, so `Multi` never creates a file of its own and has nothing to
//! remove: every file under `dir` belongs to whichever caller named it.
//!
//! `run` drives every queued transfer under `Io.async`, not
//! `Io.concurrent`. `async` runs even on a build with no concurrency, so a
//! caller never sees `error.ConcurrencyUnavailable` from `Multi` itself;
//! only the loopback fixture this file's own tests use needs that
//! fallback, the same way every other HTTP test in this project does.
//!
//! **The zurl command line does not use this, and that is on purpose.**
//! `-Z` has a pool of its own in `src/cli/run.zig`. The two differ in
//! destination policy, which is the reason for the split, and in three
//! more things that follow from it:
//!
//! | | `Multi` | `runParallel` |
//! | --- | --- | --- |
//! | destination | `download.toFile`, staged, published on success | curl's own `-o`, truncated in place, partial bytes kept |
//! | spawn | `Io.async`, always runs | `Io.concurrent`, may degrade and say so |
//! | work split | fixed stride | atomic claim by index |
//! | failure | every outcome kept | the first non-zero exit code |
//!
//! The command line must leave the file curl leaves, partial bytes and
//! all, and must let a user point `-o` at `/dev/null` or another special
//! file, which a staged write and an atomic rename cannot do. It also
//! throws away the SHA-256 that `toFile` computes for every byte. A
//! `Multi` built for a cache and a pool built for curl's contract are two
//! policies, not one, so neither calls the other.
//!
//! Keep this in mind when a concurrency defect is found in one of them:
//! the same defect is likely open in the other, and closing one does not
//! close the other.

const Multi = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const Client = @import("Client.zig");
const Transfer = @import("Transfer.zig");
const download = @import("download.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// A queued transfer, waiting for a slot. Every field is borrowed: the
/// caller must keep `url_text`, `sub_path`, and every slice `options`
/// holds such as `options.headers`, alive for as long as the caller reads
/// `outcomes()` afterward, not only until `run` returns.
const Job = struct {
    url_text: []const u8,
    /// Where this transfer writes, resolved against the `Multi`'s `dir`.
    sub_path: []const u8,
    options: Transfer.Options,
};

/// What one transfer produced.
///
/// Read an `Outcome` through a pointer, never copy it by value.
/// `Diagnostics.record` can make `diagnostics.url` point back into this
/// same `Outcome`'s own `diagnostics.url_storage`. A struct copy carries
/// that pointer forward unchanged, now pointing into storage that belongs
/// to a different `Outcome`, or to one that no longer exists.
pub const Outcome = struct {
    /// The url `add` queued this transfer with. Borrowed from the caller,
    /// the same way `Job.url_text` is.
    url: []const u8,
    /// The `sub_path` `add` queued this transfer with. Borrowed from the
    /// caller, the same way `url` is.
    sub_path: []const u8,
    result: Error!download.Result,
    /// This outcome's own diagnostics. `run` never shares one
    /// `Diagnostics` between two slots, or between two transfers the same
    /// slot serves in turn: every `Outcome` in `outcomes()` owns a value
    /// of its own.
    diagnostics: Diagnostics,
};

/// Returned when `init` is asked for zero slots.
pub const InitError = Allocator.Error || error{
    /// Zero slots can never run a queued transfer. Left unchecked, `run`
    /// would return with every job still queued and no outcome to show
    /// for it: not a hang, since `run` still returns, but a silent no-op
    /// that reads like one to a caller who expected the work to run.
    /// Refusing here turns that silent drop into an error the caller sees
    /// at the one call that can still do something about it.
    NoSlots,
};

gpa: Allocator,
io: Io,
dir: Io.Dir,
/// One `Client` per slot, allocated once. A `Client` is not safe to move
/// after its first `perform`, so every worker task addresses its
/// `Client` by pointer into this slice; nothing ever copies one out.
clients: []Client,
/// One `Future` per slot, reused by every `run` call.
futures: []Io.Future(void),
jobs: std.ArrayList(Job),
/// One outcome per queued job. `add` grows this alongside `jobs`, so
/// `run` never allocates: it only claims the capacity `add` already
/// reserved.
outcome_storage: std.ArrayList(Outcome),

/// Allocates `slots` clients, once, and returns a `Multi` ready for `add`.
///
/// `dir` is the base directory every job's `sub_path` resolves against. It
/// must outlive the `Multi`. `Multi` never creates or removes anything
/// inside `dir` itself: it did not create the directory and does not own
/// it or any file a caller's own `sub_path` names.
pub fn init(gpa: Allocator, io: Io, dir: Io.Dir, slots: usize) InitError!Multi {
    if (slots == 0) return error.NoSlots;

    const clients = try gpa.alloc(Client, slots);
    errdefer gpa.free(clients);
    for (clients) |*c| c.* = .init(gpa, io);

    const futures = try gpa.alloc(Io.Future(void), slots);

    return .{
        .gpa = gpa,
        .io = io,
        .dir = dir,
        .clients = clients,
        .futures = futures,
        .jobs = .empty,
        .outcome_storage = .empty,
    };
}

/// Closes every `Client` and frees everything `init` and `add` allocated.
///
/// Touches no file inside `dir`: `Multi` never wrote one of its own to
/// remove. `toFile` publishes atomically and only on success, so a
/// caller's `dir` holds exactly the files their own `sub_path`s named,
/// nothing `Multi` needs to clean up.
pub fn deinit(m: *Multi) void {
    for (m.clients) |*c| c.deinit();
    m.gpa.free(m.clients);
    m.gpa.free(m.futures);
    m.jobs.deinit(m.gpa);
    m.outcome_storage.deinit(m.gpa);
}

/// Queues a transfer that writes to `sub_path`, resolved against the
/// `Multi`'s own `dir`. `run` drives it once it reaches the front of
/// whichever slot it lands on.
///
/// `url_text`, `sub_path`, and every slice `options` holds are borrowed,
/// not copied: they must stay valid for as long as the caller reads
/// `outcomes()`, not only until `run` returns.
pub fn add(m: *Multi, url_text: []const u8, sub_path: []const u8, options: Transfer.Options) Allocator.Error!void {
    try m.jobs.append(m.gpa, .{ .url_text = url_text, .sub_path = sub_path, .options = options });
    // Reserved here, not in `run`, so `run` can stay a plain `void`
    // function that only ever writes into capacity `add` already bought.
    try m.outcome_storage.ensureTotalCapacity(m.gpa, m.jobs.items.len);
}

/// Drives every queued transfer to completion, then returns.
///
/// Splits the queue across `clients.len` slots by index: job `i` runs on
/// slot `i % clients.len`. A slot with more than one job runs them one
/// after another, on its own `Client`, so a job's failure never reaches a
/// job on another slot, and never stops the jobs still queued behind it
/// on its own slot either.
///
/// Calling `run` again is well defined. It replays every job `add` has
/// ever queued, including ones an earlier `run` already finished, and
/// `outcomes()` afterward holds only the new results: `run` clears the
/// old ones first, rather than appending behind them.
pub fn run(m: *Multi) void {
    // Clears `items.len` back to zero without releasing capacity, so a
    // second `run` writes into the same reserved storage `add` already
    // paid for instead of growing `items.len` past it. Without this, a
    // second `run` calls `addManyAsSliceAssumeCapacity` while `items.len`
    // is already `n`, asking for `2n` against a capacity of only `n`: an
    // assert failure in Debug, and silently out-of-bounds memory in
    // ReleaseFast.
    m.outcome_storage.clearRetainingCapacity();

    const n = m.jobs.items.len;
    if (n == 0) return;
    _ = m.outcome_storage.addManyAsSliceAssumeCapacity(n);

    for (0..m.clients.len) |slot| m.futures[slot] = m.io.async(worker, .{ m, slot });
    for (m.futures[0..m.clients.len]) |*f| f.await(m.io);
}

/// One slot's share of the queue, from `run`.
///
/// Writes each outcome straight into its final slot in
/// `m.outcome_storage`, never through a local copy. `Diagnostics.record`
/// can make a `Diagnostics` self-referential: a redacted url points back
/// into that same `Diagnostics`'s own `url_storage`. Building the outcome
/// in a local variable and copying it into place afterward would carry
/// that pointer along unchanged, now pointing at a `url_storage` that no
/// longer exists. Passing `&outcome.diagnostics`, already at its
/// permanent address, straight to `toFile` is what keeps the pointer
/// honest.
fn worker(m: *Multi, slot: usize) void {
    var i = slot;
    while (i < m.jobs.items.len) : (i += m.clients.len) {
        const job = m.jobs.items[i];
        const outcome = &m.outcome_storage.items[i];
        outcome.* = .{ .url = job.url_text, .sub_path = job.sub_path, .result = undefined, .diagnostics = .{} };
        outcome.result = download.toFile(&m.clients[slot], job.url_text, m.dir, job.sub_path, job.options, &outcome.diagnostics);
    }
}

/// Every outcome `run` has produced so far, in queue order.
pub fn outcomes(m: *const Multi) []const Outcome {
    return m.outcome_storage.items;
}

const testing = std.testing;
const test_server = @import("zurl-http").test_server;

test "zero slots is a programmer error, not a hang" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // A plain function call that returns, with a named error, is
    // definitionally not a hang: the fact this test proves is that a
    // caller finds out right here, synchronously, rather than watching
    // `run` return having done nothing.
    try testing.expectError(error.NoSlots, Multi.init(testing.allocator, testing.io, tmp.dir, 0));
}

test "a multi with no transfers runs and reports nothing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var m: Multi = try .init(testing.allocator, testing.io, tmp.dir, 2);
    defer m.deinit();

    m.run();
    try testing.expectEqual(@as(usize, 0), m.outcomes().len);
}

test "two transfers both complete and report their own results" {
    var server_a: test_server.TestServer = undefined;
    try server_a.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
    });
    defer server_a.stop();

    var server_b: test_server.TestServer = undefined;
    try server_b.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    });
    defer server_b.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var m: Multi = try .init(testing.allocator, testing.io, tmp.dir, 2);
    defer m.deinit();

    const url_a = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_a.port()});
    defer testing.allocator.free(url_a);
    const url_b = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_b.port()});
    defer testing.allocator.free(url_b);

    try m.add(url_a, "out-a", .{});
    try m.add(url_b, "out-b", .{});
    m.run();

    const results = m.outcomes();
    try testing.expectEqual(@as(usize, 2), results.len);

    for (results) |*o| {
        if (std.mem.eql(u8, o.url, url_a)) {
            const r = try o.result;
            try testing.expectEqual(@as(u64, 3), r.size);
            try testing.expectEqual(@as(u16, 200), r.status);
        } else if (std.mem.eql(u8, o.url, url_b)) {
            const r = try o.result;
            try testing.expectEqual(@as(u64, 5), r.size);
            try testing.expectEqual(@as(u16, 200), r.status);
        } else {
            return error.TestUnexpectedResult;
        }
    }
}

test "more transfers than slots still all complete, each with its own body" {
    // Four distinct servers, four distinct bodies, and four distinct
    // destinations. Two slots serving four jobs means slots 0 and 1 each
    // serve two jobs in turn on the same `Client`; identical "ok" bodies
    // could not tell a correct run from one where slot reuse crossed two
    // transfers' bytes, so each case here differs from every other one.
    var server_0: test_server.TestServer = undefined;
    try server_0.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nzero"});
    defer server_0.stop();

    var server_1: test_server.TestServer = undefined;
    try server_1.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none"});
    defer server_1.stop();

    var server_2: test_server.TestServer = undefined;
    try server_2.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo"});
    defer server_2.stop();

    var server_3: test_server.TestServer = undefined;
    try server_3.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nthree"});
    defer server_3.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var m: Multi = try .init(testing.allocator, testing.io, tmp.dir, 2);
    defer m.deinit();

    const url_0 = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_0.port()});
    defer testing.allocator.free(url_0);
    const url_1 = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_1.port()});
    defer testing.allocator.free(url_1);
    const url_2 = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_2.port()});
    defer testing.allocator.free(url_2);
    const url_3 = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_3.port()});
    defer testing.allocator.free(url_3);

    try m.add(url_0, "out-0", .{});
    try m.add(url_1, "out-1", .{});
    try m.add(url_2, "out-2", .{});
    try m.add(url_3, "out-3", .{});
    m.run();

    const results = m.outcomes();
    try testing.expectEqual(@as(usize, 4), results.len);

    const Case = struct { url: []const u8, sub_path: []const u8, body: []const u8 };
    const cases = [_]Case{
        .{ .url = url_0, .sub_path = "out-0", .body = "zero" },
        .{ .url = url_1, .sub_path = "out-1", .body = "one" },
        .{ .url = url_2, .sub_path = "out-2", .body = "two" },
        .{ .url = url_3, .sub_path = "out-3", .body = "three" },
    };

    for (cases) |case| {
        const o = for (results) |*r| {
            if (std.mem.eql(u8, r.url, case.url)) break r;
        } else unreachable;

        const result = try o.result;
        try testing.expectEqual(@as(u16, 200), result.status);
        try testing.expectEqual(@as(u64, case.body.len), result.size);

        const contents = try tmp.dir.readFileAlloc(testing.io, case.sub_path, testing.allocator, .limited(64));
        defer testing.allocator.free(contents);
        try testing.expectEqualStrings(case.body, contents);
    }
}

test "one failing transfer does not stop the others" {
    var server_a: test_server.TestServer = undefined;
    try server_a.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server_a.stop();

    var server_c: test_server.TestServer = undefined;
    try server_c.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server_c.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // One slot per transfer, so the failing middle transfer cannot share
    // a slot, and therefore a `Client`, with either of the good ones.
    var m: Multi = try .init(testing.allocator, testing.io, tmp.dir, 3);
    defer m.deinit();

    const url_a = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_a.port()});
    defer testing.allocator.free(url_a);
    // Port 1 is closed on loopback, the same fixture `Client.zig`'s own
    // tests use for a connection that never succeeds.
    const url_b = "http://127.0.0.1:1/";
    const url_c = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_c.port()});
    defer testing.allocator.free(url_c);

    try m.add(url_a, "out-a", .{});
    try m.add(url_b, "out-b", .{});
    try m.add(url_c, "out-c", .{});
    m.run();

    const results = m.outcomes();
    try testing.expectEqual(@as(usize, 3), results.len);

    for (results) |*o| {
        if (std.mem.eql(u8, o.url, url_b)) {
            try testing.expectError(error.CouldNotConnect, o.result);
        } else {
            _ = try o.result;
        }
    }
}

test "each transfer gets its own diagnostics" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var m: Multi = try .init(testing.allocator, testing.io, tmp.dir, 2);
    defer m.deinit();

    // Two different causes of failure, and neither needs a live server: a
    // closed port, and a scheme zurl has no handler for. That lets this
    // test run in every build configuration, including single-threaded.
    const url_closed = "http://127.0.0.1:1/";
    const url_unsupported = "ftp://127.0.0.1/file";

    try m.add(url_closed, "out-closed", .{});
    try m.add(url_unsupported, "out-unsupported", .{});
    m.run();

    const results = m.outcomes();
    try testing.expectEqual(@as(usize, 2), results.len);

    const closed = for (results) |*o| {
        if (std.mem.eql(u8, o.url, url_closed)) break o;
    } else unreachable;
    const unsupported = for (results) |*o| {
        if (std.mem.eql(u8, o.url, url_unsupported)) break o;
    } else unreachable;

    // Each outcome names its own url through `Outcome.url` itself, set
    // from the job it answers, not read back out of `Diagnostics`.
    try testing.expectEqualStrings(url_closed, closed.url);
    try testing.expectEqualStrings(url_unsupported, unsupported.url);

    try testing.expectError(error.CouldNotConnect, closed.result);
    try testing.expectError(error.UnsupportedProtocol, unsupported.result);

    // The defect this test exists to catch: a `Multi` that shares one
    // `Diagnostics` between slots would leave both outcomes reading back
    // whichever transfer recorded into it last.
    try testing.expectEqualStrings("127.0.0.1", closed.diagnostics.host.?);
    try testing.expectEqual(@as(?[]const u8, null), closed.diagnostics.url());
    try testing.expectEqualStrings(url_unsupported, unsupported.diagnostics.url().?);
    try testing.expectEqual(@as(?[]const u8, null), unsupported.diagnostics.host);
    try testing.expect(closed.diagnostics.curl_code.? != unsupported.diagnostics.curl_code.?);
}

test "a caller's unrelated file in dir survives init and deinit" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "not-mine.txt", .data = "the caller put this here" });

    // No `add` and no `run`: `deinit` alone must not touch a file it
    // never created. Before the fix, `deinit` deleted a fixed scratch
    // name in every slot regardless of whether that slot ever wrote,
    // which could delete an unrelated caller file of the same name.
    var m: Multi = try .init(testing.allocator, testing.io, tmp.dir, 1);
    m.deinit();

    const contents = try tmp.dir.readFileAlloc(testing.io, "not-mine.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("the caller put this here", contents);
}

test "two transfers write two different files with the right contents" {
    var server_a: test_server.TestServer = undefined;
    try server_a.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
    });
    defer server_a.stop();

    var server_b: test_server.TestServer = undefined;
    try server_b.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    });
    defer server_b.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var m: Multi = try .init(testing.allocator, testing.io, tmp.dir, 2);
    defer m.deinit();

    const url_a = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_a.port()});
    defer testing.allocator.free(url_a);
    const url_b = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_b.port()});
    defer testing.allocator.free(url_b);

    try m.add(url_a, "first.bin", .{});
    try m.add(url_b, "second.bin", .{});
    m.run();

    for (m.outcomes()) |*o| _ = try o.result;

    const first = try tmp.dir.readFileAlloc(testing.io, "first.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("abc", first);

    const second = try tmp.dir.readFileAlloc(testing.io, "second.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("hello", second);
}

test "a second run is well defined: outcomes reflect only the latest run" {
    var server_a: test_server.TestServer = undefined;
    try server_a.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server_a.stop();

    var server_b: test_server.TestServer = undefined;
    try server_b.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server_b.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var m: Multi = try .init(testing.allocator, testing.io, tmp.dir, 2);
    defer m.deinit();

    const url_a = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_a.port()});
    defer testing.allocator.free(url_a);
    const url_b = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server_b.port()});
    defer testing.allocator.free(url_b);

    try m.add(url_a, "out-a", .{});
    try m.add(url_b, "out-b", .{});

    m.run();
    try testing.expectEqual(@as(usize, 2), m.outcomes().len);

    // Before the fix, a second `run` grew `outcome_storage.items.len` to
    // `2 * n` against a capacity of only `n`: `array_list.zig` asserts in
    // Debug, and ReleaseFast hands back a slice that reads past the end
    // of the allocation with no error at all. `outcomes()` here must
    // report exactly the two jobs `add` queued, not four.
    m.run();
    const results = m.outcomes();
    try testing.expectEqual(@as(usize, 2), results.len);
    for (results) |*o| _ = try o.result;
}
