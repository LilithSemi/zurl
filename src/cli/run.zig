//! zurl: how the urls in a `Plan` get fetched.
//!
//! This file owns the run. It holds the `Context` every action shares, the
//! choice between one transfer at a time and `-Z`'s several at a time, and
//! the path of one url from the command line to the bytes on disk.
//!
//! It owns no flag and no wording. `src/cli/Args.zig` builds the `Plan`
//! this file runs, `src/cli/report.zig` turns a fault into a line on
//! standard error, `src/cli/output.zig` opens the files, and
//! `src/cli/progress.zig` draws the meter. `src/main.zig` builds the
//! `Context` and calls `transfers`.
//!
//! Four decisions shape this file, and each one has a test:
//!
//! - **One `Client` serves every url in one invocation.** A `Client` holds
//!   the trust store and the connection pool, so a new one for each url
//!   would load the CA bundle again for each url. `-Z` is the one
//!   exception: a `Client` cannot serve two transfers at once, so
//!   `runParallel` gives every worker one of its own and pays that cost
//!   once for each worker.
//! - **A failure on one url does not stop the rest.** curl runs every url
//!   it was given and exits with the code of the *last* transfer that
//!   failed, and a later success does not clear that code. `runSerial`
//!   matches it. `-Z` keeps the *first* failure instead, which is what
//!   curl's own parallel path does. See `runParallel`.
//! - **The progress meter goes to standard error, and only to standard
//!   error.** `src/cli/progress.zig` draws it. A body written to standard
//!   output therefore stays exactly the bytes the peer sent. `-s` turns
//!   the meter off, and `-S` does not turn it back on, which is what
//!   curl 8.21.0 does.
//! - **A body that goes to a terminal draws no meter.** The two streams
//!   reach the same screen there, so the meter's row would cut into the
//!   body, and a user who pipes that screen into a parser reads corrupt
//!   data. curl closes this by drawing nothing, measured under a real
//!   pty. `meterVisibility` collects the answer for one url and
//!   `progress.draws` decides. `Context.stdout_is_terminal` is the one
//!   input that comes from the operating system, and `src/main.zig` is
//!   the one place that reads it.
//! - **A `-O` name zurl will not write stops that url before it reaches a
//!   server.** `fetchOne` reads the name out of the url and checks it
//!   before it calls `perform`. Most urls get a name this way, one the
//!   url wrote or, failing that, curl's own `curl_response`; only a name
//!   that would reach a path outside the working directory, or that
//!   carries a byte no file name may hold, stops the url before the
//!   network does.

const std = @import("std");
const zurl = @import("zurl");
const zurl_core = @import("zurl-core");
const zurl_stream = @import("zurl-stream");
const zurl_file = @import("zurl-file");
const zurl_dict = @import("zurl-dict");
const zurl_gopher = @import("zurl-gopher");
const zurl_tftp = @import("zurl-tftp");
const zurl_ftp = @import("zurl-ftp");
const zurl_pop3 = @import("zurl-pop3");
const zurl_imap = @import("zurl-imap");
const zurl_smtp = @import("zurl-smtp");
const zurl_ws = @import("zurl-ws");
const zurl_telnet = @import("zurl-telnet");
const zurl_sftp = @import("zurl-sftp");
const zurl_scp = @import("zurl-scp");
const zurl_ldap = @import("zurl-ldap");
const zurl_mqtt = @import("zurl-mqtt");
const zurl_rtsp = @import("zurl-rtsp");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// The flag parser. This file reads a `Plan` and never builds one.
const Args = @import("Args.zig");
/// The two places a fault becomes text.
const report = @import("report.zig");
/// Where the body goes, and the one rule that checks a `-O` name.
const output = @import("output.zig");
/// The `-w` format string.
const writeout = @import("writeout.zig");
/// The progress meter, and `--progress-bar`.
const progress = @import("progress.zig");
/// The one printer for untrusted text in a message. Every string `-v`
/// writes goes through it.
const safe = @import("safe.zig");

/// How many transfers `-Z` runs at the same time.
///
/// curl 8.21.0 runs 50, and `--parallel-max` takes it up to 65535. zurl
/// runs eight, because a slot is not free. Every open connection reads the
/// response head through a buffer of `zurl-http`'s own `head_len_max`,
/// which is 300 KiB, and every running transfer holds a 32 KiB write
/// buffer for the file it fills. Eight slots therefore cost
/// 8 * 332 KiB, which is 2.6 MiB, before a single body byte arrives.
/// curl's 50 would cost 16.2 MiB the same way.
///
/// Eight is still far past the point where more slots stop helping.
/// Parallel transfers pay off because a transfer waits on the network, not
/// because it works the processor, so a handful of slots already covers
/// the wait that one transfer spends idle.
const parallel_slots: usize = 8;

/// What every action needs. Gathered once in `main` so no function below
/// reaches for a global, and so a test can see exactly what the actions
/// touch.
pub const Context = struct {
    /// Backs the `Client` and its connection pool.
    gpa: Allocator,
    /// Backs the parsed `Plan` and everything it borrows. Lives as long as
    /// the process.
    arena: Allocator,
    io: Io,
    env: *std.process.Environ.Map,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
    /// Whether `stdout` is a terminal.
    ///
    /// **This is the seam for the progress meter's terminal rule.** A
    /// transfer that writes its body to a terminal draws no meter,
    /// because the meter's row would cut into the body. `src/main.zig` is
    /// the one place that asks the operating system, through
    /// `Io.File.isTty`. Everything below reads this field, so a test
    /// drives the rule both ways by setting a boolean and never needs a
    /// terminal.
    ///
    /// False by default, which is what a test gets and what a spawned
    /// child gets when its output is a pipe.
    stdout_is_terminal: bool = false,
    /// Guards `stdout` and `stderr` while `-Z` runs several transfers at
    /// the same time. Null when one transfer runs at a time, which is
    /// every path but `runParallel`.
    ///
    /// An `Io.Writer` holds one buffer and one end index. Two workers that
    /// wrote through the same one would not merely mix their lines: they
    /// would race on that index and corrupt the buffer. `lockReports` and
    /// `unlockReports` are the only two functions that read this field,
    /// and every write to `stdout` or `stderr` outside a transfer's own
    /// body goes between them.
    report_lock: ?*Io.Mutex = null,
    /// The `-m`/`--max-time` bound this transfer runs under, or null when
    /// the url has no bound.
    ///
    /// `boundedTransfer` sets it on a copy of the `Context` it hands the
    /// raced task, so only the transfer inside the race can see it. The
    /// one reader is `failure`, which stops reporting a fault that the
    /// cancel caused rather than the peer. See `Deadline`.
    deadline: ?*Deadline = null,
};

/// Whether the `-m`/`--max-time` bound of one transfer has passed.
///
/// **Read across two tasks, so the flag is atomic.** `boundedTransfer`
/// runs the transfer and a sleep as two raced tasks. When the sleep wins,
/// that task sets this flag and then cancels the transfer. The transfer
/// wakes inside whatever call was waiting, with `error.Canceled`, and
/// unwinds through `failure`, which reads the flag here.
///
/// The flag latches: nothing ever clears it. One `Deadline` serves one
/// url, and `boundedTransfer` builds a new one for each.
pub const Deadline = struct {
    hit: std.atomic.Value(bool) = .init(false),

    /// Whether the bound has passed. `acquire`, so a reader that sees the
    /// flag also sees everything the writer wrote before it.
    fn reached(d: *const Deadline) bool {
        return d.hit.load(.acquire);
    }
};

/// Takes the lock that guards `ctx.stdout` and `ctx.stderr`, if this run
/// has one. Does nothing when one transfer runs at a time.
fn lockReports(ctx: Context) void {
    // Uncancelable, because the caller is about to write a message the
    // user asked for and there is no path here that answers a cancel.
    if (ctx.report_lock) |m| m.lockUncancelable(ctx.io);
}

/// Releases what `lockReports` took.
fn unlockReports(ctx: Context) void {
    if (ctx.report_lock) |m| m.unlock(ctx.io);
}

/// Drops whatever `w` still holds, after a failed flush that the caller
/// has already reported.
///
/// A failed `flush` leaves the bytes in the buffer, so the next flush
/// tries the same write and fails the same way. Without this, one write
/// fault reported once here would be reported a second time by `main`,
/// and a `-s` run that reported nothing would still get `main`'s line.
///
/// This throws away bytes the user asked for. That is the honest
/// outcome: the stream will not take them, zurl has said so, and holding
/// them only makes the next writer say it again.
pub fn dropUnwritten(w: *Io.Writer) void {
    w.end = 0;
}

/// Fetches every url in `plan` and returns the exit code for the run.
///
/// Picks between the two ways to run them. `-Z` with two or more urls
/// takes `runParallel`, and everything else takes `runSerial`. `-Z` with
/// one url takes `runSerial` too: one transfer cannot overlap anything, so
/// `-Z` there is exactly a run with no `-Z`.
///
/// The two paths differ in more than speed, and each difference has a
/// test:
///
/// - **The exit code.** `runSerial` keeps the last failure and
///   `runParallel` keeps the first, because that is what each matching
///   curl path does.
/// - **The progress meter.** `runParallel` draws none. See its own doc
///   comment.
/// - **A shared destination.** Two transfers cannot fill one file, or one
///   standard output, at the same time. `parallelBlocker` names such a
///   run, and `runParallel` then takes one slot instead of many.
pub fn transfers(ctx: Context, plan: Args.Plan) !u8 {
    // `-D` names one file for the whole run and every url appends its own
    // head blocks to it, so the one truncation happens here, before the
    // first transfer. curl 8.21.0 does the same: the file is there and
    // empty even when no transfer reaches a server.
    if (plan.output.headers_file) |target| switch (target) {
        // `-D -` names standard output, which holds nothing to truncate:
        // the truncation this block does is `-D`'s own file-only rule,
        // and standard output is not a file.
        .stdout => {},
        .file => |headers_path| {
            var d: zurl_core.Diagnostics = .{};
            output.emptyHeadersFile(ctx.io, headers_path, &d) catch |err| {
                if (!plan.silent or plan.show_error) {
                    try report.writeTransferFailure(ctx.stderr, err, &d);
                    try ctx.stderr.flush();
                }
                return exitCodeFor(err);
            };
        },
    };

    if (!plan.parallel or plan.urls.len < 2) return runSerial(ctx, plan);

    const slots = if (try parallelBlocker(ctx.gpa, plan)) |why| one_slot: {
        // IronStyle: recovery is never silent. The user asked for
        // transfers at the same time and gets them one at a time, so the
        // reason reaches stderr before the first one starts.
        try noteParallelDegraded(ctx, plan, why);
        break :one_slot 1;
    } else @min(plan.urls.len, try parallelWanted(ctx, plan));

    return runParallel(ctx, plan, slots);
}

/// How many transfers `-Z` may run at once, after `--parallel-max`.
///
/// `parallel_slots` is the answer with no flag. `--parallel-max` names
/// another, and a number outside 1 to `parallel_max_ceiling` reads as
/// though the flag were not there, which is what curl does: its own
/// `tool_getparam.c` puts a value outside its range back to the default
/// and says nothing.
///
/// zurl says something. IronStyle asks that recovery is never silent, and
/// a user who typed `--parallel-max 5000` and got eight has to hear that
/// the number was not used. The exit code and every transfer stay exactly
/// what curl gives.
fn parallelWanted(ctx: Context, plan: Args.Plan) !usize {
    const wanted = try parallelMaxWanted(ctx, plan);
    return parallelHostCapped(ctx, plan, wanted);
}

/// `parallelWanted` without the `--parallel-max-host` cap.
fn parallelMaxWanted(ctx: Context, plan: Args.Plan) !usize {
    const named = plan.parallel_max orelse return parallel_slots;
    if (named >= 1 and named <= parallel_max_ceiling) return named;

    var buffer: [note_buffer_len]u8 = undefined;
    const message = std.fmt.bufPrint(
        &buffer,
        "zurl: --parallel-max: {d} is outside 1 to {d}, so {d} transfers run at a time",
        .{ named, parallel_max_ceiling, parallel_slots },
    ) catch "zurl: --parallel-max: the number is outside the range zurl reads, so the default is used";
    try noteParallelDegraded(ctx, plan, message);
    return parallel_slots;
}

/// Brings `wanted` down to what `--parallel-max-host` allows.
///
/// **zurl reads the flag as a bound on the whole run, and that is
/// stricter than curl's own per-host bound.** Each `-Z` worker holds one
/// `Client` and runs one url at a time, so a run of *n* workers opens at
/// most *n* connections, and at most *n* of those can reach any one host.
/// Capping the workers therefore keeps the promise for every host in the
/// list, whatever mix of hosts it holds, with no per-host bookkeeping and
/// no worker ever parked waiting for a host to free up.
///
/// The cost is that a run over several hosts may use fewer workers than
/// curl would. It never uses more than the flag allows, and the note below
/// says which flag decided the count, so the narrower reading is never
/// silent.
///
/// A value of zero, or one past `parallel_max_ceiling`, reads as though
/// the flag were not there, which is how `--parallel-max` already reads
/// such a number and how curl reads one.
fn parallelHostCapped(ctx: Context, plan: Args.Plan, wanted: usize) !usize {
    const named = plan.parallel_max_host orelse return wanted;
    if (named < 1 or named > parallel_max_ceiling) {
        var buffer: [note_buffer_len]u8 = undefined;
        const message = std.fmt.bufPrint(
            &buffer,
            "zurl: --parallel-max-host: {d} is outside 1 to {d}, so it changes nothing",
            .{ named, parallel_max_ceiling },
        ) catch "zurl: --parallel-max-host: the number is outside the range zurl reads, so it changes nothing";
        try noteParallelDegraded(ctx, plan, message);
        return wanted;
    }
    if (named >= wanted) return wanted;

    var buffer: [note_buffer_len]u8 = undefined;
    const message = std.fmt.bufPrint(
        &buffer,
        "zurl: --parallel-max-host: {d} bounds the whole run here, not one host, " ++
            "so {d} transfers run at a time",
        .{ named, named },
    ) catch "zurl: --parallel-max-host: the cap bounds the whole run here, not one host";
    try noteParallelDegraded(ctx, plan, message);
    return named;
}

/// The largest `--parallel-max` zurl reads. curl's own ceiling, from its
/// `MAX_PARALLEL`.
const parallel_max_ceiling: usize = 300;

/// Fetches every url in `plan`, in order, one at a time, and returns the
/// exit code for the run.
///
/// One `Client` serves them all: it owns the trust store and the
/// connection pool, and a new one for each url would load the CA bundle
/// again for each url.
///
/// A url that fails does not stop the ones after it, and the code the
/// shell gets is the code of the **last** transfer that failed. A success
/// after a failure does not clear it. curl 8.21.0 behaves the same way,
/// checked against the real program.
fn runSerial(ctx: Context, plan: Args.Plan) !u8 {
    var client: zurl.Client = .init(ctx.gpa, ctx.io);
    defer client.deinit();

    // The fetchers outlive every transfer on this client, and never move:
    // the client holds their addresses and the body of a transfer on any
    // of these protocols points inside one of them. See
    // `registerProtocols`.
    var fetchers: Fetchers = undefined;
    try fetchers.init(ctx.gpa, ctx.io);
    defer fetchers.deinit();
    try registerProtocols(&client, &fetchers);

    var exit_code: u8 = 0;
    // **`--rate`: when the previous transfer started, so the next one can
    // wait its turn.** Null until the first transfer has started, because
    // the flag paces the gap between starts and the first start has no gap
    // in front of it. curl's own flag does the same: the first transfer of
    // a run goes out at once.
    var last_start: ?Io.Timestamp = null;

    for (plan.urls, 0..) |url, index| {
        if (plan.rate_wait_ms) |wait_ms| try waitForRate(ctx, wait_ms, &last_start);

        const code = try fetchOne(ctx, &client, url, plan, index, true);
        if (code != 0) exit_code = code;
        // **`--fail-early`: the run stops at the first url that failed.**
        // Measured against curl 8.21.0 with two urls, the first answering
        // `404`: `--fail --fail-early` fetched the first alone and exited
        // 22, and `--fail` on its own fetched both.
        //
        // The flag reads the exit code and nothing else, which is why
        // `--fail-early` with no `--fail` beside it changes nothing for a
        // `404`: that status is not a failure without `--fail`, so there
        // is no first failure to stop at. curl answers the same way,
        // measured: exit 0, and both urls fetched.
        if (plan.fail_early and code != 0) break;
    }
    return exit_code;
}

/// One fetcher for each protocol package this build carries.
///
/// **One value, because one client needs one of each.** A fetcher holds
/// the transfer in play for its own protocol, so two clients may never
/// share one, and `runParallel` gives every worker a `Fetchers` of its
/// own for the same reason it gives every worker a `Client`.
///
/// **A `Fetchers` must not move once it is registered.** Every dispatch
/// entry carries the address of a field inside it, and the body of a
/// transfer on any of these protocols is a reader that points inside one
/// of those fields.
const Fetchers = struct {
    file: zurl_file.Fetcher,
    dict: zurl_dict.Fetcher,
    gopher: zurl_gopher.Fetcher,
    tftp: zurl_tftp.Fetcher,
    ftp: zurl_ftp.Fetcher,
    pop3: zurl_pop3.Fetcher,
    imap: zurl_imap.Fetcher,
    smtp: zurl_smtp.Fetcher,
    ws: zurl_ws.Fetcher,
    telnet: zurl_telnet.Fetcher,
    sftp: zurl_sftp.Fetcher,
    scp: zurl_scp.Fetcher,
    ldap: zurl_ldap.Fetcher,
    /// **A pointer, where every field above is a value.** An
    /// `zurl_mqtt.Fetcher` holds a megabyte of packet buffer, which is
    /// more than a stack frame should carry, so it lives on the heap and
    /// this field holds its address. The address is what the dispatch
    /// entry carries either way, so nothing else changes.
    mqtt: *zurl_mqtt.Fetcher,
    /// A pointer, for the reason `mqtt` gives: an
    /// `zurl_rtsp.Fetcher` holds a 64 KiB reply head block.
    rtsp: *zurl_rtsp.Fetcher,

    /// Starts `f` in place.
    ///
    /// In place and fallible, where this once returned a value, because
    /// the two heap fetchers can fail to allocate. A caller that stops
    /// part way must call `deinit` on the values it did start and on none
    /// of the others.
    fn init(f: *Fetchers, gpa: Allocator, io: Io) Allocator.Error!void {
        f.file = .init(io);
        f.dict = .init(gpa, io);
        f.gopher = .init(gpa, io);
        f.tftp = .init(gpa, io);
        f.ftp = .init(gpa, io);
        f.pop3 = .init(gpa, io);
        f.imap = .init(gpa, io);
        f.smtp = .init(gpa, io);
        f.ws = .init(gpa, io);
        f.telnet = .init(gpa, io);
        f.sftp = .init(gpa, io);
        f.scp = .init(gpa, io);
        f.ldap = .init(gpa, io);
        f.mqtt = try zurl_mqtt.Fetcher.create(gpa, io);
        errdefer f.mqtt.destroy();
        f.rtsp = try zurl_rtsp.Fetcher.create(gpa, io);
    }

    fn deinit(f: *Fetchers) void {
        f.file.deinit();
        f.dict.deinit();
        f.gopher.deinit();
        f.tftp.deinit();
        f.ftp.deinit();
        f.pop3.deinit();
        f.imap.deinit();
        f.smtp.deinit();
        f.ws.deinit();
        f.telnet.deinit();
        f.sftp.deinit();
        f.scp.deinit();
        f.ldap.deinit();
        f.mqtt.destroy();
        f.rtsp.destroy();
    }
};

/// Registers every protocol package this build carries with `client`.
///
/// **This file is where a build decides which protocols zurl speaks.**
/// The `zurl` package imports no protocol package, so `http` and `https`
/// come from its own built-in table and everything else arrives here.
/// Dropping a package from `build.zig`, dropping its field from
/// `Fetchers`, and dropping its line below is all it takes to build a zurl
/// without it, and a new protocol package joins by adding the three.
///
/// `gophers` takes a second line beside `gopher` because a dispatch table
/// names one scheme for each row. Both rows point at one vtable inside
/// `zurl-gopher`, the way `http` and `https` share one inside `zurl`.
///
/// `fetchers` must outlive `client` and must not move afterwards. Each
/// registration carries the address of a field inside it, and the body of
/// a transfer is a reader that points inside that field.
fn registerProtocols(client: *zurl.Client, fetchers: *Fetchers) !void {
    // Each call teaches `zurl_core.url` the scheme as well as the dispatch
    // table, so a url of that scheme parses from here on. See
    // `zurl.Client.registerProtocol`.
    try client.registerProtocol(fetchers.file.protocol(zurl));
    try client.registerProtocol(fetchers.dict.protocol(zurl));
    try client.registerProtocol(fetchers.gopher.protocol(zurl));
    try client.registerProtocol(fetchers.gopher.secureProtocol(zurl));
    try client.registerProtocol(fetchers.tftp.protocol(zurl));
    // `ftps` takes a second line for the reason `gophers` does, and it
    // carries its own default port: 990 for implicit TLS against 21 for
    // plain FTP, which is what curl dials for each.
    try client.registerProtocol(fetchers.ftp.protocol(zurl));
    try client.registerProtocol(fetchers.ftp.secureProtocol(zurl));
    // `pop3s` takes a second line for the same reason, on port 995 against
    // 110 for plain POP3.
    try client.registerProtocol(fetchers.pop3.protocol(zurl));
    try client.registerProtocol(fetchers.pop3.secureProtocol(zurl));
    // `imaps` takes a second line for the same reason, on port 993 against
    // 143 for plain IMAP.
    try client.registerProtocol(fetchers.imap.protocol(zurl));
    try client.registerProtocol(fetchers.imap.secureProtocol(zurl));
    // `smtps` takes a second line for the same reason, on port 465 against
    // 25 for plain SMTP.
    try client.registerProtocol(fetchers.smtp.protocol(zurl));
    try client.registerProtocol(fetchers.smtp.secureProtocol(zurl));
    // `wss` takes a second line for the same reason, on port 443 against
    // 80 for plain `ws`. The two ports differ because the opening
    // handshake of RFC 6455 is an HTTP request, so it carries the HTTP
    // ports and not a pair of its own.
    try client.registerProtocol(fetchers.ws.protocol(zurl));
    try client.registerProtocol(fetchers.ws.secureProtocol(zurl));
    // `telnet` takes one line: RFC 854 names no encrypted twin, and curl
    // carries none either.
    try client.registerProtocol(fetchers.telnet.protocol(zurl));
    // `sftp` takes one line: SSH carries its own encryption, so there is
    // no plain twin and no second port.
    try client.registerProtocol(fetchers.sftp.protocol(zurl));
    // `scp` takes one line for the same reason, on the same port 22. The
    // two are separate packages over one SSH client: `sftp` speaks a
    // subsystem the server looks up in its own table, and `scp` runs the
    // remote `scp` binary over an `exec` channel. **Only the second one
    // reaches a shell**, and `zurl_scp.command` is the one place in this
    // build that writes such a command.
    try client.registerProtocol(fetchers.scp.protocol(zurl));
    // `ldaps` takes a second line for the reason `gophers` does, on port
    // 636 against 389 for plain LDAP, which is what curl dials for each.
    try client.registerProtocol(fetchers.ldap.protocol(zurl));
    try client.registerProtocol(fetchers.ldap.secureProtocol(zurl));
    // `mqtts` takes a second line for the reason `gophers` does, on port
    // 8883 against 1883 for plain MQTT, which is what curl dials for each.
    try client.registerProtocol(fetchers.mqtt.protocol(zurl));
    try client.registerProtocol(fetchers.mqtt.secureProtocol(zurl));
    // `rtsp` takes one line: RFC 2326 names no encrypted twin, `rtsps`
    // belongs to RTSP 2.0, and curl 8.21.0 carries neither.
    try client.registerProtocol(fetchers.rtsp.protocol(zurl));
}

/// What `runParallel` shares between its workers.
///
/// Every field a worker writes belongs to that worker alone. `next` is the
/// one exception, and it is an atomic.
const ParallelRun = struct {
    /// Carries the lock that guards `stdout` and `stderr`. Copied by
    /// value, so a worker never writes back into the caller's own
    /// `Context`.
    ctx: Context,
    plan: Args.Plan,
    /// The index of the next url no worker has claimed yet.
    ///
    /// Workers claim by index rather than take a fixed share of the queue,
    /// so one slow url never leaves another worker idle with urls still
    /// waiting.
    next: std.atomic.Value(usize),
    /// One `Client` for each worker, addressed by slot. A `Client` cannot
    /// serve two transfers at once: `performHttp` rebuilds its body stack
    /// in place on every call, and an open exchange holds a pointer into
    /// that client's own connection pool. No worker ever touches another
    /// worker's `Client`.
    clients: []zurl.Client,
    /// One result for each url, in the order the command line named them.
    /// Each worker writes only the elements it claimed, and `runParallel`
    /// reads them all once every worker has stopped.
    results: []anyerror!u8,
    /// True once any url has failed. Only `--fail-early` reads it, and a
    /// worker reads it before it claims the next url.
    ///
    /// Atomic because every worker writes it and every worker reads it.
    /// The store is `release` and the load is `acquire`, so a worker that
    /// sees the flag also sees the result behind it.
    failed: std.atomic.Value(bool) = .init(false),
};

/// Fetches every url in `plan` on `slots` workers and returns the exit
/// code for the run. This is `-Z`.
///
/// **The exit code is the first failure, not the last.** Measured against
/// curl 8.21.0 on loopback, with one transfer failing early with
/// `CURLE_HTTP_RETURNED_ERROR` (22) and another failing late with
/// `CURLE_PARTIAL_FILE` (18), and with the two swapped: `-Z` reported the
/// code of whichever transfer failed *first*, in all four orderings, while
/// the same command with no `-Z` reported the last failure in command-line
/// order. curl's parallel loop keeps the first non-zero result it sees and
/// never replaces it.
///
/// zurl reads "first" in command-line order rather than in the order the
/// failures land. The two agree whenever the transfers fail in the order
/// the command line named them, and command-line order has one property
/// curl's does not: the same command on the same server gives the same
/// exit code every time, instead of one that turns on which worker lost a
/// race.
///
/// **This draws no progress meter.** curl 8.21.0 draws a second meter for
/// `-Z`, of columns `DL% UL% Dled Uled Xfers Live Total Current Left
/// Speed`, which counts every transfer on one row. zurl has one meter, the
/// one `src/cli/progress.zig` draws for a single transfer, and several of
/// those on one standard error would overwrite each other's row. Drawing
/// none is the honest answer until zurl has a meter of curl's second
/// shape. `--help` says so.
///
/// **A run that gets fewer workers than it asked for says so.**
/// `Io.concurrent` answers `error.ConcurrencyUnavailable`, and worker 0
/// runs on this task, so every url still runs. The note reaches stderr
/// before the first one starts, and it names how many workers the run
/// really got. `workerShortfallNote` writes it.
/// `Transfer.Options.connect_timeout` degrades the same way, through
/// `Diagnostics.message`.
///
/// A build with no concurrency is one case of that shortfall, and today it
/// is the only one that happens: `error.ConcurrencyUnavailable` is a
/// property of the whole build, so the loop below fails on its first call
/// or on none. A partial start is what the next engine change makes live,
/// and the condition already covers it.
///
/// **`ctx.gpa` must be safe to use from several tasks at once.** Each
/// worker's `Client` allocates from it while the transfers run. It holds
/// today, and by two different rules: a Debug build uses
/// `DebugAllocator`, whose `thread_safe` defaults to `!single_threaded`,
/// and a release build uses `smp_allocator`. `zurl.Multi.init` carries
/// the same requirement.
fn runParallel(ctx: Context, plan: Args.Plan, wanted_slots: usize) !u8 {
    std.debug.assert(wanted_slots >= 1);
    std.debug.assert(wanted_slots <= plan.urls.len);

    // The invariant that keeps `transferOne`'s body write safe. That write
    // goes straight to `ctx.stdout` and takes no lock, because a body is
    // too long to hold one, so more than one worker is allowed only when
    // every body goes to a file. `parallelBlocker` holds this up already
    // and takes the run down to one slot otherwise.
    //
    // **This is a branch, not an assertion.** It used to be
    // `std.debug.assert`, which ReleaseFast removes, and ReleaseFast is
    // the build a user runs. A later `parallelBlocker` that missed a shape
    // would then leave two workers writing bodies into one 4096-byte
    // `Io.Writer`, racing on its end index and corrupting the buffer
    // rather than merely interleaving lines. A branch costs one compare
    // for the whole run and holds in every optimisation mode.
    //
    // Nothing reaches this today, because `parallelBlocker` refuses the
    // same shape first and has already written its own note. If that ever
    // stops being true, this writes a note of its own: recovery is never
    // silent.
    const slots = if (wanted_slots > 1 and plan.output.anyToStdout(plan.urls.len)) one: {
        try noteParallelDegraded(
            ctx,
            plan,
            "zurl: -Z: a body goes to standard output, so the transfers run one at a time",
        );
        break :one 1;
    } else wanted_slots;

    const clients = try ctx.gpa.alloc(zurl.Client, slots);
    defer ctx.gpa.free(clients);
    for (clients) |*c| c.* = .init(ctx.gpa, ctx.io);
    defer for (clients) |*c| c.deinit();

    // **One connection pool for the whole run, and this is the saving.**
    // Every worker owns a `Client`, and a `Client` keeps a pool of its
    // own, so eight urls on one HTTPS host used to cost eight TCP
    // connections and eight TLS handshakes. One pool costs one of each on
    // a peer that speaks HTTP/2: the first worker dials and publishes the
    // connection, the rest join it and each opens a stream. A peer with no
    // HTTP/2 still gets one connection for each worker, because HTTP/1.1
    // carries one request at a time.
    //
    // **It is freed after the clients, and that order is the rule.** Each
    // client holds the pool while it lives and gives its hold back at
    // `deinit`, so the pool must outlive every one of them. The `defer`
    // below is written after the clients' own, and a `defer` runs in
    // reverse, so this runs last.
    //
    // A pool that cannot be allocated is not a failure of the run. Every
    // worker then keeps the pool it would have kept anyway, which is what
    // this command did before sharing existed, and `shareConnections` is
    // simply not called.
    const shared_pool: ?*zurl.ConnectionPool = zurl.createConnectionPool(ctx.gpa, ctx.io) catch null;
    defer if (shared_pool) |pool| zurl.destroyConnectionPool(pool);
    if (shared_pool) |pool| {
        for (clients) |*c| {
            // Every client here was made three lines above and has opened
            // nothing, so nothing can refuse. A branch and not an assert,
            // because an assert disappears in the ReleaseFast build a user
            // runs and a worker with no shared pool is correct, only
            // slower.
            c.shareConnections(pool) catch break;
        }
    }

    // One set of fetchers for each client, for the same reason each worker
    // gets a client of its own: a fetcher holds the one transfer its
    // worker reads, and two workers sharing one would each drop the
    // other's answer. The slice is heap-allocated, so every fetcher keeps
    // one address for the whole run.
    const fetchers = try ctx.gpa.alloc(Fetchers, slots);
    defer ctx.gpa.free(fetchers);
    // **Only the ones that started are torn down.** `Fetchers.init`
    // allocates, so a run that stops part way through this loop must not
    // call `deinit` on a slot that holds nothing. The counter is read when
    // the defer runs, so it covers the success path and the failure path
    // with one line.
    var fetchers_made: usize = 0;
    defer for (fetchers[0..fetchers_made]) |*f| f.deinit();
    for (fetchers) |*f| {
        try f.init(ctx.gpa, ctx.io);
        fetchers_made += 1;
    }
    for (clients, fetchers) |*c, *f| try registerProtocols(c, f);

    const results = try ctx.gpa.alloc(anyerror!u8, plan.urls.len);
    defer ctx.gpa.free(results);

    // Worker 0 runs on this task, so only the workers above it need one.
    const futures = try ctx.gpa.alloc(Io.Future(void), slots - 1);
    defer ctx.gpa.free(futures);

    var lock: Io.Mutex = .init;
    var guarded = ctx;
    guarded.report_lock = &lock;

    var run: ParallelRun = .{
        .ctx = guarded,
        .plan = plan,
        .next = .init(0),
        .clients = clients,
        .results = results,
    };

    var started: usize = 0;
    while (started < futures.len) : (started += 1) {
        futures[started] = ctx.io.concurrent(parallelWorker, .{ &run, started + 1 }) catch |err| switch (err) {
            error.ConcurrencyUnavailable => break,
        };
    }

    // Worker 0 runs on this task, so the run has one more worker than the
    // loop above started. The condition is `running < slots`, not
    // `started == 0`: a run that asked for eight workers and got three
    // said nothing at all, and waited longer than the user asked for with
    // no word about why. Recovery is never silent, and a partial start is
    // a recovery.
    var note_buffer: [note_buffer_len]u8 = undefined;
    if (workerShortfallNote(&note_buffer, slots, started + 1)) |note|
        try noteParallelDegraded(ctx, plan, note);

    parallelWorker(&run, 0);
    for (futures[0..started]) |*f| f.await(ctx.io);

    var exit_code: u8 = 0;
    for (results) |result| {
        const code = try result;
        if (code != 0 and exit_code == 0) exit_code = code;
    }
    return exit_code;
}

/// One worker's share of `run`, claimed url by url.
///
/// Returns `void`, because `Io.concurrent` gives a worker nowhere to
/// report an error to. A `fetchOne` that could not write its own report
/// lands in `run.results`, and `runParallel` raises it after every worker
/// has stopped.
fn parallelWorker(run: *ParallelRun, slot: usize) void {
    while (true) {
        // **`--fail-early` stops every worker, not only this one.** The
        // flag is read before a url is claimed, so a worker that is
        // already inside a transfer finishes it: a transfer cannot be
        // taken back once it has reached a server, and curl's own
        // parallel path lets the running ones finish too.
        if (run.plan.fail_early and run.failed.load(.acquire)) return;

        // Monotonic is enough: the index is the only thing this ordering
        // has to keep, and every result a worker writes is read after
        // `await`, which orders the memory for `runParallel` itself.
        const index = run.next.fetchAdd(1, .monotonic);
        if (index >= run.plan.urls.len) return;
        const result = fetchOne(
            run.ctx,
            &run.clients[slot],
            run.plan.urls[index],
            run.plan,
            index,
            false,
        );
        run.results[index] = result;
        // Release, so a worker that reads `failed` with `acquire` sees
        // this store and everything before it. An error that `fetchOne`
        // could not report counts as a failure too: `runParallel` raises
        // it, and the run has nothing more to gain by claiming more urls.
        if (result) |code| {
            if (code != 0) run.failed.store(true, .release);
        } else |_| run.failed.store(true, .release);
    }
}

/// Returns the sentence that says why `-Z` cannot overlap these urls, or
/// null when it can.
///
/// Two transfers cannot fill one destination at the same time. Standard
/// output is one stream, `-D` names one destination for the whole run
/// (a file, or standard output too, with `-D -`), and two urls can name
/// one file through `-o` or through `-O`. Each of those makes the run one
/// transfer wide.
///
/// **A body on standard output blocks the whole run, not only its own
/// url.** The body write goes straight to `ctx.stdout` and takes no lock,
/// because a body is too long to hold one, while `-w` writes to the same
/// stream under `Context.report_lock`. One unlocked writer beside a locked
/// one still races on the writer's end index, so one url on standard
/// output is enough.
///
/// This runs before the first transfer, so a user learns the run is one
/// wide before waiting for it, not after.
///
/// Takes an allocator rather than a `Context`, because `gpa` is the only
/// field it reads. A test can then drive it with a `Plan` alone.
fn parallelBlocker(gpa: Allocator, plan: Args.Plan) Allocator.Error!?[]const u8 {
    // **One request body, one reader.** Every url of the run reads the
    // same `Transfer.Options.body`, and that source holds one position and
    // is put back to its first byte before each send. Two workers reading
    // it at once would each get a part of it, and each would then send a
    // body that does not match its own `content-length`.
    if (plan.options.body != null)
        return "zurl: -Z: one request body serves every url, and it has one reader, so the transfers run one at a time";
    if (plan.output.anyToStdout(plan.urls.len))
        return "zurl: -Z: a body goes to standard output, which is one stream, so the transfers run one at a time";
    if (plan.output.headers_file != null)
        return "zurl: -Z: -D names one file for every url, so the transfers run one at a time";
    if (try repeatedDestination(gpa, plan))
        return "zurl: -Z: two urls write to the same file, so the transfers run one at a time";
    return null;
}

/// Whether two urls in `plan` write their bodies to one file.
///
/// The key is the destination path: the `-o` path for a url `-o` covers,
/// and the name `output.nameFromUrl` takes out of the url for one `-O`
/// covers. The two kinds share one key space, because `-o a` and a url
/// ending in `/a` name the same file.
///
/// A url whose `-O` name `output.nameFromUrl` refuses stands for itself
/// here. That url fails on its own account later, and two copies of one
/// refused url still name one destination, so the whole url is the honest
/// key.
///
/// Only a url this run actually writes to a file is counted. A url on
/// standard output has no file name to clash with, and `parallelBlocker`
/// has already refused that shape for its own reason.
///
/// Sorts and then compares neighbours, so the cost stays at n log n for a
/// command line that names many urls.
fn repeatedDestination(gpa: Allocator, plan: Args.Plan) Allocator.Error!bool {
    const names = try gpa.alloc([]const u8, plan.urls.len);
    defer gpa.free(names);

    var count: usize = 0;
    for (plan.urls, 0..) |url, index| {
        switch (plan.output.bodyTarget(index)) {
            // Neither of these opens a file, so neither can clash with
            // another url. A discarded body writes nowhere at all.
            .stdout, .discard => {},
            .file => |path| {
                names[count] = path;
                count += 1;
            },
            .url_name => {
                names[count] = output.nameFromUrl(url) catch url;
                count += 1;
            },
        }
    }
    if (count < 2) return false;

    const keys = names[0..count];
    std.mem.sort([]const u8, keys, {}, lessThanBytes);

    for (keys[1..], keys[0 .. keys.len - 1]) |right, left| {
        if (std.mem.eql(u8, left, right)) return true;
    }
    return false;
}

fn lessThanBytes(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

/// How much room `workerShortfallNote` gets for its sentence.
///
/// The longest sentence it writes carries two numbers. `parallel_slots`
/// bounds both at eight today, and twenty digits each covers every `usize`
/// a later bound could name.
const note_buffer_len: usize = 192;

/// Returns the sentence for a `-Z` run that got `running` workers when it
/// asked for `wanted`, or null when it got every worker it asked for.
///
/// **Two wordings, one condition.** `Io.concurrent` answers
/// `error.ConcurrencyUnavailable` for two different reasons, and a user
/// acts on them differently. A run with one worker got no concurrency at
/// all, which is a property of the build. A run with some of the workers
/// it asked for has concurrency and ran out of it, which is a property of
/// the machine. The sentence names which one happened.
///
/// `running` counts worker 0, the one that runs on `runParallel`'s own
/// task, so it is never zero.
///
/// A run of one worker asked for nothing to overlap, so it gets no note:
/// `runParallel` reaches that only after `parallelBlocker` or the standard
/// output branch has already written a note of its own.
///
/// Takes a buffer rather than an allocator, because the sentence is short
/// and bounded, and this must not fail on a run that is already degraded.
/// A buffer too small for the sentence falls back to the wording with no
/// numbers, so the user still hears about the shortfall.
fn workerShortfallNote(buffer: []u8, wanted: usize, running: usize) ?[]const u8 {
    std.debug.assert(running >= 1);
    if (wanted <= 1) return null;
    if (running >= wanted) return null;
    if (running == 1)
        return "zurl: -Z: this build has no concurrency, so the transfers run one at a time";
    return std.fmt.bufPrint(
        buffer,
        "zurl: -Z: this build started {d} of the {d} workers asked for, so the transfers run {d} at a time",
        .{ running, wanted, running },
    ) catch "zurl: -Z: this build started fewer workers than asked for, so fewer transfers run at a time";
}

/// Writes one line saying `-Z` runs the transfers one at a time, and why.
///
/// This is not a failure: every url still runs and the exit code is
/// whatever the transfers earned. So it follows the same `-s` and `-S`
/// rule `noteFallbackName` follows, the one place zurl already asks
/// whether the user wants quiet.
fn noteParallelDegraded(ctx: Context, plan: Args.Plan, message: []const u8) !void {
    if (!plan.silent or plan.show_error) {
        try ctx.stderr.print("{s}\n", .{message});
        try ctx.stderr.flush();
    }
}

/// Collects what decides whether url `index` draws a progress meter.
///
/// This is pure over its four arguments, so a test drives the terminal
/// rule both ways without a terminal. `progress.draws` turns the answer
/// into a yes or a no, and holds the reason for each rule.
///
/// `stdout_is_terminal` comes from `Context`, which `src/main.zig` fills
/// from `Io.File.isTty`. `draw_meter` is false only under `-Z`.
fn meterVisibility(
    plan: Args.Plan,
    index: usize,
    stdout_is_terminal: bool,
    draw_meter: bool,
) progress.Visibility {
    return .{
        .silent = plan.silent,
        .no_meter = plan.no_progress_meter,
        .parallel = !draw_meter,
        .body_to_stdout = plan.output.bodyToStdout(index),
        .stdout_is_terminal = stdout_is_terminal,
    };
}

/// Fetches one url, writes its body where `plan` asked, and then renders
/// the `-w` format string. Returns 0, or the libcurl code for the fault
/// that stopped the transfer.
///
/// `transferOne` does the transfer. This function wraps it because `-w`
/// reports on a transfer that failed as well as on one that worked, the
/// way curl 8.21.0 does: a refused connection still prints
/// `%{http_code}` as `000` and `%{exitcode}` as the libcurl number.
/// Wrapping keeps that one rule in one place, rather than beside every
/// early return inside the transfer.
///
/// **The write-out goes to standard output, after the body, and it is the
/// last thing this url writes there.** Measured against curl 8.21.0 with
/// and without `-o`: with no `-o` the body reaches standard output first
/// and the write-out follows it, and with `-o` the body goes to the file
/// and standard output carries the write-out alone. `-D -` still writes
/// first: measured, `curl -D - -o - -w '...'` puts the head block ahead
/// of the body, which stays ahead of the write-out. `transferOne` already
/// writes the headers before the body, so this ordering falls out of the
/// code as written rather than needing a rule of its own.
///
/// `index` is this url's position on the command line. It picks the url's
/// own `-o`/`-O` destination out of `plan.output`, which pairs one
/// destination with one url the way curl does.
///
/// `draw_meter` is false only under `-Z`. Several meters on one standard
/// error would overwrite each other's row, so `runParallel` draws none.
/// The `Speedometer` still runs, so `-w` still reports the size, the rate,
/// and the time of every transfer.
fn fetchOne(
    ctx: Context,
    client: *zurl.Client,
    url: []const u8,
    plan: Args.Plan,
    index: usize,
    draw_meter: bool,
) !u8 {
    // The clock starts before the connection, because curl's
    // `%{time_total}` counts the name lookup and the connection too. There
    // is no body to wrap yet, so the meter starts on an empty reader and
    // `transferOne` points it at the body once one exists. One meter means
    // one clock, and no second timing path.
    var no_body: Io.Reader = .fixed("");
    var meter_buffer: [0]u8 = .{};
    var meter: zurl_stream.Speedometer = .init(&no_body, ctx.io, &meter_buffer);

    // The progress meter draws from that same `Speedometer`, so the row it
    // writes and the `%{speed_download}` that `-w` prints come from one
    // clock and one count. A second instance in the same stream would
    // report a second, slightly different, transfer.
    //
    // `progress.draws` holds every rule about whether a meter exists.
    // `-s` gives the transfer no reporter at all, `-Z` gives none either,
    // and a body that goes to a terminal gives none, because the meter's
    // row would cut into the body on that screen.
    const visibility = meterVisibility(plan, index, ctx.stdout_is_terminal, draw_meter);
    var display: ?progress.Meter = if (!progress.draws(visibility)) null else .{
        .out = ctx.stderr,
        .style = if (plan.progress_bar) .bar else .meter,
        .columns = if (plan.progress_bar) progress.terminalColumns(ctx.env) else progress.default_columns,
        .speedometer = &meter,
    };

    // A copy, because `plan` is what the caller gave and the reporter
    // points at a local. Every url gets its own meter and its own copy.
    var drawn_plan = plan;
    if (display) |*d| drawn_plan.options.reporter = d.reporter();

    // `transferOne` fills these in as it learns them. The defaults are
    // what a transfer that reached no server reports.
    var values: writeout.Values = .{ .url_effective = url };

    // **The `-m` bound wraps the whole transfer, and the write-out below
    // stays outside it.** curl prints the write-out for a transfer that
    // timed out too, and `%{time_total}` then names the bound the run hit.
    var work: Transfer = .{
        .ctx = ctx,
        .client = client,
        .url = url,
        .plan = drawn_plan,
        .index = index,
        .meter = &meter,
        .values = &values,
        .display = if (display) |*d| d else null,
    };
    // **The `--retry` loop, and it is here for one reason: `-m` bounds one
    // try.** curl bounds each try with `--max-time` and bounds the whole
    // run of tries with `--retry-max-time`, so the two flags cannot be one
    // bound. Measured: `--max-time 1 --retry 2` against a server that
    // never answered ran three requests, each cut off after one second.
    // `boundedTransfer` is inside this loop for that reason.
    var attempt: Attempt = .{};
    work.attempt = &attempt;

    const retry_started = Io.Timestamp.now(ctx.io, .awake);
    var remaining: u32 = plan.retry.attempts;
    // The first wait. `--retry-delay` names it and holds it still, and no
    // flag leaves it at one second and doubles it. See `Args.Retry`.
    var wait_ms: u64 = if (plan.retry.delay_s) |named|
        @as(u64, named) * std.time.ms_per_s
    else
        retry_first_wait_ms;

    const code = while (true) {
        attempt = .{};
        // The budget the *next* decision reads. `transferOne` asks it, at
        // the moment it has an answer from the peer, so the
        // `--retry-max-time` bound is measured where curl measures it.
        work.retry = if (plan.retry.enabled() and remaining > 0)
            RetryBudget{ .rules = plan.retry, .started = retry_started }
        else
            null;

        const attempt_code = switch (plan.max_time) {
            // No bound was asked for, so no second task is needed. This is
            // also the shape every build took before `-m` existed, and a
            // run with no `-m` pays nothing for the flag.
            .none => try transferTask(&work),
            else => try boundedTransfer(&work, plan.max_time),
        };
        if (!attempt.again) break attempt_code;

        const sleep_ms = retryWait(wait_ms, attempt.retry_after_s);
        // **A `Retry-After` that would carry the run past
        // `--retry-max-time` ends the tries instead.** curl does the same,
        // and it is the one place the bound is read against a wait rather
        // than against what has already passed.
        if (retryAfterTooLong(ctx, plan.retry, retry_started, attempt.retry_after_s)) {
            try noteRetryStopped(ctx, plan);
            break attempt_code;
        }

        remaining -= 1;
        try noteRetry(ctx, plan, attempt.reason, sleep_ms, remaining);
        // The doubling belongs to the run with no `--retry-delay`.
        // Measured: `--retry-delay 2` waited two seconds every time, and
        // no flag waited one, two, four, and eight.
        if (plan.retry.delay_s == null) wait_ms = @min(wait_ms * 2, retry_max_wait_ms);

        Io.sleep(ctx.io, .{ .nanoseconds = @intCast(sleep_ms * std.time.ns_per_ms) }, .awake) catch |err| switch (err) {
            // Something outside this run stopped the wait. Report what the
            // try that just failed reported, rather than start another.
            error.Canceled => break attempt_code,
        };
    };

    const format = plan.write_out orelse return code;

    values.size_download = meter.transferred;
    // Read the clock once and give both variables that one reading.
    // `bytesPerSecond` would read it again, and then `%{speed_download}`
    // would describe a longer transfer than `%{time_total}` names.
    values.time_total_ns = meter.elapsedNs();
    values.speed_download = zurl_stream.Speedometer.rate(meter.transferred, values.time_total_ns);

    // Taken as one block, so a `-Z` run writes one url's whole write-out
    // before the next url's begins. `render` writes to both streams, and
    // an unknown variable puts its own line on stderr, so both are held.
    lockReports(ctx);
    defer unlockReports(ctx);

    writeout.render(ctx.stdout, ctx.stderr, format, values) catch |err| switch (err) {
        error.WriteFailed => return try writeOutFailure(ctx, plan, url, code),
    };
    // Flushed for the same reason the body is: this url's write-out must
    // reach standard output before the next url's fault reaches standard
    // error.
    ctx.stdout.flush() catch return try writeOutFailure(ctx, plan, url, code);
    try ctx.stderr.flush();

    return code;
}

/// Everything one transfer needs, as one value, so the whole transfer
/// fits in one raced task.
///
/// A struct and not a parameter list because `std.Io.Select.concurrent`
/// takes the arguments as a tuple, and a tuple of eight is a tuple nobody
/// reads. `zurl_http.h1.Setup` is the same shape for the same reason.
const Transfer = struct {
    ctx: Context,
    client: *zurl.Client,
    url: []const u8,
    plan: Args.Plan,
    index: usize,
    meter: *zurl_stream.Speedometer,
    values: *writeout.Values,
    display: ?*progress.Meter,
    /// What this try may still spend on another one, or null when no try
    /// is left. `transferOne` reads it at the moment it has an answer.
    retry: ?RetryBudget = null,
    /// Where this try records that it wants another. `fetchOne` owns the
    /// value and reads it after the try returns.
    attempt: *Attempt = undefined,
};

/// What one try of a url reports back to the `--retry` loop.
///
/// **A try that asks for another wrote no body byte.** `transferOne`
/// decides before it opens the destination or reads the body, so the file
/// on disk is untouched and there is nothing to rewind. curl rewinds the
/// file instead, because it decides after the body has been written.
const Attempt = struct {
    /// Whether this try wants another. False on every path that wrote the
    /// body or reported a fault that is not one to retry.
    again: bool = false,
    /// Why. Read only when `again` is true, and only to word the note.
    reason: RetryReason = .http_status,
    /// The seconds the peer's own `Retry-After` asked for, when it sent
    /// one that reads as a plain count. Null otherwise.
    retry_after_s: ?u32 = null,
};

/// Why a try wants another one. This words the note and nothing else.
const RetryReason = enum {
    /// The peer answered one of the transient statuses.
    http_status,
    /// The try ran out of time.
    timed_out,
    /// The host name has no address.
    resolve,
    /// The peer did not take the connection.
    connect,
    /// `--retry-all-errors` covered a failure the default set does not.
    other,
};

/// What a try may still spend on another one.
const RetryBudget = struct {
    rules: Args.Retry,
    /// When the first try of this url started. `--retry-max-time` is
    /// measured from here.
    started: Io.Timestamp,
};

/// The first wait between two tries, in milliseconds. curl's own
/// `RETRY_SLEEP_DEFAULT`, measured: no `--retry-delay` waited one second
/// before the second try.
const retry_first_wait_ms: u64 = 1000;

/// The longest the doubling wait reaches. curl's own `RETRY_SLEEP_MAX`,
/// ten minutes.
const retry_max_wait_ms: u64 = 10 * 60 * std.time.ms_per_s;

/// The statuses a bare `--retry` sends the request again for.
///
/// **Measured against curl 8.21.0**, one loopback server for each status,
/// with `--retry 1 --retry-delay 1`. Two requests went out for each status
/// below and one for every other, `400`, `401`, `403`, `404`, `405`,
/// `409`, `425`, `501`, and `507` among them.
///
/// Each of these is the peer saying it did not serve the request: a
/// timeout of its own, too many requests, or a gateway that had nothing to
/// give. That is why a retry here is not a request sent twice to a peer
/// that acted on it once. A failure zurl cannot read that way is held to
/// the harder rule. See `retryFailure`.
fn retryableStatus(status: u16) bool {
    return switch (status) {
        408, 429, 500, 502, 503, 504 => true,
        else => false,
    };
}

/// Whether `err` is a failure this run sends the request again for.
///
/// **Measured against curl 8.21.0.** A bare `--retry` covers a transfer
/// that ran out of time and a host name with no address, and it covers
/// nothing else: a refused connection ran one request, and a body that
/// stopped short of its length ran one. `--retry-connrefused` brings the
/// refused connection in, and `--retry-all-errors` brings in every
/// failure.
///
/// **One widening zurl cannot avoid.** curl reads the operating system's
/// own `ECONNREFUSED` for `--retry-connrefused`. zurl maps every dial
/// fault to `error.CouldNotConnect`, so this flag also covers a host that
/// is unreachable and a network that is down. Both are the same class of
/// fault for a user on a network that drops, and neither reaches a peer,
/// so neither can be a request served twice.
fn retryableFailure(rules: Args.Retry, err: zurl_core.Error) bool {
    if (rules.all_errors) return true;
    return switch (err) {
        // Always, with no flag beside `--retry`. curl retries
        // `CURLE_OPERATION_TIMEDOUT` and `CURLE_COULDNT_RESOLVE_HOST`
        // whatever else the command line said.
        error.OperationTimedOut, error.CouldNotResolveHost => true,
        error.CouldNotConnect => rules.connrefused,
        else => false,
    };
}

/// The reason to word the note with, for `err`.
fn reasonFor(err: zurl_core.Error) RetryReason {
    return switch (err) {
        error.OperationTimedOut => .timed_out,
        error.CouldNotResolveHost => .resolve,
        error.CouldNotConnect => .connect,
        else => .other,
    };
}

/// Whether `budget` still allows another try, right now.
///
/// **`--retry-max-time` is measured at the decision, not at the start of a
/// try.** Measured against curl 8.21.0: `--retry 10 --retry-max-time 5`
/// against a `503` sent requests at 0, 1, 3, and 7 seconds. The try at 3
/// seconds was under the bound, so it earned a wait of 4 seconds and a
/// fourth request past the bound; the try at 7 seconds was over it and
/// earned nothing. So the bound gates the decision and never the wait
/// that follows it.
fn retryAllowed(ctx: Context, budget: ?RetryBudget) bool {
    const b = budget orelse return false;
    if (b.rules.max_time_s == 0) return true;
    const elapsed = b.started.durationTo(Io.Timestamp.now(ctx.io, .awake));
    const bound_ns: i96 = @as(i96, b.rules.max_time_s) * std.time.ns_per_s;
    return elapsed.nanoseconds < bound_ns;
}

/// The wait before the next try: the one the flags built, or the peer's
/// own `Retry-After` when that asks for longer.
///
/// Measured against curl 8.21.0: a `503` carrying `Retry-After: 3` was
/// tried again after three seconds, both with no `--retry-delay` and with
/// `--retry-delay 1`. So the header raises the wait and never lowers it.
fn retryWait(wait_ms: u64, retry_after_s: ?u32) u64 {
    const named = retry_after_s orelse return wait_ms;
    return @max(wait_ms, @as(u64, named) * std.time.ms_per_s);
}

/// Whether a `Retry-After` the peer sent would carry the run past
/// `--retry-max-time`.
///
/// **The check is the peer's header alone, and never the wait the flags
/// built.** curl reads it that way, and the difference is measurable:
/// `--retry 10 --retry-max-time 5` against a `503` with no `Retry-After`
/// sent requests at 0, 1, 3, and 7 seconds, so the doubling wait was
/// allowed to carry the last try well past the bound. Only `retryAllowed`
/// gates that run, and it reads what has already passed. A peer's own
/// header gets this second, tighter check, because a server can name any
/// number it likes.
fn retryAfterTooLong(ctx: Context, rules: Args.Retry, started: Io.Timestamp, retry_after_s: ?u32) bool {
    const named = retry_after_s orelse return false;
    if (rules.max_time_s == 0) return false;
    const elapsed = started.durationTo(Io.Timestamp.now(ctx.io, .awake));
    const elapsed_s: i96 = @divFloor(elapsed.nanoseconds, std.time.ns_per_s);
    return elapsed_s + @as(i96, named) > @as(i96, rules.max_time_s);
}

/// Writes the one line that says a try is coming, and when.
///
/// curl writes `Warning: Problem : HTTP error. Retrying in 1 second. 2
/// retries left.` for the same event, measured. zurl writes its own
/// wording under the same `-s` and `-S` rule every other note follows, so
/// a `-s` run stays quiet and a `-sS` run still hears it.
fn noteRetry(ctx: Context, plan: Args.Plan, reason: RetryReason, sleep_ms: u64, left: u32) !void {
    if (plan.silent and !plan.show_error) return;
    const cause = switch (reason) {
        .http_status => "the server answered a status that asks for another try",
        .timed_out => "the transfer ran out of time",
        .resolve => "the host name has no address",
        .connect => "the peer did not take the connection",
        .other => "the transfer failed",
    };
    lockReports(ctx);
    defer unlockReports(ctx);
    try ctx.stderr.print(
        "zurl: --retry: {s}. Trying again in {d}.{d:0>3} seconds. {d} left.\n",
        .{ cause, sleep_ms / std.time.ms_per_s, sleep_ms % std.time.ms_per_s, left },
    );
    try ctx.stderr.flush();
}

/// Writes the one line that says the tries ended at `--retry-max-time`.
fn noteRetryStopped(ctx: Context, plan: Args.Plan) !void {
    if (plan.silent and !plan.show_error) return;
    lockReports(ctx);
    defer unlockReports(ctx);
    try ctx.stderr.writeAll(
        "zurl: --retry: the next wait would pass --retry-max-time, so no try is left\n",
    );
    try ctx.stderr.flush();
}

/// Reads a `Retry-After` value as a count of seconds.
///
/// **Digits alone.** RFC 9110 also allows an HTTP date there, and curl
/// reads one. zurl reads the count and treats a date as no header at all,
/// so such a response falls back to the wait the flags built. A date that
/// was read wrong would be worse than one that was not read: it would put
/// a wait of days on a run that asked for seconds.
///
/// A count past `retry_after_max_s` is read as that bound. A peer that
/// asks a client to wait a year is not a peer to wait for, and
/// `--retry-max-time` still ends the run either way.
fn retryAfterSeconds(text: ?[]const u8) ?u32 {
    const value = std.mem.trim(u8, text orelse return null, " \t");
    if (value.len == 0) return null;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
    }
    const seconds = std.fmt.parseInt(u64, value, 10) catch return retry_after_max_s;
    return @intCast(@min(seconds, retry_after_max_s));
}

/// The longest `Retry-After` this run reads, in seconds. One hour.
const retry_after_max_s: u32 = 60 * 60;

/// Runs one transfer. This is the task `boundedTransfer` races, and it is
/// also what a url with no `-m` calls directly.
fn transferTask(t: *Transfer) anyerror!u8 {
    return transferOne(
        t.ctx,
        t.client,
        t.url,
        t.plan,
        t.index,
        t.meter,
        t.values,
        t.display,
        t.retry,
        t.attempt,
    );
}

/// Sleeps until the `-m` bound has passed. The other half of the race.
fn deadlineTask(io: Io, timeout: Io.Timeout) Io.Cancelable!void {
    return timeout.sleep(io);
}

/// The two tasks `boundedTransfer` races: the whole transfer, and the
/// bound on it. `std.Io.Select` reports whichever finishes first.
const TransferRace = union(enum) {
    transfer: anyerror!u8,
    deadline: Io.Cancelable!void,
};

/// The sentence a run prints when it cannot enforce `-m`.
///
/// `zurl.Client` writes the same shape for `--connect-timeout` on a build
/// with no concurrency. A dropped bound is a recovery, and recovery is
/// never silent.
const max_time_degraded_message =
    "zurl: -m: this run cannot start a second task, so the time limit was not enforced";

/// Runs one transfer and stops waiting after `bound`. This is
/// `-m`/`--max-time`.
///
/// **The bound covers the whole transfer, and not the connect alone.**
/// `--connect-timeout` bounds the connect and the handshake, inside the
/// engine. This one bounds everything: the name lookup, the connect, the
/// request, every redirect hop, and every byte of the body. Measured
/// against curl 8.21.0 with a loopback server that sent three bytes of a
/// hundred and then stopped: `curl -m 2` returned after two seconds with
/// exit 28 and kept the three bytes. A bound checked between reads could
/// not do that, because the read that never returns is the one that has
/// to end.
///
/// The shape follows `zurl_http.h1.openConnection`: two concurrent tasks,
/// whichever finishes first wins, and the loser is cancelled. A build that
/// cannot start a second task runs the transfer with no bound and says so,
/// which is what `zurl.Client` does for `--connect-timeout`. A silently
/// dropped bound would be worse than a named one.
///
/// **The cancel is what ends a blocked read, and it lands on whatever call
/// was waiting.** So the fault the transfer reports on the way out names a
/// symptom, not the bound. `failure` reads `Context.deadline` and prints
/// nothing on that path, and this function prints the one message the user
/// needs, once, after the race has ended.
fn boundedTransfer(work: *Transfer, bound: Io.Timeout) !u8 {
    const ctx = work.ctx;

    var deadline: Deadline = .{};
    // The task sees the flag; the caller does not. `failure` reads it
    // through this copy, so a transfer outside a race can never take that
    // path.
    work.ctx.deadline = &deadline;

    var results: [2]TransferRace = undefined;
    var race: Io.Select(TransferRace) = .init(ctx.io, &results);

    race.concurrent(.transfer, transferTask, .{work}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            try noteMaxTimeDegraded(ctx, work.plan);
            work.ctx.deadline = null;
            return try transferTask(work);
        },
    };
    race.concurrent(.deadline, deadlineTask, .{ ctx.io, bound }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            // The transfer is already running, so it cannot be taken
            // back. Let it finish with no bound and say the bound went.
            const finished = endTransferRace(&race);
            try noteMaxTimeDegraded(ctx, work.plan);
            return if (finished) |result| try result else 0;
        },
    };

    const first = race.await() catch |err| switch (err) {
        error.Canceled => {
            _ = endTransferRace(&race);
            return err;
        },
    };

    switch (first) {
        // The transfer finished inside its bound, so its own answer
        // stands. The sleep is cancelled and reports nothing.
        .transfer => |result| {
            _ = endTransferRace(&race);
            return try result;
        },
        .deadline => |slept| {
            slept catch |err| switch (err) {
                error.Canceled => {
                    _ = endTransferRace(&race);
                    return err;
                },
            };
            // Set before the cancel, so the transfer sees it on the way
            // out and reports nothing of its own.
            deadline.hit.store(true, .release);
            const finished = endTransferRace(&race);

            // A transfer that had already finished when the bound passed
            // keeps its own answer, whatever it was. Only one that the
            // cancel actually stopped earns the timeout, and a Zig error
            // on that path is the cancel too, so it earns the same.
            const code: u8 = if (finished) |result|
                (result catch exitCodeFor(error.OperationTimedOut))
            else
                exitCodeFor(error.OperationTimedOut);
            if (code == 0) return 0;

            return try reportMaxTime(ctx, work.plan, work.url, work.display);
        },
    }
}

/// Ends `race` and returns whatever the transfer task produced, or null
/// when the caller has already taken that result.
///
/// `std.Io.Select.cancel` waits for every task, so a transfer that
/// finished at the deadline is still reported here.
fn endTransferRace(race: *Io.Select(TransferRace)) ?anyerror!u8 {
    var finished: ?anyerror!u8 = null;
    while (race.cancel()) |result| switch (result) {
        .transfer => |code| finished = code,
        .deadline => {},
    };
    return finished;
}

/// Reports the transfer that ran out of time, and returns curl's own exit
/// code for it.
///
/// `-s` hides the message and `-S` brings it back, the same rule
/// `failure` follows, because this is that same report on a path where
/// the transfer itself could not write it.
fn reportMaxTime(
    ctx: Context,
    plan: Args.Plan,
    url: []const u8,
    display: ?*progress.Meter,
) !u8 {
    if (display) |m| m.finish();
    var d: zurl_core.Diagnostics = .{};
    const err = zurl_core.Diagnostics.record(&d, error.OperationTimedOut, .{
        .url = url,
        .message = "the transfer did not finish inside the -m limit",
    });
    if (!plan.silent or plan.show_error) {
        lockReports(ctx);
        defer unlockReports(ctx);
        try report.writeTransferFailure(ctx.stderr, err, &d);
        try ctx.stderr.flush();
    }
    return exitCodeFor(err);
}

/// Says that this run could not enforce `-m`, under the same `-s` and `-S`
/// rule every other note follows.
fn noteMaxTimeDegraded(ctx: Context, plan: Args.Plan) !void {
    if (plan.silent and !plan.show_error) return;
    lockReports(ctx);
    defer unlockReports(ctx);
    try ctx.stderr.print("{s}\n", .{max_time_degraded_message});
    try ctx.stderr.flush();
}

/// Reports a standard output that would not take this url's write-out,
/// and returns the exit code for the url.
///
/// `code` is what the transfer itself earned. A transfer that already
/// failed keeps its own code, because that fault is the one the user must
/// act on. A transfer that worked takes curl's own code for a write
/// failure.
///
/// The caller holds `report_lock`, so this writes no lock of its own.
fn writeOutFailure(ctx: Context, plan: Args.Plan, url: []const u8, code: u8) !u8 {
    dropUnwritten(ctx.stdout);
    var d: zurl_core.Diagnostics = .{};
    const err = zurl_core.Diagnostics.record(&d, error.WriteError, .{
        .url = url,
        .message = "cannot write the -w output to standard output",
    });
    if (!plan.silent or plan.show_error) {
        try report.writeTransferFailure(ctx.stderr, err, &d);
        try ctx.stderr.flush();
    }
    return if (code != 0) code else exitCodeFor(err);
}

/// Fetches one url and writes its body where `plan` asked. Returns 0, or
/// the libcurl code for the fault that stopped it.
///
/// The `-O` name comes out of the url and is checked **before**
/// `client.perform` runs. A url that names a path instead of a file
/// therefore reaches no server: zurl refuses the name rather than fetch a
/// body it has nowhere to put.
///
/// `meter` counts the body bytes and the time. Every read of the body
/// goes through it, so `%{size_download}` counts what a failed transfer
/// read too, not only what a whole one did.
///
/// `values` gathers what `-w` prints. What this writes into it borrows
/// from the `zurl.Response`, so the caller must render before the next
/// `perform` on this `client`.
///
/// `display` is the progress meter, or null with `-s`. It opens once the
/// response arrives and closes on every path out. **A transfer that
/// reached no server draws nothing**, because `start` never runs, which is
/// what curl 8.21.0 does: a refused connection prints one message and no
/// meter.
fn transferOne(
    ctx: Context,
    client: *zurl.Client,
    url: []const u8,
    plan: Args.Plan,
    index: usize,
    meter: *zurl_stream.Speedometer,
    values: *writeout.Values,
    display: ?*progress.Meter,
    budget: ?RetryBudget,
    attempt: *Attempt,
) !u8 {
    var d: zurl_core.Diagnostics = .{};

    const named_path: ?[]const u8 = switch (plan.output.bodyTarget(index)) {
        // Neither of these names a file. `--out-null` reads the whole body
        // and writes it nowhere, so there is no path to resume from, to
        // check for, or to give a mode to.
        .stdout, .discard => null,
        .file => |named| named,
        .url_name => name: {
            const name = output.nameFromUrl(url) catch |err| return try failure(
                ctx,
                plan,
                display,
                zurl_core.Diagnostics.record(&d, output.faultFor(err), .{ .message = output.explain(err) }),
                &d,
            );
            // curl 8.21.0 invents this name with no word to the user.
            // IronStyle asks that recovery never stay silent, and a note
            // on stderr costs nothing curl's own contract promises: the
            // exit code, the file, and standard output all stay curl's.
            //
            // The check is on the pointer, not the bytes: a url can spell
            // a real last segment "curl_response" too, and that name
            // earns no note, because the url asked for it. Only
            // `output.nameFromUrl` handing back its own constant, because
            // the url asked for nothing, earns one.
            if (name.ptr == output.fallback_name.ptr) try noteFallbackName(ctx, plan);
            break :name name;
        },
    };

    const path: ?[]const u8 = if (named_path) |named|
        try joinOutputDir(ctx, plan, named)
    else
        null;

    // **`--skip-existing`: a file that is already there ends this url
    // here, before any socket opens.** That is what the flag is for: a run
    // that resumes a batch download must not ask the server again for
    // every file it already has.
    //
    // The answer is a `stat` and nothing more. The file is not opened, not
    // truncated, and not read, so a file this run skips is left byte for
    // byte as it was. A url that writes to standard output or that
    // `--out-null` covers has no file to find, so `path` is null there and
    // the url runs.
    //
    // The exit code is 0, which is what curl gives, measured. IronStyle
    // asks that recovery never stay silent, so the user hears which url
    // was skipped and why.
    if (plan.skip_existing) {
        if (path) |destination| {
            if (try alreadyThere(ctx, destination)) {
                try noteSkippedExisting(ctx, plan, destination);
                return 0;
            }
        }
    }

    // **`-C`: where in the file the body starts, and the `Range` header
    // that asks the peer for it.** The offset is read here, from the
    // destination this url writes, because only this function knows which
    // file that is. See `resumeOffset` for what each spelling of the flag
    // measures.
    const resume_offset = try resumeOffset(ctx, plan, path);
    var range_buffer: [range_value_max]u8 = undefined;
    // **The one `Range` header this url sends, and where it came from.**
    //
    // `-r` names the value outright, and `-C` builds one out of the offset
    // it resumes from. `Args` refuses the two flags together, the way curl
    // does, so at most one of them answers here.
    //
    // **A `-H Range:` the user wrote replaces both.** Measured against
    // curl 8.21.0: `-r 0-9 -H 'Range: bytes=7-8'` sends `bytes=7-8` and no
    // second line. Two of that header would let a peer read one request as
    // two, and the user's own header is the user's.
    const range_value: ?[]const u8 = value: {
        if (userWroteRange(plan.options.headers)) break :value null;
        if (plan.range) |named| break :value named;
        if (resume_offset == 0) break :value null;
        break :value std.fmt.bufPrint(&range_buffer, "bytes={d}-", .{resume_offset}) catch
            return try failure(ctx, plan, display, zurl_core.Diagnostics.record(&d, error.RangeError, .{
                .url = url,
                .message = "-C: the offset does not fit in a Range header",
            }), &d);
    };
    // Owned for the length of the transfer. The header list `plan.options`
    // holds is the caller's, so a `Range` of this url's own goes into a
    // copy and never into the plan every url shares.
    const range_headers: ?[]std.http.Header = if (range_value) |value| headers: {
        const list = try ctx.gpa.alloc(std.http.Header, plan.options.headers.len + 1);
        @memcpy(list[0..plan.options.headers.len], plan.options.headers);
        list[plan.options.headers.len] = .{ .name = "Range", .value = value };
        break :headers list;
    } else null;
    defer if (range_headers) |list| ctx.gpa.free(list);

    var options = plan.options;
    // **The `-m` bound, handed to the transport that the cancel cannot
    // reach.** `boundedTransfer` races this transfer against a sleep and
    // cancels it when the sleep wins. That cancel lands on a blocked TCP
    // read, so HTTP/1.1 and HTTP/2 stop at once; it does not land on a
    // QUIC datagram wait. Measured before this line existed: `--http3
    // --max-time 0.05` fetched 1.3 MB in 0.89 seconds and exited 0, where
    // the same page over HTTP/2 exited 28 after 0.10 seconds. The HTTP/3
    // transport reads the flag at every wait instead. A run with no `-m`
    // has no `Deadline` and hands down null.
    options.stop = if (ctx.deadline) |bound| &bound.hit else null;
    if (range_headers) |list| options.headers = list;
    // **A protocol with no headers reads the offset itself.** An FTP
    // transfer asks for a resumed download with `REST` and carries no
    // header at all, so the `Range` line above says nothing to it. The
    // number goes in the options beside the header, and each protocol
    // reads the one it understands. See `zurl.Transfer.Options.resume_from`.
    options.resume_from = resume_offset;
    // `-r` travels the same way and for the same reason. FTP answers the
    // open ended form with `REST` and refuses the rest by name. See
    // `zurl_ftp.Fetcher.restFromRange`.
    options.range = plan.range;

    // **The one `-v` line before the transfer.** It names the url and the
    // method, which is what a user reads a verbose run for first, and it
    // is written before the connect so a run that hangs still says what it
    // was reaching for. The url goes through `safe.Text`, which masks a
    // userinfo password.
    try verboseNote(ctx, plan, "{s} {f}", .{
        @tagName(options.method),
        safe.Text{ .bytes = url, .max_len = zurl_core.Diagnostics.url_storage_len },
    });

    // Taken before the fault is reported, so a transfer that failed for
    // some other reason still tells the user which certificate directory
    // entries zurl passed over. `perform` is what loads the trust roots,
    // so nothing was skipped before this call.
    const performed = client.perform(url, options, &d);
    try noteCaSkips(ctx, plan, client);
    const response = performed catch |err| {
        // **The `--retry` decision for a failure, and the one rule that
        // keeps it safe.**
        //
        // A failure says the transfer did not finish. It does not say
        // whether the peer read the request and acted on it. So a failure
        // is sent again only when the engine reports that no peer answered
        // any byte of it: `zurl.Client.peerAnswered`, which is
        // `zurl_http.h1.Exchange.peer_answered` for the whole transfer,
        // every redirect hop included. Without that check a `POST` that
        // timed out while the server was already writing its answer would
        // go out a second time, and the server would act on it twice.
        //
        // `--fail` is the one failure that carries a status, and it takes
        // the status path below instead: the peer answered, and what it
        // answered is the whole question.
        // **The exit code is settled here, on every path, and a try that
        // asks for another still carries it.** `fetchOne` may stop the
        // tries between two of them, at `--retry-max-time`, and the run
        // then reports what the last try earned. A retried try that
        // returned zero would turn a failed run into a successful one.
        if (err == error.HttpReturnedError) {
            _ = retryStatus(ctx, plan, client, budget, d.status, attempt);
        } else if (retryAllowed(ctx, budget) and
            retryableFailure(plan.retry, err) and
            !client.peerAnswered())
        {
            attempt.* = .{ .again = true, .reason = reasonFor(err) };
        }
        // The fault reaches the user once for each try, whether or not
        // another follows. curl writes its own line for each try too,
        // measured: three `curl: (7)` lines for
        // `--retry 2 --retry-connrefused` against a closed port.
        return try failure(ctx, plan, display, err, &d);
    };

    // **The `--retry` decision for a status the peer answered.**
    //
    // Nothing has been written yet: the destination is not open, no head
    // block has gone out, and no body byte has been read. So a try that
    // asks for another leaves the file exactly as it was, and there is no
    // rewind to get wrong. curl rewinds instead, because it decides after
    // the body is on disk.
    if (retryStatus(ctx, plan, client, budget, response.status, attempt)) {
        // The code this try earned, so a run whose tries end here still
        // reports it. Without `--fail-with-body` a transient status is
        // exit 0, which is what curl gives for the same answer.
        if (plan.fail_with_body and response.status >= 400)
            return try statusFailure(ctx, plan, display, url, response.status, &d);
        return 0;
    }

    // The response is here, so the meter opens. Every path out of this
    // function then closes it, and `finish` is safe to call again, so a
    // `failure` that already closed it closes nothing twice.
    if (display) |m| m.start();
    defer if (display) |m| m.finish();

    // Read before anything can fail below, so a `-D` that cannot be
    // written still leaves `-w` the status and the url it already knows.
    values.http_code = response.status;
    values.url_effective = response.effective_url;
    values.content_type = response.header("Content-Type");
    values.http_version = response.http_version;

    // **A resumed transfer reads the range the peer says it sent, and it
    // stops when that is not the range that was asked for.**
    //
    // `-C` seeks to `resume_offset` and writes the body from there, so
    // those bytes must be the bytes at that position of that same entity.
    // The one thing on the wire that says which bytes they are is
    // `Content-Range`, RFC 9110 section 14.4. A peer that names a
    // different position, that names none, or that names one this build
    // cannot read has not answered the question. Writing its body at the
    // offset would leave a file that is neither the old content nor the
    // new one, and no later step can find that damage, so the transfer
    // stops here and the file keeps every byte it held.
    //
    // Measured against curl 8.21.0, a loopback server, and a local file of
    // five bytes, so `-C -` sends `Range: bytes=5-`:
    //
    // ```
    // 206, Content-Range: bytes 5-9/10    both      exit 0, file resumed
    // 206, no Content-Range               both      exit 33, file kept
    // 206, Content-Range: bytes 0-9/10    both      exit 33, file kept
    // 200, no Content-Range               both      exit 33, file kept
    // 204, 304, 404, 500                  both      exit 33, file kept
    // 206, Content-Range: bytes garbage   curl 0    curl appends 10 bytes
    // 206, Content-Range: items 5-9/10    curl 0    curl appends 10 bytes
    // 206, Content-Range: bytes */10      curl 0    curl appends 10 bytes
    // ```
    //
    // The last three lines are where this build is stricter than curl, and
    // it is on purpose. curl reads the first number after the header name
    // and never reads the unit, so a header that says nothing about bytes
    // five to nine still lets ten bytes land at byte five. This build
    // reads the whole grammar and refuses all three, with the same exit 33
    // and the same untouched file as the two shapes curl does catch.
    //
    // One more line of that table is a divergence in the other direction:
    // a `200` that carries a correct `Content-Range` resumes under curl
    // and is refused here. RFC 9110 gives `Content-Range` a meaning in a
    // `206` and a `416` alone, and a `200` says the body is the whole
    // representation, so the header cannot make it a part of one.
    //
    // `416` is the one status that is not a fault here. It has an arm of
    // its own below.
    //
    // **Only an HTTP transfer is asked this question.** `Content-Range` is
    // an HTTP header, and a protocol that speaks no HTTP resumes by
    // another means and has none to send: FTP asks with `REST`, and
    // `zurl_ftp.Fetcher` answers the offset or fails the transfer itself.
    // `Response.http_version` is null for every such protocol and is set
    // for every HTTP response, so it is the one field that tells the two
    // apart. The status alone cannot: a protocol with no HTTP status
    // reports `0`, which is neither `200` nor `416`.
    const http_answer = response.http_version != null;
    if (http_answer and resume_offset > 0 and response.status != 416) {
        const complaint: ?[]const u8 = complaint: {
            if (response.status == 200)
                break :complaint "-C: the server sent the whole body instead of the range that was asked for";
            const raw = response.header("Content-Range") orelse
                break :complaint "-C: the server sent no Content-Range, so which bytes it sent is unknown";
            const said = parseContentRange(raw) catch |err| break :complaint switch (err) {
                error.NotBytes => "-C: the server did not count the Content-Range in bytes",
                error.NoFirstPosition => "-C: the Content-Range names no first byte, so the range was refused",
                error.Malformed => "-C: the server sent a Content-Range this build cannot read",
            };
            if (said.first != resume_offset)
                break :complaint "-C: the server started the range at a byte other than the one asked for";
            break :complaint null;
        };
        if (complaint) |message| return try failure(
            ctx,
            plan,
            display,
            zurl_core.Diagnostics.record(&d, error.RangeError, .{
                .url = url,
                .message = message,
            }),
            &d,
        );
    }

    // **`416 Range Not Satisfiable`: the peer refused the range, so no
    // part of the entity came with it and nothing reaches the
    // destination.**
    //
    // This is the ordinary answer to a `-C -` on a file that is already
    // whole: the offset is the length of the entity, so there is no byte
    // left to send. It is not a fault, and curl exits 0 for it, measured.
    // What a `416` does carry is the server's own explanation of the
    // refusal, and writing that at the resume offset is the same damage as
    // any other wrong range, so the body is read to its end and thrown
    // away. `body_refused` carries that decision to the write below.
    //
    // curl 8.21.0 throws the body away too. With `-i` it still appends the
    // head to the file, measured: a file of five bytes became
    // `AAAAAHTTP/1.1 416 ...`. This build writes nothing at all, because a
    // resumed file that grew is the one thing this arm exists to stop.
    //
    // **`--fail` and `--fail-with-body` still see a `416` as a failure
    // here, and curl does not.** curl exempts this one status from `-f`
    // while a resume is running, and exits 0. `zurl.Client` answers `-f`
    // inside `perform`, before this line, so `-f` exits 22 and
    // `--fail-with-body` exits 22. Neither writes a body.
    const body_refused = http_answer and resume_offset > 0 and response.status == 416;

    // **`--fail-with-body`: the status is a failure and the body is still
    // written.** The code is settled here and returned at the end, after
    // every byte has landed where the user asked. `--fail` never reaches
    // this line, because `options.fail_on_error` already stopped the
    // transfer inside `perform`, and the two flags clear each other in
    // `Args`.
    const failed_status: ?u16 = if (plan.fail_with_body and response.status >= 400)
        response.status
    else
        null;

    // **The `-v` block for a transfer that reached a server.** It runs
    // before a byte of the body is read, so the head is on standard error
    // ahead of the body on standard output, the way curl orders them.
    if (plan.verbose) {
        if (response.headers) |block| try verboseResponseHead(ctx, plan, block);
        if (response.headers_oversize)
            try verboseNote(ctx, plan, "{s}", .{output.headers_oversize_message});
        if (response.effective_url.len > 0) try verboseNote(ctx, plan, "effective url: {f}", .{
            safe.Text{ .bytes = response.effective_url, .max_len = zurl_core.Diagnostics.url_storage_len },
        });
        // **The recovered faults, which nothing else prints.** A
        // `Diagnostics.message` is written beside a failure by
        // `report.writeTransferFailure`, and a transfer that succeeded
        // drops it. So a `TCP_NODELAY` that did not take, a connect
        // timeout this build could not enforce, a credential withheld
        // across a redirect, and a `401` challenge left unanswered were
        // all recorded and never shown. This is where they land.
        //
        // `d.url()` is not printed again beside it: the first `-v` line
        // already named the url, and `Diagnostics` masks the password in
        // whatever it holds anyway.
        if (d.message) |message| try verboseNote(ctx, plan, "{f}", .{
            safe.Text{ .bytes = message, .max_len = zurl_core.Diagnostics.message_storage_len },
        });
    }

    // **`-i`, `--show-headers`: the head of the last hop, where the body
    // goes.** Not the same flag as `-D`, which names a file of its own and
    // writes the head of every hop into it. curl writes the final head
    // alone here, so a redirect chain under `-i -L` shows the head of the
    // answer and not of each hop.
    //
    // A response that carries no head at all writes nothing here and fails
    // nothing. That is every transfer outside http, https, and rtsp in
    // this build: those packages set no `Response.headers`, so `-i` on an
    // `ftp://` url shows the body alone. curl prints an invented head for
    // some of them and zurl has none to invent. `--help` says so, and
    // `-D` and `-I` refuse by name below.
    //
    // **`rtsp` is the one non-HTTP package that fills the field.** RFC
    // 2326 gives a reply a status line and a header block, so there is a
    // real head to report and nothing has to be invented. curl prints one
    // for `rtsp` too, measured: `curl -s -i rtsp://host/stream` wrote
    // `RTSP/1.0 200 OK` and the headers under it.
    const shown_head: ?[]const u8 = if (plan.show_headers) response.final_headers else null;

    // The meter had no body to wrap when the clock started. It has one
    // now, and every read below goes through it.
    meter.source = response.body;
    const body = &meter.interface;

    // **`--etag-save` writes as soon as the head is in, before the body.**
    // curl writes it from its own header callback, so a transfer whose
    // body then failed still leaves the tag. Measured against curl 8.21.0:
    // a `404` answer carrying `ETag: "e404"` still wrote that tag.
    try saveEtag(ctx, plan, response);

    // The headers go first, the way curl writes them as they arrive and
    // long before the body ends. A `-D` that cannot be written stops this
    // url here: the user asked for the headers, and a body written beside
    // a missing header file would hide that.
    if (plan.output.headers_file) |target| {
        const block = response.headers orelse return try failure(
            ctx,
            plan,
            display,
            // No url in the message, because the sentence already names
            // the flag and `-o` names no url for its own write faults
            // either. Safety is not the reason any more:
            // `zurl_core.Diagnostics.record` masks a password in whatever
            // url it is given, so a url here would be safe. This is a
            // wording choice, not a rule.
            //
            // **Two causes and two names.** A head the engine dropped at a
            // bound of its own is a read fault this build made, and it
            // keeps `error.WriteError`. A protocol that reports no head at
            // all is `error.NotBuiltIn`, exit 4, because nothing went
            // wrong: this build has no head for that protocol. A user who
            // reads a write fault looks at the file system, and the file
            // system is not the cause.
            if (response.headers_oversize)
                zurl_core.Diagnostics.record(&d, error.WriteError, .{
                    .message = output.headers_oversize_message,
                })
            else
                zurl_core.Diagnostics.record(&d, error.NotBuiltIn, .{
                    .message = output.headers_missing_message,
                }),
            &d,
        );
        switch (target) {
            .file => |headers_path| output.headersToFile(ctx.io, headers_path, block, &d) catch |err|
                return try failure(ctx, plan, display, err, &d),
            // `-D -`: the same standard output the body may or may not
            // also be going to. Written straight through, with no bound
            // of its own beyond the one `response.headers_oversize`
            // already checked above.
            .stdout => ctx.stdout.writeAll(block) catch return try stdoutWriteFailure(
                ctx,
                plan,
                display,
                url,
                &d,
                "cannot write the headers to standard output",
            ),
        }
    }

    // **`-J`: the name the server chose, and the only point where a peer
    // may name a file zurl writes.**
    //
    // It runs here, after the head has arrived, because the header it
    // reads is part of that head. Nothing else moves: the name still goes
    // through `output.checkName`, the same one rule a `-O` name goes
    // through, and `--output-dir` still joins in front of whatever the
    // name turns out to be.
    //
    // A url this flag does not cover keeps the path already settled. That
    // is every url whose destination is not `-O`, which is what curl does:
    // measured, `-J -o named` wrote `named` and `-J` with no `-O` at all
    // wrote the body to standard output.
    const header_named: ?[]const u8 = if (!plan.remote_header_name)
        null
    else switch (plan.output.bodyTarget(index)) {
        .stdout, .file, .discard => null,
        .url_name => named: {
            const raw = response.header("content-disposition") orelse break :named null;
            const found = output.nameFromDisposition(raw) catch |err| return try failure(
                ctx,
                plan,
                display,
                zurl_core.Diagnostics.record(&d, output.faultFor(err), .{
                    .message = output.explainHeaderName(err),
                }),
                &d,
            );
            break :named switch (found) {
                .write => |name| try joinOutputDir(ctx, plan, name),
                // The header named nothing zurl can use, so `-O`'s own
                // name from the url stands. curl does the same for a
                // response that carries no usable disposition at all,
                // measured. Recovery is never silent, so the user hears
                // which name the file got.
                .none => none: {
                    try noteHeaderNameUnused(ctx, plan);
                    break :none null;
                },
            };
        },
    };

    // **The `416` arm: read the body to its end and write none of it.**
    //
    // It stands in front of every destination, the file, standard output,
    // and `--out-null` alike, because the reason is the body and not where
    // the body was going. The read runs to the end so the status, the
    // timings, and the byte count `-w` prints are all real, and so the
    // connection is not left half read for the next url in the pool. See
    // the `416` note above the `Content-Range` check.
    if (body_refused) {
        var sink: std.Io.Writer.Discarding = .init(&.{});
        _ = body.streamRemaining(&sink.writer) catch |err| switch (err) {
            // A `Discarding` writer never fails, so a read is the only
            // thing here that can have failed.
            error.ReadFailed => return try failure(ctx, plan, display, client.resolveBodyError(&d), &d),
            error.WriteFailed => return try stdoutWriteFailure(
                ctx,
                plan,
                display,
                url,
                &d,
                "cannot throw the body away",
            ),
        };
        try noteRangeRefused(ctx, plan, resume_offset);
        // No body landed anywhere, so no trailer belongs anywhere either.
        return try statusFailure(ctx, plan, display, url, failed_status, &d);
    }

    if (header_named orelse path) |destination| {
        const file_options: output.FileOptions = .{
            .create_dirs = plan.create_dirs,
            .no_clobber = plan.no_clobber,
            .offset = resume_offset,
            .mode = plan.create_file_mode,
            .modified_at = if (plan.remote_time) remoteTime(response) else null,
            .remove_on_error = plan.remove_on_error,
            // **A `-J` name never overwrites, and a `-O` name always
            // may.** The difference is who chose the name. `Args` refuses
            // `-J` beside `-C`, so this can never turn a resume into a
            // refusal. See `output.FileOptions.refuse_existing`.
            .refuse_existing = header_named != null,
            .prefix = shown_head orelse "",
            // **A name the url or a header chose never writes through a
            // symbolic link, and a name the user typed still does.** See
            // `output.FileOptions.refuse_symlink` for the measurement
            // against curl and for why the two flags differ. `-J` sets
            // this too: `header_named` is filled only on a `.url_name`
            // target, so the arm below covers both.
            .refuse_symlink = switch (plan.output.bodyTarget(index)) {
                .url_name => true,
                .stdout, .file, .discard => false,
            },
        };
        output.toFile(ctx.io, destination, body, file_options, &d) catch |err| switch (err) {
            // The peer, not the file. `Response.body` reports only that a
            // read failed, so ask the client which fault it was.
            error.ReadFailed => return try failure(ctx, plan, display, client.resolveBodyError(&d), &d),
            // The file, not the peer. `toFile` has already recorded the
            // operating system's own name for the cause.
            error.WriteError => return try failure(ctx, plan, display, error.WriteError, &d),
        };
        // The body has landed, so a trailer section behind it can be
        // written. It never goes where this body went: `-i` is the only
        // flag that puts a head beside a body, and it names standard
        // output and not a file.
        writeTrailers(ctx, plan, client, false) catch
            return try failure(ctx, plan, display, error.WriteError, &d);
        return try statusFailure(ctx, plan, display, url, failed_status, &d);
    }

    // **`--out-null`: read the whole body and write it nowhere.** The
    // transfer runs to its end, so the status, the timings, and the byte
    // count are all real and `-w` prints them. A run that stopped reading
    // instead would leave the connection half read and would report a size
    // the peer never finished sending.
    //
    // `-i` writes no head here either. The flag says the head goes where
    // the body goes, and the body goes nowhere. curl 8.21.0 does the same,
    // measured: `-i --out-null` wrote nothing at all.
    if (plan.output.bodyTarget(index) == .discard) {
        var sink: std.Io.Writer.Discarding = .init(&.{});
        _ = body.streamRemaining(&sink.writer) catch |err| switch (err) {
            // The peer, not the sink. A `Discarding` writer never fails,
            // so only a read can have failed here.
            error.ReadFailed => return try failure(ctx, plan, display, client.resolveBodyError(&d), &d),
            error.WriteFailed => return try stdoutWriteFailure(
                ctx,
                plan,
                display,
                url,
                &d,
                "cannot throw the body away",
            ),
        };
        // `-i` wrote no head here, so it writes no trailer either. `-D`
        // named a destination of its own and still gets both.
        writeTrailers(ctx, plan, client, false) catch
            return try failure(ctx, plan, display, error.WriteError, &d);
        return try statusFailure(ctx, plan, display, url, failed_status, &d);
    }

    // `-i` onto standard output: the head, then the body, in that order
    // and through the same writer, so nothing can come between them.
    if (shown_head) |block| ctx.stdout.writeAll(block) catch return try stdoutWriteFailure(
        ctx,
        plan,
        display,
        url,
        &d,
        "cannot write the headers to standard output",
    );

    _ = body.streamRemaining(ctx.stdout) catch |err| switch (err) {
        // The peer, not stdout. `Response.body` reports only that a read
        // failed, so ask the client which fault it was.
        error.ReadFailed => return try failure(ctx, plan, display, client.resolveBodyError(&d), &d),
        // stdout, not the peer. curl calls this `CURLE_WRITE_ERROR`.
        error.WriteFailed => return try stdoutWriteFailure(
            ctx,
            plan,
            display,
            url,
            &d,
            "cannot write the body to standard output",
        ),
    };

    // **The trailer section goes out before the flush, not after it.** It
    // follows the body through the same writer, so nothing can come
    // between them, which is the reason `-i` writes its head through this
    // writer too. `shown_head` being set is what says `-i` asked for the
    // head here, so it is what says the trailer belongs here as well.
    writeTrailers(ctx, plan, client, shown_head != null) catch
        return try stdoutWriteFailure(
            ctx,
            plan,
            display,
            url,
            &d,
            "cannot write the trailers to standard output",
        );

    // Flushed here, not once at the end, so one url's body reaches
    // standard output before the next url's fault reaches standard error.
    ctx.stdout.flush() catch
        return try stdoutWriteFailure(
            ctx,
            plan,
            display,
            url,
            &d,
            "cannot write the body to standard output",
        );

    return try statusFailure(ctx, plan, display, url, failed_status, &d);
}

/// Decides whether a status the peer answered earns another try, and
/// records the decision in `attempt`.
///
/// **This is the one place a request the peer answered may go out again,
/// and each status in the set is the peer's own word that it did not serve
/// the request.** `408` and `504` are timeouts of the peer's own, `429`
/// says it took nothing, and `500`, `502`, and `503` say it had nothing to
/// give. curl retries exactly these six and no other, measured, and it
/// retries them for every method, `POST` included.
///
/// `--retry-all-errors` adds nothing here on its own. Measured against
/// curl 8.21.0: `--retry-all-errors` alone on a `404` sent one request,
/// and `--retry-all-errors --fail` on the same `404` sent three, because
/// `--fail` turns the status into a failure and that flag reads failures.
/// So the `--fail` path passes `d.status` in and gets both readings from
/// this one function.
fn retryStatus(
    ctx: Context,
    plan: Args.Plan,
    client: *zurl.Client,
    budget: ?RetryBudget,
    status: ?u16,
    attempt: *Attempt,
) bool {
    const answered = status orelse return false;
    if (!retryAllowed(ctx, budget)) return false;
    // `--fail` makes the status a failure, and `--retry-all-errors` then
    // covers it. With no `--fail` the transfer succeeded, so there is no
    // failure for that flag to read and only the six statuses count.
    const covered = retryableStatus(answered) or
        (plan.retry.all_errors and plan.options.fail_on_error and answered >= 400);
    if (!covered) return false;

    attempt.* = .{
        .again = true,
        .reason = .http_status,
        .retry_after_s = retryAfterSeconds(client.finalHeader("Retry-After")),
    };
    return true;
}

/// Whether the caller's own headers already carry a `Range`.
///
/// `-C` and `-r` each build one, and a header the user wrote outranks
/// both. Matched without regard to case, because a field name has none.
fn userWroteRange(headers: []const std.http.Header) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Range")) return true;
    }
    return false;
}

/// How long a `Range` header value `-C` can build.
///
/// `bytes=` is six bytes, a `u64` is at most twenty digits, and the
/// trailing `-` is one. Thirty-two is that with room to spare, and it
/// bounds the buffer so no offset a user types can grow it.
const range_value_max = 32;

/// The longest `Content-Range` value this build reads.
///
/// The longest legal value is `bytes ` in front of three `u64` decimals
/// with a `-` and a `/` between them, which is sixty nine bytes. A hundred
/// and twenty eight is that with room to spare. A value longer than this
/// is a value no peer has a reason to send, so it is refused with the rest
/// of the shapes that do not parse, and no work is done on it.
const content_range_max = 128;

/// What one `Content-Range` header says, after it is read.
const ContentRange = struct {
    /// Where the first byte the peer sent sits in the whole entity.
    first: u64,
    /// Where the last byte the peer sent sits. Never below `first`.
    last: u64,
    /// How long the whole entity is, or null for the `*` spelling, which
    /// says the peer does not know the length.
    complete: ?u64,
};

/// Reads a `Content-Range` header value.
///
/// RFC 9110 section 14.4 gives the grammar:
///
/// ```
/// Content-Range     = range-unit SP ( range-resp / unsatisfied-range )
/// range-resp        = incl-range "/" ( complete-length / "*" )
/// incl-range        = first-pos "-" last-pos
/// unsatisfied-range = "*/" complete-length
/// ```
///
/// **Every part is read, and not the first number alone.** The caller
/// writes a body at a byte offset on the strength of this answer, so a
/// header that describes something other than bytes, or a range that
/// describes no bytes at all, must not come back as a position. curl reads
/// the first digit it finds after the header name and stops, which lets
/// `items 5-9/10` and `bytes garbage` through. Measured, both then corrupt
/// the resumed file. See the table at the `Content-Range` check in
/// `runTransfer`.
///
/// **The unit may end at a space, an `=`, or a `:`.** One space is what
/// the grammar gives. The other two are what old servers send, which is
/// why curl takes them, and taking them changes nothing about safety: the
/// unit must still read `bytes` and the first position must still match
/// the offset that was asked for. A value with no unit at all, such as
/// `5-9/10`, ends nowhere a unit can end, so it comes back as
/// `error.Malformed` and never as a position. curl takes that one too.
///
/// Returns `error.NotBytes` when the unit is something else,
/// `error.NoFirstPosition` for the `*/<length>` shape a `416` sends, and
/// `error.Malformed` for anything that does not parse.
fn parseContentRange(value: []const u8) error{ NotBytes, NoFirstPosition, Malformed }!ContentRange {
    if (value.len == 0 or value.len > content_range_max) return error.Malformed;

    const unit_end = std.mem.indexOfAny(u8, value, " =:") orelse return error.Malformed;
    if (!std.ascii.eqlIgnoreCase(value[0..unit_end], "bytes")) return error.NotBytes;

    // The separator itself and any space behind it. More than one space is
    // a peer being loose with a header, and the numbers behind it still
    // have one meaning, so the spaces are stepped over and nothing else
    // is.
    var rest = value[unit_end + 1 ..];
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];

    // `*/<length>` names no first byte, so a resumed transfer learns
    // nothing from it.
    if (std.mem.startsWith(u8, rest, "*/")) return error.NoFirstPosition;

    const dash = std.mem.indexOfScalar(u8, rest, '-') orelse return error.Malformed;
    const slash = std.mem.indexOfScalarPos(u8, rest, dash + 1, '/') orelse return error.Malformed;

    const first = contentRangeNumber(rest[0..dash]) orelse return error.Malformed;
    const last = contentRangeNumber(rest[dash + 1 .. slash]) orelse return error.Malformed;
    const tail = rest[slash + 1 ..];
    const complete: ?u64 = complete: {
        if (std.mem.eql(u8, tail, "*")) break :complete null;
        break :complete contentRangeNumber(tail) orelse return error.Malformed;
    };

    // A range that ends before it starts, or that reaches past the entity
    // it says it came from, describes no bytes at all.
    if (last < first) return error.Malformed;
    if (complete) |length| {
        if (length == 0 or last >= length) return error.Malformed;
    }
    return .{ .first = first, .last = last, .complete = complete };
}

/// One decimal number out of a `Content-Range`, or null when `text` is
/// empty, when it carries a byte that is not a digit, or when it names a
/// number above what a `u64` holds.
///
/// `std.fmt.parseInt` on its own takes a leading `+` and a `_` between
/// digits. The grammar has neither, so the digits are checked first and
/// `parseInt` is left with the size bound alone.
fn contentRangeNumber(text: []const u8) ?u64 {
    if (text.len == 0) return null;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
    }
    return std.fmt.parseInt(u64, text, 10) catch null;
}

/// Where `-C` resumes this url from, in bytes. Zero means the whole body,
/// which is what no flag at all asks for.
///
/// Measured against curl 8.21.0 with a loopback server that answers a
/// `Range` request with `206`:
///
/// ```
/// -C -  and a file holding 5 bytes   Range: bytes=5-
/// -C -  and no such file             no Range header
/// -C -  and -o -                     no Range header
/// -C 5  whatever the file holds      Range: bytes=5-
/// ```
///
/// `-C -` on a destination that is not a file measures nothing, so it
/// resumes from zero. A body on standard output has no length to read
/// back, and curl sends no `Range` for it either, measured.
///
/// A file that cannot be measured is the same answer as a file that is not
/// there: resume from zero and fetch the whole body. That is not silent
/// recovery, because there is no fault to report. curl reads the size the
/// same way and asks for the whole body when it gets none.
fn resumeOffset(ctx: Context, plan: Args.Plan, path: ?[]const u8) !u64 {
    const wanted = plan.resume_at orelse return 0;
    return switch (wanted) {
        .offset => |named| named,
        .file_size => size: {
            const destination = path orelse break :size 0;
            const info = Io.Dir.cwd().statFile(ctx.io, destination, .{}) catch break :size 0;
            break :size info.size;
        },
    };
}

/// Whether `path` already names something on disk. This is
/// `--skip-existing`.
///
/// **A path that cannot be measured reads as not there, and the transfer
/// runs.** That is the safe direction: a run that skipped on an unreadable
/// `stat` would write nothing and exit 0, and the user would believe they
/// had the file. A run that fetches finds the real fault when it opens the
/// destination to write it, where every other write fault is found.
///
/// Any kind of entry counts, and not a regular file alone. A directory or
/// a symbolic link at that path is a destination `output.toFile` cannot
/// write either, so a transfer that ran would fail on it.
fn alreadyThere(ctx: Context, path: []const u8) !bool {
    _ = Io.Dir.cwd().statFile(ctx.io, path, .{}) catch return false;
    return true;
}

/// Writes one line to stderr naming the url that `--skip-existing` left
/// alone, unless `plan` asked for silence.
///
/// **A skipped url writes nothing and exits 0**, so without this line a
/// user reads an empty run as a run that fetched. IronStyle asks that
/// recovery never stay silent, and this is the recovery. curl prints
/// nothing here, so the line goes to standard error and never to standard
/// output, where it would join what `-w` writes.
fn noteSkippedExisting(ctx: Context, plan: Args.Plan, path: []const u8) !void {
    if (!plan.silent or plan.show_error) {
        lockReports(ctx);
        defer unlockReports(ctx);

        try ctx.stderr.print(
            "zurl: --skip-existing: '{f}' is already there, so this url was not fetched\n",
            .{safe.text(path)},
        );
        try ctx.stderr.flush();
    }
}

/// Reports a status `--fail-with-body` treats as a failure, after the body
/// has already been written, and returns the exit code for this url.
///
/// Returns 0 when the status was not one to fail on, which is every
/// transfer that did not name `--fail-with-body`.
///
/// **The body is already on disk or on standard output when this runs.**
/// That is the whole difference from `--fail`, which stops the transfer
/// inside `perform` and writes nothing. Measured against curl 8.21.0 with
/// a loopback server answering `404` with a body: `--fail-with-body -o f`
/// exits 22 and leaves the body in `f`, and `--fail -o f` exits 22 and
/// creates no file.
fn statusFailure(
    ctx: Context,
    plan: Args.Plan,
    display: ?*progress.Meter,
    url: []const u8,
    failed_status: ?u16,
    d: *zurl_core.Diagnostics,
) !u8 {
    const status = failed_status orelse return 0;
    return try failure(ctx, plan, display, zurl_core.Diagnostics.record(d, error.HttpReturnedError, .{
        .url = url,
        .status = status,
    }), d);
}

/// Reports a standard output that would not take this url's body, and
/// returns curl's own exit code for it.
///
/// The url goes into the `Diagnostics` as the raw text the user typed.
/// `zurl_core.Diagnostics.record` is the only writer of that field and it
/// masks the userinfo password itself, so this path cannot put a password
/// on standard error whether or not its author thought about one.
///
/// The bytes standard output would not take are dropped here. They are
/// gone either way: the stream refused them. Dropping them keeps `main`'s
/// own last flush from meeting the same fault and reporting it a second
/// time, which under `-s` would break the silence this call already
/// honoured.
///
/// `message` names what standard output would not take: the body, or,
/// with `-D -`, the response head block. One function serves both,
/// because the recovery is the same either way, and only the sentence
/// differs.
fn stdoutWriteFailure(
    ctx: Context,
    plan: Args.Plan,
    display: ?*progress.Meter,
    url: []const u8,
    d: *zurl_core.Diagnostics,
    message: []const u8,
) !u8 {
    dropUnwritten(ctx.stdout);
    return failure(ctx, plan, display, zurl_core.Diagnostics.record(d, error.WriteError, .{
        .url = url,
        .message = message,
    }), d);
}

/// Reports `err` on stderr, unless `plan` asked for silence, and returns
/// the exit code for it.
///
/// `-s` hides the message and `-S` brings it back, which is curl's rule.
/// Neither changes the exit code: a silent run still tells the shell what
/// happened.
///
/// `display` closes first, so the meter's last row ends with a newline and
/// the message starts on a line of its own. A meter that never opened
/// writes nothing here, so a transfer that reached no server still prints
/// the message alone, the way curl does.
fn failure(
    ctx: Context,
    plan: Args.Plan,
    display: ?*progress.Meter,
    err: zurl_core.Error,
    d: *const zurl_core.Diagnostics,
) !u8 {
    if (display) |m| m.finish();

    // **A transfer the `-m` bound stopped reports that bound, and nothing
    // else.** The cancel that ended it landed on whichever call was
    // waiting, so `err` names a symptom: a read that failed, or a write
    // that could not flush. `boundedTransfer` prints the one message the
    // user needs, once, after the race has ended, so this path writes
    // nothing at all. Writing here as well would print two sentences for
    // one fault, and the first of them would name the wrong cause.
    if (ctx.deadline) |bound| {
        if (bound.reached()) return exitCodeFor(error.OperationTimedOut);
    }

    if (!plan.silent or plan.show_error) {
        // Held across the write and the flush, so a `-Z` run never leaves
        // one url's message cut in half by another url's.
        lockReports(ctx);
        defer unlockReports(ctx);

        try report.writeTransferFailure(ctx.stderr, err, d);
        try ctx.stderr.flush();
    }
    return exitCodeFor(err);
}

/// Writes one line to stderr naming the certificate directory entries the
/// trust root load passed over, unless `plan` asked for silence.
///
/// `--capath` and `SSL_CERT_DIR` name a directory the machine owns, so a
/// stale, unreadable, or truncated entry there is ordinary.
/// `zurl_tls.loader.loadDir` skips such an entry and keeps every root the
/// other entries hold, which is what makes zurl usable on a real machine.
/// IronStyle says recovery is never silent, so this is where the skip
/// reaches the user.
///
/// This is not a failure: the transfer runs and the exit code is whatever
/// it earns. So it follows the same `-s` and `-S` rule the other notes
/// follow.
///
/// `Client.takeCaSkips` hands the record out once for the life of a
/// `Client`, so a run of many urls prints this line one time, not once for
/// each url.
fn noteCaSkips(ctx: Context, plan: Args.Plan, client: *zurl.Client) !void {
    const skipped = client.takeCaSkips() orelse return;
    if (plan.silent and !plan.show_error) return;

    lockReports(ctx);
    defer unlockReports(ctx);

    try ctx.stderr.print(
        "zurl: certificate directory: skipped {s}\n",
        .{skipped},
    );
    try ctx.stderr.flush();
}

/// Writes one line to stderr saying `-O` found no usable name and wrote
/// `output.fallback_name` instead, unless `plan` asked for silence.
///
/// This is not a failure: the transfer still runs and still exits 0, so
/// `-s` and `-S` follow the same rule they follow for a failure message,
/// the one place zurl already asks whether the user wants quiet.
fn noteFallbackName(ctx: Context, plan: Args.Plan) !void {
    if (!plan.silent or plan.show_error) {
        lockReports(ctx);
        defer unlockReports(ctx);

        try ctx.stderr.print(
            "zurl: -O found no usable name in the url, writing {s}\n",
            .{output.fallback_name},
        );
        try ctx.stderr.flush();
    }
}

/// Waits until `wait_ms` has passed since the transfer at `last_start`
/// began, then records this moment as the new start. This is `--rate`.
///
/// **The flag paces the *starts*, not the gaps between transfers.** curl's
/// own manual says the rate counts requests in a unit of time, so a
/// transfer that itself took longer than the wait leaves no wait at all
/// for the next one. `durationTo` is signed, so that case reads as a
/// negative remainder and skips the sleep.
///
/// **`--rate` reaches a serial run alone**, which is what curl documents
/// and what the flag's own help line says: `-Z` has its own pacing in the
/// number of workers, and a rate applied on top of it would be two answers
/// to one question. `runParallel` never calls this.
///
/// A cancel during the wait belongs to the caller. `-m` bounds one
/// transfer and not the gap in front of it, so nothing here can be
/// cancelled by that bound; a cancel from anywhere else ends the run, and
/// the error travels up rather than being swallowed into a shorter wait.
fn waitForRate(ctx: Context, wait_ms: u64, last_start: *?Io.Timestamp) !void {
    const now = Io.Timestamp.now(ctx.io, .awake);
    defer last_start.* = Io.Timestamp.now(ctx.io, .awake);

    const previous = last_start.* orelse return;
    const elapsed_ns = previous.durationTo(now).nanoseconds;
    const wanted_ns: i96 = @as(i96, wait_ms) * std.time.ns_per_ms;
    if (elapsed_ns >= wanted_ns) return;

    try Io.sleep(ctx.io, .{ .nanoseconds = wanted_ns - elapsed_ns }, .awake);
}

/// Writes the response's own `ETag` where `--etag-save` asked for it.
///
/// **Measured against curl 8.21.0, byte for byte.** The file holds the
/// header value exactly as the server wrote it, quotes and all, and one
/// newline after it:
///
/// ```
/// ETag: "abc123"    the file holds `"abc123"\n`, nine bytes
/// ETag: W/"weak1"   the file holds `W/"weak1"\n`: the weak mark stays
/// no ETag at all    the file is created and left empty
/// ```
///
/// So `--etag-save` and `--etag-compare` round trip: what one writes is
/// what the other sends, and neither adds or removes a quote.
///
/// **A file that cannot be written costs no exit code.** curl exits 0
/// there, and a body already on disk is worth more than the tag beside it.
/// The loss still reaches standard error, under the same `-s` and `-S`
/// rule every other note follows, because recovery is never silent.
///
/// A run over several urls leaves the tag of the last url that carried
/// one, which is what one file for a whole run can hold.
/// Writes the trailer section behind the body, the way curl writes it.
///
/// **A trailer section is written after the body and nowhere else.** RFC
/// 9110 section 6.5 is for a field whose value the sender does not know
/// until the body has gone, so the field lines can only reach a reader
/// after the body they follow. Measured against curl 8.21.0 over HTTP/2,
/// with a server that sent `grpc-status: 0` and `x-end: yes` behind a
/// six-octet body:
///
/// - `-D file` left `HTTP/2 200 \r\n`, the head fields, the empty line
///   that closes the head, and then the two trailer lines. No second empty
///   line, and no second status line.
/// - `-i` wrote the head, the empty line, the body, and then the same two
///   lines, all to standard output.
/// - `%header{grpc-status}` answered empty, `%{size_header}` counted the
///   head block alone, and `%{header_json}` left the trailer out. So a
///   trailer reaches the two dumps and reaches nothing else, which is what
///   `zurl.Client.responseTrailers` promises.
///
/// `to_stdout` says whether the body went to standard output under `-i`,
/// which is the one case where the trailer follows it there. A body thrown
/// away by `--out-null` writes no head under `-i` and writes no trailer
/// either.
///
/// A peer that sent no trailer writes nothing, which is every ordinary
/// response and every HTTP/1.1 hop.
fn writeTrailers(
    ctx: Context,
    plan: Args.Plan,
    client: *zurl.Client,
    to_stdout: bool,
) error{ WriteError, WriteFailed }!void {
    const block = client.responseTrailers() orelse return;

    if (plan.output.headers_file) |target| switch (target) {
        .file => |headers_path| {
            var d: zurl_core.Diagnostics = .{};
            try output.headersToFile(ctx.io, headers_path, block, &d);
        },
        // `-D -`: appended straight after whatever already went out, which
        // is the head and, when the body also goes here, the body.
        .stdout => ctx.stdout.writeAll(block) catch return error.WriteFailed,
    };

    if (to_stdout) ctx.stdout.writeAll(block) catch return error.WriteFailed;
}

fn saveEtag(ctx: Context, plan: Args.Plan, response: zurl.Response) !void {
    const path = plan.etag_save orelse return;
    // The header value with no surrounding space. Empty when the response
    // carried none, which still creates the file: curl leaves an empty
    // file there, measured, and a stale tag from an earlier run would be
    // worse than none.
    const raw = response.header("etag") orelse "";
    const tag = std.mem.trim(u8, raw, " \t");

    var d: zurl_core.Diagnostics = .{};
    output.etagToFile(ctx.io, path, tag, &d) catch {
        if (!plan.silent or plan.show_error) {
            lockReports(ctx);
            defer unlockReports(ctx);

            try ctx.stderr.print(
                "zurl: --etag-save: cannot write '{f}'\n",
                .{safe.text(path)},
            );
            try ctx.stderr.flush();
        }
    };
}

/// Writes one line to stderr saying `-J` found no name it could use in the
/// response, unless `plan` asked for silence.
///
/// A `Content-Disposition` that names nothing, or that names `.`, `..`, or
/// a path with an empty last segment, leaves `-O`'s own name from the url
/// in place. curl does the same for a response with no disposition at all,
/// measured. That is recovery, so it is never silent.
fn noteHeaderNameUnused(ctx: Context, plan: Args.Plan) !void {
    if (!plan.silent or plan.show_error) {
        lockReports(ctx);
        defer unlockReports(ctx);

        try ctx.stderr.writeAll(
            "zurl: -J found no usable name in the response, keeping the name -O took from the url\n",
        );
        try ctx.stderr.flush();
    }
}

/// Writes one line to stderr saying the peer refused the range `-C` asked
/// for, unless `plan` asked for silence.
///
/// A `416` under a resume writes nothing and exits 0, so without this line
/// a user reads an empty run as a run that finished the file. It is the
/// usual answer for a file that is already whole, and it is also what a
/// peer sends when the local file is longer than the entity, which is a
/// file the user should look at. IronStyle asks that recovery never stay
/// silent, and this is the recovery. curl prints nothing here, so the line
/// goes to standard error and never to standard output, where it would
/// join what `-w` writes.
fn noteRangeRefused(ctx: Context, plan: Args.Plan, offset: u64) !void {
    if (!plan.silent or plan.show_error) {
        lockReports(ctx);
        defer unlockReports(ctx);

        try ctx.stderr.print(
            "zurl: -C: the server has no bytes past {d}, so nothing was written\n",
            .{offset},
        );
        try ctx.stderr.flush();
    }
}

/// Puts `--output-dir` in front of a file name, and returns the path to
/// write.
///
/// **`--output-dir` moves the file and never the name.** It joins in front
/// of whatever `-o`, `-O`, or `-J` settled on, which is where curl puts it
/// too, so the name itself is untouched and only the directory in front of
/// it changes. Measured against curl 8.21.0: `--output-dir sub -O` wrote
/// `sub/<the url's last segment>`, and `--output-dir sub -OJ` wrote
/// `sub/<the header's name>`.
///
/// **The directory is the user's own and the name is not.** A
/// `--output-dir ../elsewhere` reaches outside the working directory, and
/// so it should: the user typed it. Measured, curl writes there too. The
/// name joined onto it is the part that may come from a url or from a
/// server, and `output.checkName` has already refused every separator such
/// a name could carry, so the joined path can reach no directory but the
/// one the flag named.
///
/// An empty `--output-dir` changes nothing, and no flag at all changes
/// nothing. The joined text lives in the arena, which outlives every
/// transfer.
///
/// This creates no directory. `--create-dirs` does that, which is what
/// curl asks for too: measured, `--output-dir sub -O` with no `sub` exits
/// 23 and writes nothing.
fn joinOutputDir(ctx: Context, plan: Args.Plan, name: []const u8) ![]const u8 {
    const dir = plan.output_dir orelse return name;
    if (dir.len == 0) return name;
    return std.fs.path.join(ctx.arena, &.{ dir, name });
}

/// The time `-R`, `--remote-time` gives the output file: the
/// `Last-Modified` the server sent, in seconds since the epoch, or null
/// when the response carried none that reads.
///
/// `zurl_core.cookie.parseDate` is the reader. RFC 9110 gives
/// `Last-Modified` the same IMF-fixdate that a cookie `Expires` uses, and
/// that function already reads all three of the formats a client must
/// accept, with the measurements behind it. One date parser, and no second
/// one to drift from it.
///
/// A header that does not read leaves the file with the time of the write.
/// That is what curl does with an unreadable date, and it is the safe
/// direction: a wrong time on a file is worse than the time it already
/// had.
fn remoteTime(response: zurl.Response) ?i64 {
    const value = response.header("last-modified") orelse return null;
    return zurl_core.cookie.parseDate(std.mem.trim(u8, value, " \t"));
}

/// What every `-v` line starts with for a note zurl wrote itself. curl
/// uses the same marker, so a person who reads one reads the other.
const verbose_note_prefix = "* ";

/// What every `-v` line starts with for a header the server sent. curl
/// uses the same marker.
const verbose_response_prefix = "< ";

/// How much of one response header line `-v` shows.
///
/// A header line is bounded by the engine long before it reaches here, and
/// this is the bound on what one *message* shows, which is a different
/// question: a message is one line on a terminal. `src/cli/safe.zig` cuts
/// what is longer and marks the cut.
const verbose_header_max: usize = 1024;

/// Writes one `-v` note.
///
/// **`-s` does not silence this, and that is curl's own rule.** Measured
/// against curl 8.21.0: `curl -v -s` still writes the whole verbose block.
/// `-s` turns off the progress meter and the message a failed transfer
/// earns; `-v` is a user asking to be told, and the later flag of the two
/// does not cancel it.
///
/// **Every string a caller passes must already be a `safe.Text`.** This
/// writes what it is given. `safe.Text` is the one printer that masks a
/// userinfo password and drops a control byte, and a `{s}` here would be
/// the hole this whole file routes around. See `src/cli/safe.zig`.
fn verboseNote(ctx: Context, plan: Args.Plan, comptime fmt: []const u8, args: anytype) !void {
    if (!plan.verbose) return;

    lockReports(ctx);
    defer unlockReports(ctx);

    try ctx.stderr.writeAll(verbose_note_prefix);
    try ctx.stderr.print(fmt, args);
    try ctx.stderr.writeAll("\n");
    try ctx.stderr.flush();
}

/// Writes the response head under `-v`, one line for each header, each
/// marked with `verbose_response_prefix`.
///
/// **The request head is not written, and this is the rule that keeps a
/// credential out of `-v`.** An `Authorization` line, whether zurl built
/// it from `-u` or the user wrote it with `-H`, lives only in a request
/// head. Nothing here can reach one: `zurl.Response` carries the heads the
/// server sent and no request bytes at all, so there is no path from a
/// credential to this output that a later change could open by accident.
/// `--help` says the same thing to the user.
///
/// A `Set-Cookie` the server sent does print, which is what curl prints
/// too. That is the server's own text and not the user's secret.
///
/// `block` is the head as it arrived, with CRLF line endings. Each line
/// goes through `safe.Text`, so a control byte a server wrote cannot move
/// a terminal's cursor and a line longer than `verbose_header_max` is cut
/// and marked.
fn verboseResponseHead(ctx: Context, plan: Args.Plan, block: []const u8) !void {
    if (!plan.verbose) return;

    lockReports(ctx);
    defer unlockReports(ctx);

    // A head ends with its own empty line, so the block ends with a line
    // feed and a split on that byte hands back one empty piece past the
    // end. Dropping it here is what keeps the marked empty line to exactly
    // one, which is what curl writes.
    const body_of_head = std.mem.trimEnd(u8, block, "\n");
    var lines = std.mem.splitScalar(u8, body_of_head, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        // The empty line that ends a head prints as a bare marker, which
        // is what curl writes, so a reader can see where one head stopped
        // and the next hop began.
        try ctx.stderr.writeAll(verbose_response_prefix);
        try ctx.stderr.print("{f}\n", .{safe.Text{ .bytes = line, .max_len = verbose_header_max }});
    }
    try ctx.stderr.flush();
}

/// Returns the exit code for `err`, which is curl's own `CURLE_*` number.
pub fn exitCodeFor(err: zurl_core.Error) u8 {
    const code = zurl_core.errors.curlCode(err);
    // Every row in `zurl_core.errors` holds a code below 256, and an exit
    // status carries 8 bits. A wider code would be a defect in that table,
    // which is a programmer error and not a runtime fault.
    std.debug.assert(code <= std.math.maxInt(u8));
    return @intCast(code);
}

const testing = std.testing;

/// Builds the `Plan` a `-Z` decision reads, and nothing else.
///
/// `parallelBlocker` and `repeatedDestination` read three fields: the
/// urls, `output.body`, and `output.headers_file`. Every other field of a
/// `Plan` keeps its default here, so a test names only what it measures.
fn schedulePlan(
    urls: []const []const u8,
    body: []const Args.BodyTarget,
    headers_file: ?[]const u8,
) Args.Plan {
    return .{
        .urls = urls,
        .options = .{},
        .output = .{
            .body = body,
            .headers_file = if (headers_file) |path| .{ .file = path } else null,
        },
        .parallel = true,
    };
}

test "-Z overlaps two urls that each write a file of their own" {
    const plan = schedulePlan(
        &.{ "http://x/one", "http://x/two" },
        &.{ .{ .file = "a" }, .{ .file = "b" } },
        null,
    );
    try testing.expectEqual(@as(?[]const u8, null), try parallelBlocker(testing.allocator, plan));
}

test "a body on standard output stops -Z from overlapping" {
    // No `-o` covers either url, so both bodies go to the one stream.
    const plan = schedulePlan(&.{ "http://x/one", "http://x/two" }, &.{}, null);
    try testing.expectEqualStrings(
        "zurl: -Z: a body goes to standard output, which is one stream, so the transfers run one at a time",
        (try parallelBlocker(testing.allocator, plan)).?,
    );
}

test "one url past the last -o is enough to stop -Z" {
    // The second url has no destination, so it falls to standard output.
    const plan = schedulePlan(&.{ "http://x/one", "http://x/two" }, &.{.{ .file = "a" }}, null);
    try testing.expectEqualStrings(
        "zurl: -Z: a body goes to standard output, which is one stream, so the transfers run one at a time",
        (try parallelBlocker(testing.allocator, plan)).?,
    );
}

test "-D names one file for every url, so -Z runs one at a time" {
    const plan = schedulePlan(
        &.{ "http://x/one", "http://x/two" },
        &.{ .{ .file = "a" }, .{ .file = "b" } },
        "heads.txt",
    );
    try testing.expectEqualStrings(
        "zurl: -Z: -D names one file for every url, so the transfers run one at a time",
        (try parallelBlocker(testing.allocator, plan)).?,
    );
}

test "two urls that write to one file stop -Z" {
    const plan = schedulePlan(
        &.{ "http://x/one", "http://x/two" },
        &.{ .{ .file = "a" }, .{ .file = "a" } },
        null,
    );
    try testing.expectEqualStrings(
        "zurl: -Z: two urls write to the same file, so the transfers run one at a time",
        (try parallelBlocker(testing.allocator, plan)).?,
    );
}

test "standard output is named before -D, and -D before a repeated file" {
    // All three shapes at once. The order the sentences come in is what a
    // user reads, so it is pinned here rather than left to the reader of
    // the code.
    const both = schedulePlan(&.{ "http://x/one", "http://x/two" }, &.{}, "heads.txt");
    try testing.expectEqualStrings(
        "zurl: -Z: a body goes to standard output, which is one stream, so the transfers run one at a time",
        (try parallelBlocker(testing.allocator, both)).?,
    );

    const headers_and_repeat = schedulePlan(
        &.{ "http://x/one", "http://x/two" },
        &.{ .{ .file = "a" }, .{ .file = "a" } },
        "heads.txt",
    );
    try testing.expectEqualStrings(
        "zurl: -Z: -D names one file for every url, so the transfers run one at a time",
        (try parallelBlocker(testing.allocator, headers_and_repeat)).?,
    );
}

test "two -O urls with the same last segment name one file" {
    // Different hosts, different paths, one name. `-O` writes into the
    // working directory, so the host does not keep them apart.
    const plan = schedulePlan(
        &.{ "http://a/dir/report.bin", "http://b/other/report.bin" },
        &.{ .url_name, .url_name },
        null,
    );
    try testing.expect(try repeatedDestination(testing.allocator, plan));
}

test "two -O urls with different last segments name two files" {
    const plan = schedulePlan(
        &.{ "http://a/one.bin", "http://a/two.bin" },
        &.{ .url_name, .url_name },
        null,
    );
    try testing.expect(!try repeatedDestination(testing.allocator, plan));
}

test "an -o path and a -O last segment share one key space" {
    // `-o report.bin` and a url ending in `/report.bin` name one file.
    const plan = schedulePlan(
        &.{ "http://a/one", "http://b/dir/report.bin" },
        &.{ .{ .file = "report.bin" }, .url_name },
        null,
    );
    try testing.expect(try repeatedDestination(testing.allocator, plan));
}

test "two -O urls that both fall back to curl_response name one file" {
    // Neither url's last path segment names anything, so `nameFromUrl`
    // hands back its own constant for both.
    const plan = schedulePlan(
        &.{ "http://a/", "http://b/" },
        &.{ .url_name, .url_name },
        null,
    );
    try testing.expect(try repeatedDestination(testing.allocator, plan));
}

test "a url whose -O name is refused stands for itself" {
    // `..` is a name `nameFromUrl` refuses, so the whole url is the key.
    // Two copies of one refused url still name one destination, and two
    // different refused urls do not.
    const same = schedulePlan(
        &.{ "http://a/dir/..%2fx", "http://a/dir/..%2fx" },
        &.{ .url_name, .url_name },
        null,
    );
    try testing.expect(try repeatedDestination(testing.allocator, same));

    const different = schedulePlan(
        &.{ "http://a/dir/..%2fx", "http://a/dir/..%2fy" },
        &.{ .url_name, .url_name },
        null,
    );
    try testing.expect(!try repeatedDestination(testing.allocator, different));
}

test "a url on standard output has no file name to clash with" {
    // One url writes `a` and the other writes the stream. No two files.
    const plan = schedulePlan(&.{ "http://x/a", "http://x/b" }, &.{.{ .file = "a" }}, null);
    try testing.expect(!try repeatedDestination(testing.allocator, plan));
}

test "one url can never repeat a destination" {
    const plan = schedulePlan(&.{"http://x/a"}, &.{.url_name}, null);
    try testing.expect(!try repeatedDestination(testing.allocator, plan));
}

test "three urls find the repeat that is not a neighbour" {
    // The sort is what makes this work: `a`, `b`, `a` holds no repeated
    // neighbour until the keys are in order.
    const plan = schedulePlan(
        &.{ "http://x/1", "http://x/2", "http://x/3" },
        &.{ .{ .file = "a" }, .{ .file = "b" }, .{ .file = "a" } },
        null,
    );
    try testing.expect(try repeatedDestination(testing.allocator, plan));
}

test "a partial worker start says how many workers the run really got" {
    // The defect this closes. The note went out only when the run got no
    // extra worker at all, so a run that asked for eight and got three
    // said nothing, and the user waited longer than they asked to with no
    // word about it.
    var buffer: [note_buffer_len]u8 = undefined;
    const note = workerShortfallNote(&buffer, 8, 3).?;
    try testing.expectEqualStrings(
        "zurl: -Z: this build started 3 of the 8 workers asked for, so the transfers run 3 at a time",
        note,
    );
}

test "a build with no concurrency keeps its own wording" {
    // One worker means no concurrency at all, which is a property of the
    // build and not of the machine. A user acts on the two differently, so
    // the sentence has to tell them apart.
    var buffer: [note_buffer_len]u8 = undefined;
    const note = workerShortfallNote(&buffer, 8, 1).?;
    try testing.expectEqualStrings(
        "zurl: -Z: this build has no concurrency, so the transfers run one at a time",
        note,
    );
}

test "a run that gets every worker it asked for says nothing" {
    var buffer: [note_buffer_len]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), workerShortfallNote(&buffer, 8, 8));
}

test "a run that asked for one worker says nothing" {
    // `parallelBlocker` and the standard output branch each write their
    // own note before taking the run down to one slot. A second note here
    // would tell the user the same thing twice.
    var buffer: [note_buffer_len]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), workerShortfallNote(&buffer, 1, 1));
}

test "the shortfall note still reaches the user when its buffer is too small" {
    // Bounded, and never silent. A note that will not fit loses its
    // numbers, not the fact that the run was degraded.
    var buffer: [8]u8 = undefined;
    const note = workerShortfallNote(&buffer, 8, 3).?;
    try testing.expectEqualStrings(
        "zurl: -Z: this build started fewer workers than asked for, so fewer transfers run at a time",
        note,
    );
}

/// A `Plan` with the fields the meter decision reads, and nothing else.
///
/// `meterVisibility` reads `silent` and `output.body`. Every other field
/// keeps its default, so a test names only what it measures.
fn meterPlan(body: []const Args.BodyTarget, silent: bool) Args.Plan {
    return .{
        .urls = &.{ "http://x/one", "http://x/two" },
        .options = .{},
        .output = .{ .body = body },
        .silent = silent,
    };
}

test "a url on standard output draws no meter when standard output is a terminal" {
    // The terminal check is a boolean this test sets, so the test needs
    // no terminal. Measured against curl 8.21.0 under a real pty: `curl
    // URL` on a terminal draws no meter, and `curl URL | cat` draws one.
    const plan = meterPlan(&.{}, false);

    try testing.expect(!progress.draws(meterVisibility(plan, 0, true, true)));
    try testing.expect(progress.draws(meterVisibility(plan, 0, false, true)));
}

test "a url that writes a file still draws a meter on a terminal" {
    // Measured: `curl -o f URL` and `curl -O URL` both draw on a
    // terminal. The body is not on the screen, so nothing is cut.
    const to_file = meterPlan(&.{ .{ .file = "a" }, .url_name }, false);

    try testing.expect(progress.draws(meterVisibility(to_file, 0, true, true)));
    try testing.expect(progress.draws(meterVisibility(to_file, 1, true, true)));
}

test "the meter decision is for one url, and not for the whole run" {
    // Measured against curl 8.21.0 under a real pty: `curl -o f URL1
    // URL2` draws one meter, for the url that writes the file, and `curl
    // URL1 -o f URL2` draws one too. A run does not go quiet because an
    // earlier url went to the screen.
    const first_to_file = meterPlan(&.{.{ .file = "a" }}, false);
    try testing.expect(progress.draws(meterVisibility(first_to_file, 0, true, true)));
    try testing.expect(!progress.draws(meterVisibility(first_to_file, 1, true, true)));
}

test "-s and -Z each stop the meter, whatever the terminal says" {
    // `-s` silences the meter and `-S` does not bring it back. `-Z`
    // overlaps transfers, and several meters on one standard error would
    // overwrite each other's row.
    const silent = meterPlan(&.{.{ .file = "a" }}, true);
    try testing.expect(!progress.draws(meterVisibility(silent, 0, false, true)));

    const loud = meterPlan(&.{.{ .file = "a" }}, false);
    try testing.expect(!progress.draws(meterVisibility(loud, 0, false, false)));
}

test "the exit code for a transfer fault is curl's own number" {
    try testing.expectEqual(@as(u8, 7), exitCodeFor(error.CouldNotConnect));
    try testing.expectEqual(@as(u8, 23), exitCodeFor(error.WriteError));
}

test "dropUnwritten throws away what a failed flush left behind" {
    var buffer: [16]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    try w.writeAll("lost");
    try testing.expectEqual(@as(usize, 4), w.end);
    dropUnwritten(&w);
    try testing.expectEqual(@as(usize, 0), w.end);
}

test "the statuses a bare --retry sends the request again for are curl's own six" {
    // **The table this whole flag turns on, and each row was measured
    // against curl 8.21.0 with `--retry 1 --retry-delay 1`.** Two
    // requests went out for each status below and one for every other.
    // Retrying a status curl does not retry is worse than not retrying at
    // all: it can repeat a request the server already acted on.
    const retried = [_]u16{ 408, 429, 500, 502, 503, 504 };
    for (retried) |status| {
        if (!retryableStatus(status)) {
            std.debug.print("{d} should be retried\n", .{status});
            return error.TestUnexpectedResult;
        }
    }

    // The measured `no` list, and it is the important half. `404` and
    // `401` are the two a careless set would sweep in.
    const kept = [_]u16{ 200, 204, 301, 302, 400, 401, 403, 404, 405, 409, 425, 501, 505, 507 };
    for (kept) |status| {
        if (retryableStatus(status)) {
            std.debug.print("{d} should not be retried\n", .{status});
            return error.TestUnexpectedResult;
        }
    }
}

test "a bare --retry covers a timeout and a name with no address, and nothing else" {
    // Measured: `--retry 2` against a server that never answered ran three
    // requests, and against a closed port ran one. A body that stopped
    // short of its length ran one too.
    const bare: Args.Retry = .{ .attempts = 2 };
    try testing.expect(retryableFailure(bare, error.OperationTimedOut));
    try testing.expect(retryableFailure(bare, error.CouldNotResolveHost));
    try testing.expect(!retryableFailure(bare, error.CouldNotConnect));
    try testing.expect(!retryableFailure(bare, error.PartialFile));
    try testing.expect(!retryableFailure(bare, error.ReadError));
    try testing.expect(!retryableFailure(bare, error.PeerFailedVerification));
    try testing.expect(!retryableFailure(bare, error.WriteError));

    // `--retry-connrefused` adds the dial and adds nothing else.
    const refused: Args.Retry = .{ .attempts = 2, .connrefused = true };
    try testing.expect(retryableFailure(refused, error.CouldNotConnect));
    try testing.expect(!retryableFailure(refused, error.PartialFile));
    try testing.expect(!retryableFailure(refused, error.PeerFailedVerification));

    // `--retry-all-errors` adds every failure, which is what its name
    // says and what curl does.
    const all: Args.Retry = .{ .attempts = 2, .all_errors = true };
    try testing.expect(retryableFailure(all, error.PartialFile));
    try testing.expect(retryableFailure(all, error.PeerFailedVerification));
    try testing.expect(retryableFailure(all, error.CouldNotConnect));
}

test "the wait between two tries is curl's own, and Retry-After can only raise it" {
    // Measured: no `--retry-delay` waited 1, 2, 4, and 8 seconds, and
    // `--retry-delay 2` waited 2 seconds every time. A `503` carrying
    // `Retry-After: 3` waited 3 seconds under both.
    try testing.expectEqual(@as(u64, 1000), retryWait(1000, null));
    try testing.expectEqual(@as(u64, 3000), retryWait(1000, 3));
    // A header asking for less than the flags built changes nothing. A
    // peer must not be able to shorten the wait a user asked for.
    try testing.expectEqual(@as(u64, 4000), retryWait(4000, 1));
    try testing.expectEqual(@as(u64, 2000), retryWait(2000, 2));
}

test "Retry-After is read as a count of seconds, and a date is read as no header" {
    try testing.expectEqual(@as(?u32, 3), retryAfterSeconds("3"));
    try testing.expectEqual(@as(?u32, 120), retryAfterSeconds(" 120 "));
    try testing.expectEqual(@as(?u32, 0), retryAfterSeconds("0"));

    // No header at all, and an empty one.
    try testing.expectEqual(@as(?u32, null), retryAfterSeconds(null));
    try testing.expectEqual(@as(?u32, null), retryAfterSeconds(""));
    try testing.expectEqual(@as(?u32, null), retryAfterSeconds("   "));

    // **A date is read as no header.** RFC 9110 allows one there and curl
    // reads it. A date read wrong would put a wait of days on a run that
    // asked for seconds, so this reads none rather than read one badly.
    try testing.expectEqual(@as(?u32, null), retryAfterSeconds("Wed, 21 Oct 2015 07:28:00 GMT"));
    try testing.expectEqual(@as(?u32, null), retryAfterSeconds("3s"));
    try testing.expectEqual(@as(?u32, null), retryAfterSeconds("-1"));

    // A peer that asks for a year gets the bound. `--retry-max-time`
    // still ends the run either way.
    try testing.expectEqual(@as(?u32, retry_after_max_s), retryAfterSeconds("99999999"));
    try testing.expectEqual(
        @as(?u32, retry_after_max_s),
        retryAfterSeconds("999999999999999999999999"),
    );
}

test "a --retry note names the reason and the wait, and -s keeps it quiet" {
    // The note is recovery, so it follows the same `-s` and `-S` rule
    // every other note follows: quiet under `-s`, and back under `-sS`.
    var buffer: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buffer);
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();

    const ctx: Context = .{
        .gpa = testing.allocator,
        .arena = testing.allocator,
        .io = testing.io,
        .env = &env,
        .stdout = &out,
        .stderr = &out,
    };

    var plan: Args.Plan = .{ .urls = &.{}, .options = .{} };
    try noteRetry(ctx, plan, .http_status, 2000, 1);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "2.000 seconds") != null);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "1 left") != null);

    out.end = 0;
    plan.silent = true;
    try noteRetry(ctx, plan, .connect, 1000, 0);
    try testing.expectEqualStrings("", out.buffered());

    out.end = 0;
    plan.show_error = true;
    try noteRetry(ctx, plan, .timed_out, 1000, 0);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "ran out of time") != null);
}

test "--parallel-max reads a number inside its range and names one outside it" {
    var buffer: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buffer);
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();

    const ctx: Context = .{
        .gpa = testing.allocator,
        .arena = testing.allocator,
        .io = testing.io,
        .env = &env,
        .stdout = &out,
        .stderr = &out,
    };

    // No flag keeps zurl's own default.
    const bare: Args.Plan = .{ .urls = &.{}, .options = .{} };
    try testing.expectEqual(parallel_slots, try parallelWanted(ctx, bare));
    try testing.expectEqualStrings("", out.buffered());

    // Every number inside the range is taken as written, the ends
    // included.
    for ([_]usize{ 1, 2, 8, 50, parallel_max_ceiling }) |named| {
        out.end = 0;
        const plan: Args.Plan = .{ .urls = &.{}, .options = .{}, .parallel_max = named };
        try testing.expectEqual(named, try parallelWanted(ctx, plan));
        try testing.expectEqualStrings("", out.buffered());
    }

    // A number outside it falls back to the default and says so. curl
    // falls back with no word at all; the fallback is recovery, and
    // recovery is never silent.
    for ([_]usize{ 0, parallel_max_ceiling + 1, 5000 }) |named| {
        out.end = 0;
        const plan: Args.Plan = .{ .urls = &.{}, .options = .{}, .parallel_max = named };
        try testing.expectEqual(parallel_slots, try parallelWanted(ctx, plan));
        try testing.expect(std.mem.indexOf(u8, out.buffered(), "--parallel-max") != null);
    }
}

test "a Range the caller wrote outranks the one -C or -r would build" {
    // Measured against curl 8.21.0: `-r 0-9 -H 'Range: bytes=7-8'` sends
    // `bytes=7-8` and no second line. Two `Range` headers would let a peer
    // read one request as two.
    try testing.expect(userWroteRange(&.{.{ .name = "Range", .value = "bytes=1-2" }}));
    // A field name has no case to a server.
    try testing.expect(userWroteRange(&.{.{ .name = "range", .value = "bytes=1-2" }}));
    try testing.expect(userWroteRange(&.{
        .{ .name = "X-A", .value = "1" },
        .{ .name = "RANGE", .value = "bytes=1-2" },
    }));

    try testing.expect(!userWroteRange(&.{}));
    try testing.expect(!userWroteRange(&.{.{ .name = "X-A", .value = "1" }}));
    // A name that starts the same is not that header.
    try testing.expect(!userWroteRange(&.{.{ .name = "Range-Unit", .value = "bytes" }}));
}

test "the numbers the parser refuses on are the numbers the packages keep" {
    // **Two files hold each of these numbers, and this is what keeps the
    // two in step.** `src/cli/Args.zig` refuses a flag value before any
    // transfer starts, and the protocol package refuses the same value
    // again inside `open`. The parser cannot import the package, because
    // a build may leave the package out, so it writes the number down
    // itself. This test is the only place the two meet.
    try testing.expectEqual(zurl_mqtt.max_message_count, Args.max_mqtt_messages);

    // And the default a transfer runs with is the package's own default,
    // so a subscribe with no `--mqtt-messages` reads what `--help` says it
    // reads.
    const defaults: zurl.Transfer.Options = .{};
    try testing.expectEqual(zurl_mqtt.default_message_count, defaults.mqtt_messages);
}

test "a Content-Range reads back the three numbers it names" {
    const said = try parseContentRange("bytes 5-9/10");
    try testing.expectEqual(@as(u64, 5), said.first);
    try testing.expectEqual(@as(u64, 9), said.last);
    try testing.expectEqual(@as(?u64, 10), said.complete);

    // `*` for the length is legal, and it is the shape a peer sends when
    // it streams a body it has not measured.
    const unknown = try parseContentRange("bytes 5-9/*");
    try testing.expectEqual(@as(u64, 5), unknown.first);
    try testing.expectEqual(@as(?u64, null), unknown.complete);

    // One byte, at the end of the entity.
    const one = try parseContentRange("bytes 9-9/10");
    try testing.expectEqual(@as(u64, 9), one.first);
    try testing.expectEqual(@as(u64, 9), one.last);

    // The whole entity, named as a range. A `206` may say this, and the
    // caller compares the first position with the offset it asked for, so
    // it is the caller and not the parser that refuses it.
    const whole = try parseContentRange("bytes 0-9/10");
    try testing.expectEqual(@as(u64, 0), whole.first);

    // The unit has no case, and old servers end it with `=` or `:`.
    // Measured: curl 8.21.0 resumes on both of those spellings.
    try testing.expectEqual(@as(u64, 5), (try parseContentRange("BYTES 5-9/10")).first);
    try testing.expectEqual(@as(u64, 5), (try parseContentRange("bytes=5-9/10")).first);
    try testing.expectEqual(@as(u64, 5), (try parseContentRange("bytes: 5-9/10")).first);

    // The largest numbers a `u64` holds still read back.
    const big = try parseContentRange("bytes 18446744073709551614-18446744073709551614/*");
    try testing.expectEqual(@as(u64, std.math.maxInt(u64) - 1), big.first);
}

test "a Content-Range that describes no bytes is refused and never gives a position" {
    // The unit is not bytes. curl reads the `5` here and resumes, which is
    // the corruption this parser exists to stop.
    try testing.expectError(error.NotBytes, parseContentRange("items 5-9/10"));
    try testing.expectError(error.NotBytes, parseContentRange("bytess 5-9/10"));
    // A value with no unit at all ends nowhere the unit can end, so it
    // reads as a value that does not parse. curl takes this one and
    // resumes on it, measured.
    try testing.expectError(error.Malformed, parseContentRange("5-9/10"));

    // The `416` shape. It names a length and no first byte.
    try testing.expectError(error.NoFirstPosition, parseContentRange("bytes */10"));
    try testing.expectError(error.NoFirstPosition, parseContentRange("bytes  */10"));

    try testing.expectError(error.Malformed, parseContentRange(""));
    try testing.expectError(error.Malformed, parseContentRange("bytes"));
    try testing.expectError(error.Malformed, parseContentRange("bytes "));
    try testing.expectError(error.Malformed, parseContentRange("bytes garbage"));
    try testing.expectError(error.Malformed, parseContentRange("bytes 5-9"));
    try testing.expectError(error.Malformed, parseContentRange("bytes -9/10"));
    try testing.expectError(error.Malformed, parseContentRange("bytes 5-/10"));
    try testing.expectError(error.Malformed, parseContentRange("bytes 5-9/"));
    // A sign and a digit separator are not in the grammar, and
    // `std.fmt.parseInt` alone would take both.
    try testing.expectError(error.Malformed, parseContentRange("bytes +5-9/10"));
    try testing.expectError(error.Malformed, parseContentRange("bytes 5-9/1_0"));
    try testing.expectError(error.Malformed, parseContentRange("bytes 0x5-9/10"));
    // A range that ends before it starts, or that reaches past the entity
    // it says it came from.
    try testing.expectError(error.Malformed, parseContentRange("bytes 9-5/10"));
    try testing.expectError(error.Malformed, parseContentRange("bytes 5-10/10"));
    try testing.expectError(error.Malformed, parseContentRange("bytes 0-0/0"));
    // Above a `u64`, and longer than the bound.
    try testing.expectError(error.Malformed, parseContentRange("bytes 18446744073709551616-9/*"));
    try testing.expectError(error.Malformed, parseContentRange("bytes " ++ ("9" ** 200) ++ "-9/*"));
}
