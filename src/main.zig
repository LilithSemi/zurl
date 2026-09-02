//! zurl: the command-line entry point.
//!
//! `main` does wiring only: read argv, dispatch to the matching action, and
//! turn the result into an exit code. Everything else stays out of this
//! file. `src/cli/Args.zig` parses the flags, `src/cli/run.zig` fetches the
//! urls, and `src/cli/report.zig` turns a fault into a line on stderr.
//!
//! This binary answers `--version`, `--help`, and a bad command line, and
//! it fetches every url the command line names. The response body goes to
//! standard output, or to the file `-o` names, or to the file `-O` takes
//! from the url. `src/cli/output.zig` owns the last two.
//!
//! Two decisions shape `dispatch`, and each one has a test:
//!
//! - **A flag this build cannot honour is refused before any network
//!   access.** `refusal` runs before the `Client` exists, so a user who
//!   passes a `-w` format string past `writeout.max_format_bytes` learns
//!   that before a transfer runs, not after.
//! - **A netrc file the command line asked for and zurl cannot read stops
//!   the run.** `loadNetrc` reads that file here, before the first
//!   transfer, so the credentials never go missing behind a `401` that
//!   names no cause. A path `--netrc-file` named is a usage fault, exit 2.
//!   The default file `--netrc` reads is exit 26, and
//!   `--netrc-optional` accepts a missing one. Every code is curl's own,
//!   measured.
//!
//! The decisions that shape the run itself, such as the one `Client` for
//! every url and the exit code `-Z` keeps, sit in `src/cli/run.zig` beside
//! the code that holds them up.
//!
//! Exit codes follow curl. Success is 0. A bad command line is 2, curl's
//! own `CURLE_FAILED_INIT` convention for a usage error. A failed transfer
//! exits with that transfer's `CURLE_*` number, from
//! `zurl_core.errors.curlCode`.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl = @import("zurl");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// The flag parser.
const Args = @import("cli/Args.zig");
/// The two places a fault becomes text.
const report = @import("cli/report.zig");
/// The `-w` format string.
const writeout = @import("cli/writeout.zig");
/// The one printer for untrusted text in a message.
const safe = @import("cli/safe.zig");
/// The text `--help` prints.
const help = @import("cli/help.zig");
/// The one place a `-d`, a `--json`, or a `-T` becomes bytes on the wire.
const body = @import("cli/body.zig");
/// The run: the choice between one transfer at a time and `-Z`, and one
/// url's path from the command line to the bytes on disk.
const run = @import("cli/run.zig");
/// What a `-z`, `--time-cond` argument means, and the header it writes.
const timecond = @import("cli/timecond.zig");

/// What every action needs. `src/cli/run.zig` owns it, because every field
/// but the two writers exists for a transfer.
const Context = run.Context;

/// The exit code for a bad command line. Matches curl's `CURLE_FAILED_INIT`.
///
/// Public because `cli/e2e_test.zig` asserts on it too. The end to end
/// tests must name the same constant the program uses, or a change to one
/// of them would leave the other pinning a stale number.
pub const usage_error_code: u8 = 2;

/// The exit code for an option whose *argument* did not read, where curl
/// answers with `CURLE_SETOPT_OPTION_SYNTAX` and not with its usage code.
///
/// `--resolve` and `--connect-to` are the two flags that reach it.
/// Measured against curl 8.21.0: `--resolve bogus` prints `Could not parse
/// CURLOPT_RESOLVE entry 'bogus'` and exits 49.
///
/// Public for the same reason `usage_error_code` is: the end to end tests
/// assert on the same constant the program returns.
pub const setopt_syntax_error_code: u8 = 49;

/// The exit code for a url that carried a credential where
/// `--disallow-username-in-url` refused one.
///
/// This is curl's `CURLE_LOGIN_DENIED`. Measured against curl 8.21.0:
/// `--disallow-username-in-url http://alice@host/` prints `URL rejected:
/// Credentials was passed in the URL when prohibited` and exits 67.
///
/// Public for the same reason the two above are: the end to end tests
/// assert on the same constant the program returns.
pub const login_denied_error_code: u8 = 67;

/// How large a `--netrc-file` may be. A netrc file holds one line for each
/// machine, so this is far past any real one. A larger file is a usage
/// fault, not a read that grows without a bound.
const max_netrc_bytes: usize = 1 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    // **The standard streams write where the file description points, not
    // where this process counts.** `Io.File.Writer.init` selects
    // `.positional`, which writes through `pwrite` at an offset this
    // writer holds and starts at zero. A process does not own the offset
    // of a descriptor it inherited: the shell sets it, and another
    // program may share it. So `zurl url` inside `{ echo x; zurl url; }
    // > log` wrote its body over the shell's line. `.initStreaming` uses
    // `write`, which the kernel applies at the shared offset, and that is
    // what a standard stream means.
    //
    // A file `-o` names is different, and stays positional. `output.zig`
    // creates that file itself, so it owns the offset, and `-C` seeks it
    // on purpose.
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer: Io.File.Writer = .initStreaming(.stdout(), io, &stdout_buffer);

    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer: Io.File.Writer = .initStreaming(.stderr(), io, &stderr_buffer);

    // **The one place zurl asks the operating system about a terminal.**
    // A transfer that writes its body to a terminal draws no progress
    // meter, because the meter's row would cut into the body on that same
    // screen. `Context.stdout_is_terminal` carries the answer down, and
    // `cli/progress.zig` holds the rule that reads it. Asking once here
    // keeps every path below pure and keeps the tests off a real
    // terminal.
    const stdout_is_terminal = try Io.File.stdout().isTty(io);

    const ctx: Context = .{
        .gpa = init.gpa,
        .arena = arena,
        .io = io,
        .env = init.environ_map,
        .stdout = &stdout_writer.interface,
        .stderr = &stderr_writer.interface,
        .stdout_is_terminal = stdout_is_terminal,
    };

    var exit_code = dispatch(ctx, try commandLine(arena, init)) catch |err| switch (err) {
        // A write to one of the two streams that no path below could
        // report, such as the note `-Z` prints or the hint after a usage
        // fault. It reaches here as one error with no detail, so the line
        // it earns is the general one.
        error.WriteFailed => write_fault: {
            run.dropUnwritten(ctx.stdout);
            report.writeStdoutFault(ctx.stderr) catch {};
            break :write_fault run.exitCodeFor(error.WriteError);
        },
        else => |e| return e,
    };

    // **Neither flush may escape this function.** A write to standard
    // output fails whenever the far end will not take the bytes: a full
    // disk, a closed pipe, a pager the user quit. Letting the error out of
    // `main` printed a Zig stack trace and exit 1, where curl 8.21.0
    // prints one sentence and exits 23. So both flushes report instead.
    //
    // Everything below `dispatch` that writes a body or a write-out
    // flushes its own bytes and reports its own fault, and it drops what
    // it could not write, through `run.dropUnwritten`. Anything still buffered
    // here is therefore text no lower path has reported: what `--version`,
    // `--help`, or a usage fault left behind. One line covers it.
    ctx.stdout.flush() catch {
        report.writeStdoutFault(ctx.stderr) catch {};
        if (exit_code == 0) exit_code = run.exitCodeFor(error.WriteError);
    };
    // Standard error has no second stream to report to. A message that
    // cannot be written is lost, and the exit code still tells the shell
    // what happened, which is the part a script reads.
    ctx.stderr.flush() catch {};
    std.process.exit(exit_code);
}

/// Returns what the user typed after the program name, as plain slices.
///
/// `Args` takes `[]const []const u8` and `toSlice` gives
/// `[]const [:0]const u8`, so the sentinel has to come off. Nothing below
/// reads argv[0].
fn commandLine(arena: Allocator, init: std.process.Init) std.process.Args.ToSliceError![]const []const u8 {
    const argv = try init.minimal.args.toSlice(arena);
    // A process normally has argv[0]. An empty argv is not a reason to
    // crash, so this drops nothing rather than slicing past the end.
    const tail = if (argv.len > 0) argv[1..] else argv;

    const args = try arena.alloc([]const u8, tail.len);
    for (args, tail) |*out, in| out.* = in;
    return args;
}

/// Parses `args` and runs the one matching action, returning the exit code
/// to give the shell.
///
/// `--version` and `--help` are read only as the *first* argument, because
/// `Args` does not know either flag and a scan of the whole command line
/// cannot tell a `--help` the user meant from one that is another flag's
/// value. `--help` names this limit.
fn dispatch(given: Context, args: []const []const u8) !u8 {
    // **`--stderr` moves every message, so the context it moves is
    // mutable from here down.** The file cannot be opened before the
    // parse, because the parse is what names it, so the flag reaches only
    // the messages that come after it. A usage fault in the command line
    // itself therefore reaches the real standard error, which is where a
    // user who typed the flag wrong will look for it.
    var ctx = given;
    // Storage for the redirected writer. It lives on this frame because
    // `ctx.stderr` holds its address for the rest of the run.
    var redirect_buffer: [4096]u8 = undefined;
    var redirect_writer: Io.File.Writer = undefined;
    var redirect_file: ?Io.File = null;
    defer if (redirect_file) |file| {
        // The bytes are the user's messages. A flush that fails has no
        // second stream to report to, which is the rule the real standard
        // error already runs under, so the exit code carries it alone.
        ctx.stderr.flush() catch {};
        file.close(ctx.io);
    };

    if (args.len == 0) {
        try ctx.stderr.writeAll(report.help_hint);
        return usage_error_code;
    }

    // Both spellings of each, the way curl spells them: `-V, --version`
    // and `-h, --help`. These two are the only flags `Args.flag_table`
    // does not carry, so they are the only two whose spellings are written
    // out by hand, and the pair had to be checked by hand as well.
    if (std.mem.eql(u8, args[0], "--version") or std.mem.eql(u8, args[0], "-V")) {
        try printVersion(ctx.stdout);
        return 0;
    }
    if (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")) {
        try help.print(ctx.stdout);
        return 0;
    }

    var fault: Args.Fault = .{};
    var plan = Args.parseWithConfigFiles(ctx.arena, ctx.io, args, ctx.env, &fault) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        // A protocol name nobody knows is the one parse fault that is not
        // a usage fault. curl 8.21.0 answers `--proto-default nosuchproto`
        // with exit 1, which is `CURLE_UNSUPPORTED_PROTOCOL`, and not with
        // its usage code, so the number a script reads is the number curl
        // gives it. Measured.
        error.UnsupportedProtocolName => {
            try report.writeUsageFault(ctx.stderr, err, fault.message);
            return run.exitCodeFor(error.UnsupportedProtocol);
        },
        // A `--resolve` or `--connect-to` entry that does not read is the
        // second parse fault that is not a usage fault. curl 8.21.0
        // answers `--resolve bogus` with exit 49, which is
        // `CURLE_SETOPT_OPTION_SYNTAX`, so the number a script reads is
        // the number curl gives it. Measured.
        error.InvalidHostOverride => {
            try report.writeUsageFault(ctx.stderr, err, fault.message);
            return setopt_syntax_error_code;
        },
        // **A credential in a url that `--disallow-username-in-url`
        // refused is not a usage fault.** curl 8.21.0 answers it with
        // exit 67, `CURLE_LOGIN_DENIED`, and the sentence `URL rejected:
        // Credentials was passed in the URL when prohibited`. That is the
        // number a script reads, so it is the number zurl gives.
        error.UsernameInUrl => {
            try report.writeUsageFault(ctx.stderr, err, fault.message);
            return login_denied_error_code;
        },
        // **A bad proxy is not a usage fault to curl, and it is not one
        // here.** Measured against curl 8.21.0: `-x ftp://127.0.0.1` prints
        // `Unsupported proxy scheme` and exits 7, and
        // `-x http://127.0.0.1:notaport` exits 5. Those are the numbers a
        // script reads, so they are the numbers zurl gives.
        error.UnsupportedProxyScheme => {
            try report.writeUsageFault(ctx.stderr, err, fault.message);
            return run.exitCodeFor(error.CouldNotConnect);
        },
        error.InvalidProxy => {
            try report.writeUsageFault(ctx.stderr, err, fault.message);
            return run.exitCodeFor(error.CouldNotResolveProxy);
        },
        else => {
            try report.writeUsageFault(ctx.stderr, err, fault.message);
            return usage_error_code;
        },
    };

    // What the default config file asked for and this build cannot do.
    // curl treats that file as advice, so the run goes on and the user
    // hears about each line that was dropped. IronStyle: recovery is
    // never silent.
    //
    // Written after the parse, so a `silent` line in that same file still
    // silences these, which is what curl does: a `~/.curlrc` holding
    // `silent` and one unknown option printed nothing at all.
    if (!plan.silent or plan.show_error) {
        for (plan.warnings) |line| try ctx.stderr.print("{s}\n", .{line});
    }

    // **`--stderr`: every message from here down goes to the file.** The
    // text `-` names standard output, which is what curl reads it as. A
    // file that cannot be opened is a usage fault: the user named a
    // destination and a run that carried on would put the messages
    // somewhere the user did not ask for.
    if (plan.stderr_path) |named| {
        if (std.mem.eql(u8, named, "-")) {
            ctx.stderr = ctx.stdout;
        } else {
            const file = Io.Dir.cwd().createFile(ctx.io, named, .{}) catch |err| {
                try ctx.stderr.print(
                    "zurl: option --stderr: cannot write '{f}': {s}\n",
                    .{ safe.text(named), @errorName(err) },
                );
                return usage_error_code;
            };
            redirect_file = file;
            redirect_writer = .init(file, ctx.io, &redirect_buffer);
            ctx.stderr = &redirect_writer.interface;
        }
    }

    // **A flag this build accepts and cannot run stops here, by name.**
    // See `Args.UnsupportedFlag`: each of these fails quietly when it is
    // accepted and dropped, so none of them is dropped. Nothing has opened
    // a socket yet.
    if (plan.unsupported_flag) |unsupported| {
        try ctx.stderr.print("zurl: option '{f}': {s}\n", .{
            safe.text(unsupported.flag),
            unsupported.reason,
        });
        try ctx.stderr.writeAll(report.help_hint);
        return usage_error_code;
    }

    // **`--dump-ca-embed`: write the trust bundle and run nothing.** The
    // flag answers even for a command line that names a url, which is what
    // curl does, measured. It sits after the refusal above so a command
    // line that also named a flag this build cannot honour still hears
    // about that flag, and it sits before every transfer so no socket
    // opens.
    //
    // The bytes are the build's own, so they need no `safe.text`: nothing
    // a user typed reaches this output.
    if (plan.dump_ca_embed) {
        try ctx.stdout.writeAll(zurl.embedded_ca_bundle_pem);
        // The write is buffered, so a flush that fails is the difference
        // between a bundle on the pipe and half of one. It is reported and
        // never dropped.
        ctx.stdout.flush() catch {
            try ctx.stderr.writeAll("zurl: --dump-ca-embed: cannot write the bundle to standard output\n");
            return run.exitCodeFor(error.WriteError);
        };
        return 0;
    }

    // Every check below runs before the `Client` exists, so none of them
    // can report a fault after a transfer already reached a server.
    if (refusal(plan)) |message| {
        // Ends with the same hint every other usage fault gives, because
        // `--help` lists each flag this build refuses and why.
        try ctx.stderr.print("{s}\n", .{message});
        try ctx.stderr.writeAll(report.help_hint);
        return usage_error_code;
    }

    if (plan.urls.len == 0) {
        try ctx.stderr.writeAll("zurl: no url given\n");
        try ctx.stderr.writeAll(report.help_hint);
        return usage_error_code;
    }

    if (try loadNetrc(ctx, &plan)) |code| return code;

    // **`--etag-compare` and `-z` both name a file, so both are resolved
    // here and not in `Args`.** `parse` opens nothing, which is what lets
    // it stay pure and testable. This is the same seam `--netrc-file`
    // uses, one line above.
    try resolveConditionals(ctx, &plan);

    // **The request body, and the storage the whole run reads it
    // through.** `Transfer.Options.body` holds the address of a field of
    // `storage`, and the engine reads through that address on every send,
    // so `storage` must live as long as the transfers do. It is on this
    // frame for that reason and no other.
    //
    // `-I` and `-D` both write response heads, so `-I` reaches this only
    // after the head target is settled below.
    var storage: body.Storage = .{};
    defer storage.deinit(ctx.io);
    if (!try body.resolve(
        .{ .arena = ctx.arena, .io = ctx.io, .stderr = ctx.stderr },
        &plan,
        &storage,
    )) {
        try ctx.stderr.writeAll(report.help_hint);
        return usage_error_code;
    }

    // **`-I` writes the response head, and there is nothing else it could
    // write.** curl 8.21.0 prints the head of a `-I` response on standard
    // output, which is exactly what `-D -` does here. A `-D` of its own
    // already names a destination, so it stays: curl keeps the `-D` file
    // too and `-I` then adds nothing.
    if (plan.request_body.head and plan.output.headers_file == null) {
        plan.output.headers_file = .stdout;
    }

    // **The cookie jar of this run, and the one place it lives.** One jar
    // serves every url, because a cookie a server set on the first url
    // belongs to the run: that is what makes `-b` and `-c` round trip, and
    // it is what curl does with two urls in one invocation, measured.
    //
    // It is on this frame because `plan.options.cookies` holds its address
    // and the transfers read through that address. `-Z` shares one jar
    // across every worker, and `zurl.Jar` holds the lock for that.
    //
    // `plan.cookies_enabled` is the whole switch. A command line with no
    // `-b` and no `-c` builds a jar and never hands it to a transfer, so
    // the wire bytes stay exactly what they were before cookies existed.
    var jar: zurl.Jar = .init(ctx.gpa, ctx.io);
    defer jar.deinit();
    if (plan.cookies_enabled) {
        jar.junk_session_cookies = plan.junk_session_cookies;
        try loadCookieFiles(ctx, plan, &jar);
        plan.options.cookies = jar.interface();
    }

    // **The environment is read here and never inside a library.** An SSH
    // transfer needs the home directory, for `~/.ssh/known_hosts` and for
    // the default private key, and it needs a login name for a url that
    // names none. `zurl-ssh` reads no environment variable at all, for
    // the reason `Transfer.Options.netrc_text` records: a library that
    // read `HOME` itself would give a program that sets its own home two
    // answers, and every test of it would depend on the environment it
    // runs in.
    applySshEnvironment(ctx, &plan);

    const exit_code = try run.transfers(ctx, plan);
    if (plan.cookies_enabled) try saveCookieJar(ctx, plan, &jar);
    return exit_code;
}

/// Fills the two SSH options that come from the environment.
///
/// `HOME` is where `~/.ssh` is. `LOGNAME` comes before `USER`, which is
/// POSIX's own order and OpenSSH's: `LOGNAME` is the name the login
/// session was started under, and `USER` is the one a shell may have
/// changed. **An empty value names nobody** and is read as unset, which is
/// the rule `envPath` already holds for every path this program takes from
/// the environment.
///
/// A name that reaches here is still not a login: `zurl_sftp` and
/// `zurl_scp` each refuse a transfer with no user rather than guess one,
/// and this is the last candidate rather than the first.
fn applySshEnvironment(ctx: Context, plan: *Args.Plan) void {
    if (ctx.env.get("HOME")) |home| {
        if (home.len != 0) plan.options.ssh_home = home;
    }
    if (ctx.env.get("LOGNAME")) |name| {
        if (name.len != 0) {
            plan.options.ssh_user = name;
            return;
        }
    }
    if (ctx.env.get("USER")) |name| {
        if (name.len != 0) plan.options.ssh_user = name;
    }
}

/// Reads every jar file `-b` named into `jar`.
///
/// **A jar file that cannot be read costs no exit code.** Measured against
/// curl 8.21.0: `-b /nope/x` and `-b <a directory>` both exit 0, send no
/// `Cookie` header, and print nothing at all. zurl keeps the exit code and
/// the wire bytes and adds one line on standard error, under the same `-s`
/// and `-S` rule every other note follows. Recovery is never silent, and a
/// user whose session file was missing needs to hear it.
///
/// **No message here names a cookie.** A jar is a credential store, and a
/// count says everything a user needs: which file, and how many lines of
/// it were not cookies. `safe.text` prints the path, because a path from a
/// command line is untrusted text like any other.
fn loadCookieFiles(ctx: Context, plan: Args.Plan, jar: *zurl.Jar) Io.Writer.Error!void {
    const now = jar.nowSeconds();
    const speak = !plan.silent or plan.show_error;

    for (plan.cookie_files) |path| {
        jar.load(path, now) catch |err| {
            if (!speak) continue;
            switch (err) {
                error.JarTooLarge => try ctx.stderr.print(
                    "zurl: -b: '{f}' is larger than the {d} byte limit\n",
                    .{ safe.text(path), zurl.Jar.file_len_max },
                ),
                else => try ctx.stderr.print(
                    "zurl: -b: cannot read the cookie file '{f}'\n",
                    .{safe.text(path)},
                ),
            }
        };
    }

    if (speak and jar.report.lostAnything()) {
        try ctx.stderr.print(
            "zurl: -b: dropped {d} line(s) that were not cookies, " ++
                "{d} for a domain the file does not own, and {d} that had expired\n",
            .{ jar.report.malformed, jar.report.domain_refused, jar.report.expired },
        );
    }
}

/// Writes the jar where `-c` asked for it, after every url has run.
///
/// **A jar that cannot be written costs no exit code either.** Measured:
/// `curl -c /nope/dir/jar.txt URL` exits 0 and prints nothing. zurl keeps
/// the exit code, for the scripts that read it, and prints one line so the
/// loss is not silent.
///
/// `-c -` writes to standard output, which is the shape `-D -` has.
fn saveCookieJar(ctx: Context, plan: Args.Plan, jar: *zurl.Jar) Io.Writer.Error!void {
    const target = plan.cookie_jar orelse return;
    const now = jar.nowSeconds();

    switch (target) {
        .stdout => {
            jar.writeTo(ctx.stdout, now) catch {
                // The body already went to this same stream and reported
                // its own write faults. One line covers this one.
                if (!plan.silent or plan.show_error)
                    try ctx.stderr.writeAll("zurl: -c: cannot write the cookie jar to standard output\n");
            };
        },
        .file => |path| {
            jar.save(path, now) catch {
                if (!plan.silent or plan.show_error) try ctx.stderr.print(
                    "zurl: -c: cannot write the cookie jar to '{f}'\n",
                    .{safe.text(path)},
                );
            };
        },
    }
}

/// Returns the sentence that refuses `plan`, or null when this build can
/// honour every flag it holds.
///
/// `Plan` carries a field for each flag a later task implements. A build
/// that accepted such a flag and then did nothing with it would give the
/// user a transfer that quietly ignored what they asked for, so each one
/// is refused here instead. The wording matches every other refusal this
/// program writes: name the flag, then name the limit.
fn refusal(plan: Args.Plan) ?[]const u8 {
    // `-w` itself is honoured. Only a format string past the bound is
    // refused, and it is refused here so a user who typed one learns it
    // before a transfer runs, not after.
    if (plan.write_out) |format| {
        if (format.len > writeout.max_format_bytes) return writeout.too_long_message;
    }
    // **The two flags contradict each other, so the pair is a usage
    // fault.** `-C` says to add to the file the command line named, and
    // `--no-clobber` says never to touch it. A run that took both would
    // write the rest of a body into a file that holds none of the first
    // part. curl refuses the same pair: measured, `curl -C - --no-clobber
    // -o f URL` prints `option --no-clobber: is badly used here` and
    // exits 2 before any transfer.
    if (plan.no_clobber and plan.resume_at != null)
        return "zurl: option --no-clobber: cannot be used with -C";
    // **A proxy authentication scheme this build cannot answer stops the
    // run, and never quietly becomes Basic.** A user who wrote
    // `--proxy-digest` asked for a scheme where the password never travels.
    // Answering the proxy with `Basic` instead would put that password on
    // the wire in reversible base64, in cleartext, to the proxy. A refusal
    // says so; a downgrade would not.
    if (plan.proxy_auth_refused) |flag| {
        if (std.mem.eql(u8, flag, "--proxy-digest"))
            return "zurl: option --proxy-digest: this build answers a proxy with Basic alone";
        return "zurl: option --proxy-anyauth: this build answers a proxy with Basic alone";
    }
    return null;
}

/// The longest `--etag-compare` file zurl reads.
///
/// An entity tag is a short quoted string. This bound is far past any real
/// one, and it stops a file of unbounded length becoming a request header
/// of unbounded length. A file past it is read as no tag at all, with a
/// line on standard error.
const max_etag_bytes: usize = 8 * 1024;

/// The value `--etag-compare` sends when it has no tag to send.
///
/// **This is curl's own answer, measured against curl 8.21.0.** A
/// `--etag-compare` naming a file that does not exist, or an empty one,
/// still put `If-None-Match: ""` on the wire and exited 0. A missing file
/// earned a warning and nothing more. zurl matches, so a script that runs
/// `--etag-compare` before the file exists sends the same first request
/// under both programs.
const empty_etag: []const u8 = "\"\"";

/// Adds the `If-None-Match` and the `If-Modified-Since` headers the
/// command line asked for.
///
/// Both flags name something outside the process, so neither could be
/// resolved during the parse: `--etag-compare` reads a file, and `-z` may
/// name a file too.
///
/// **A user's own `-H` outranks both**, which is the rule every implied
/// header in `Args` already follows and curl's own answer for `-z`:
/// measured, `-z <date> -H 'If-Modified-Since: <other>'` put the `-H` line
/// on the wire and no second one. curl differs on `--etag-compare`, where
/// it sends both lines; zurl sends the user's alone, because two of one
/// conditional header let a server pick which one it answers.
///
/// Nothing here costs an exit code. Every fault is a line on standard
/// error under the same `-s` and `-S` rule the rest of the program follows,
/// which is what curl does with each of them.
fn resolveConditionals(ctx: Context, plan: *Args.Plan) (Allocator.Error || Io.Writer.Error)!void {
    const speak = !plan.silent or plan.show_error;

    if (plan.etag_compare) |path| {
        const text = Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(max_etag_bytes)) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.StreamTooLong => text: {
                if (speak) try ctx.stderr.print(
                    "zurl: --etag-compare: '{f}' is larger than the {d} byte limit, so no tag is sent\n",
                    .{ safe.text(path), max_etag_bytes },
                );
                break :text "";
            },
            else => text: {
                // curl warns and carries on here, and so does this.
                // Recovery is never silent, so the line is written even
                // though the transfer still runs.
                if (speak) try ctx.stderr.print(
                    "zurl: --etag-compare: cannot read '{f}', so no tag is sent\n",
                    .{safe.text(path)},
                );
                break :text "";
            },
        };
        // curl drops every line ending and sends what is left, quotes
        // included. Measured: a file holding `"q1"\n"q2"\n` sent
        // `If-None-Match: "q1""q2"`, so the newlines go and nothing else
        // does. A file holding `bare\n` sent `If-None-Match: bare`, so no
        // quote is ever added.
        const tag = try stripLineEndings(ctx.arena, text);
        try addHeader(ctx, plan, "If-None-Match", if (tag.len == 0) empty_etag else tag);
    }

    const argument = plan.time_cond orelse return;
    const request = timecond.split(argument);
    const name = request.condition.headerName() orelse {
        // `-z =<date>` asks about a file's own `Last-Modified`, which is
        // an ftp question. curl puts no header on an http request for it
        // either, measured, so the condition is dropped here. The user
        // still hears it, because a flag that changed nothing must say so.
        if (speak) try ctx.stderr.writeAll(
            "zurl: -z: a = prefix asks for a Last-Modified condition, which no http request carries\n",
        );
        return;
    };

    const seconds = timecond.readDate(request.text) orelse
        try fileTime(ctx, request.text) orelse {
        // curl's own wording, in zurl's voice: the argument was
        // neither a date nor a file, so the condition is dropped and
        // the transfer runs without it. Measured: curl exits 0 there.
        if (speak) try ctx.stderr.print(
            "zurl: -z: '{f}' is neither a date zurl reads nor a file, so no condition is sent\n",
            .{safe.text(request.text)},
        );
        return;
    };

    var value_buffer: [timecond.header_value_len]u8 = undefined;
    const value = timecond.writeHeaderValue(&value_buffer, seconds) orelse {
        // A file stamped outside the years an IMF-fixdate spells. See
        // `timecond.writeHeaderValue`.
        if (speak) try ctx.stderr.print(
            "zurl: -z: '{f}' names a time no date header holds, so no condition is sent\n",
            .{safe.text(request.text)},
        );
        return;
    };
    try addHeader(ctx, plan, name, try ctx.arena.dupe(u8, value));
}

/// Returns the modification time of `path` in seconds since the epoch, or
/// null when there is no such file.
///
/// This is the second half of what `-z` accepts. curl tries the date
/// first and the file second, and prints its warning only when both fail;
/// this keeps the same order for the same reason: a file named `now` must
/// not be shadowed by a word, and a date must not be shadowed by a file
/// that happens to carry its name.
///
/// A stamp outside the range an `i64` of seconds holds is clamped away by
/// returning null, so the caller reports it rather than send a moment that
/// wrapped.
fn fileTime(ctx: Context, path: []const u8) Io.Writer.Error!?i64 {
    if (path.len == 0) return null;
    const file = Io.Dir.cwd().openFile(ctx.io, path, .{}) catch return null;
    defer file.close(ctx.io);
    const info = file.stat(ctx.io) catch return null;
    const seconds = @divFloor(info.mtime.nanoseconds, std.time.ns_per_s);
    if (seconds < std.math.minInt(i64) or seconds > std.math.maxInt(i64)) return null;
    return @intCast(seconds);
}

/// Returns `text` with every CR and LF removed, in the arena.
///
/// An `--etag-compare` file ends in a newline whenever a shell or
/// `--etag-save` wrote it, and a header value may hold neither byte: one
/// there would end the header line early and let the rest of the file
/// read as further headers. That is the security half of this function,
/// and the reason it drops the bytes rather than refuse the file.
fn stripLineEndings(arena: Allocator, text: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, text.len);
    for (text) |byte| {
        if (byte == '\r' or byte == '\n') continue;
        out.appendAssumeCapacity(byte);
    }
    return out.toOwnedSlice(arena);
}

/// Appends one header to `plan.options.headers`, unless the user's own
/// `-H` already named it.
///
/// `plan.options.headers` is an arena slice the parse finished, so a
/// header added afterward needs a new slice one element longer. The arena
/// outlives every transfer, which is what makes that safe.
fn addHeader(
    ctx: Context,
    plan: *Args.Plan,
    name: []const u8,
    value: []const u8,
) Allocator.Error!void {
    for (plan.options.headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return;
    }
    const grown = try ctx.arena.alloc(std.http.Header, plan.options.headers.len + 1);
    @memcpy(grown[0..plan.options.headers.len], plan.options.headers);
    grown[plan.options.headers.len] = .{ .name = name, .value = value };
    plan.options.headers = grown;
}

/// curl's own exit code for a `--netrc` whose file could not be read.
///
/// Measured against curl 8.21.0, with `HOME` pointed at a directory that
/// holds no `.netrc`: `curl --netrc URL` prints `curl: (26) .netrc error:
/// no such file` and exits 26. No request goes out. `--netrc-optional`
/// exits 0 on the same command line and sends the request with no
/// credential.
///
/// 26 is `CURLE_READ_ERROR`, and not the 2 a usage fault earns, because
/// the command line itself was well formed: the file it named is what is
/// missing.
const netrc_read_error_code: u8 = 26;

/// Reads the netrc file the command line asked for into
/// `plan.options.netrc_text`, and returns the exit code that stops the
/// run, or null when the run may go on.
///
/// `Args` captures the flags and opens nothing, so this is where a file is
/// read. Three flags reach here, and they differ in which file and in what
/// a missing one means:
///
/// - `--netrc-file <path>` names one file. A path the user named and zurl
///   cannot read is a **usage fault**, exit 2, which is what curl answers
///   too: `curl --netrc-file /nope/x URL` prints `option --netrc-file: is
///   badly used here` and exits 2 before any transfer.
/// - `--netrc` and `-n` read the default file. A file that cannot be read
///   is exit 26.
/// - `--netrc-optional` reads the same default file, and a file that
///   cannot be read is no fault at all.
///
/// A `--netrc-file` on the command line outranks the default file, so the
/// explicit path is read first and the default search never runs. curl
/// refuses to combine them at all: `--netrc --netrc-file /nope/x` still
/// exits 2 on the path, measured.
///
/// Writes its own fault to stderr rather than returning an error, because
/// a `Plan` holds no place for the message.
///
/// **The `default` entry reaches every host, and that is what the netrc
/// format says it does. It is settled, and it is not a defect.** A
/// security review asked whether a `default login u password p` entry
/// should be held back from a host a redirect chose rather than a host the
/// user named. It should not, and this comment exists so the question is
/// not opened a third time.
///
/// Two reasons.
///
/// First, the format. `default` is defined as the entry that matches any
/// machine the earlier `machine` lines did not name. A user who writes a
/// complete `default` entry has instructed exactly the behaviour the
/// review asked to remove. A host-scoped `machine` entry is the way to say
/// the other thing, and `lib/zurl-core/netrc.zig` matches those by name
/// and never hands one host's entry to another.
///
/// Second, the measurement. Measured twice against curl 8.21.0, with two
/// loopback servers, where the first answers `302` to the second, and a
/// netrc holding one complete `default` entry:
///
/// ```
/// curl -L --netrc-file nrc URL1   the second server got
///                                 `Authorization: Basic dTpw`
/// zurl -L --netrc-file nrc URL1   the second server got no
///                                 `Authorization` at all
/// zurl    --netrc-file nrc URL2   the second server got
///                                 `Authorization: Basic dTpw`
/// ```
///
/// So zurl is already the stricter of the two. It sends the `default`
/// credential to the host the command line named, which is what the user
/// asked for, and drops it on the redirect, because
/// `Transfer.Options.location_trusted` is false by default and
/// `zurl.Client` clears the credential on the hop. curl sends it on.
///
/// Changing zurl here would tighten nothing that is still loose and would
/// break the one case that works. No behaviour changed for this finding.
fn loadNetrc(ctx: Context, plan: *Args.Plan) (Allocator.Error || Io.Writer.Error)!?u8 {
    if (plan.netrc_path) |path| {
        const text = Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(max_netrc_bytes)) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.StreamTooLong => {
                try ctx.stderr.print(
                    "zurl: --netrc-file: '{f}' is larger than the {d} byte limit\n",
                    .{ safe.text(path), max_netrc_bytes },
                );
                try ctx.stderr.writeAll(report.help_hint);
                return usage_error_code;
            },
            else => {
                try ctx.stderr.print("zurl: --netrc-file: cannot read '{f}'\n", .{safe.text(path)});
                try ctx.stderr.writeAll(report.help_hint);
                return usage_error_code;
            },
        };
        plan.options.netrc_text = text;
        return null;
    }

    switch (plan.netrc_mode) {
        .off => return null,
        .required, .optional => {},
    }

    const path = try defaultNetrcPath(ctx) orelse {
        // No candidate path exists at all, which is what an environment
        // with no `HOME` and no `NETRC` gives. There is nothing to read,
        // so the answer is the same as a file that is not there.
        if (plan.netrc_mode == .optional) return null;
        // Under the same `-s` and `-S` rule every transfer fault follows.
        // This is a transfer fault to curl, and not a usage fault:
        // measured, `curl -s --netrc URL` with no default file prints
        // nothing and still exits 26, where `curl -s --netrc-file /nope/x
        // URL` does print, because that one is a usage fault.
        if (!plan.silent or plan.show_error)
            try ctx.stderr.writeAll("zurl: --netrc: no netrc file to read: neither NETRC nor HOME is set\n");
        return netrc_read_error_code;
    };

    const text = Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(max_netrc_bytes)) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        // The bound is the same one `--netrc-file` holds, and a file past
        // it is refused rather than read in part. A netrc read in part
        // could drop the very entry the transfer needs and say nothing.
        error.StreamTooLong => {
            if (!plan.silent or plan.show_error) try ctx.stderr.print(
                "zurl: --netrc: '{f}' is larger than the {d} byte limit\n",
                .{ safe.text(path), max_netrc_bytes },
            );
            return netrc_read_error_code;
        },
        else => {
            // **The optional flag stops here, and it stops silently.**
            // A default file that is not there is the ordinary case for
            // `--netrc-optional`, not a recovery: nothing was dropped,
            // because there was nothing to drop.
            if (plan.netrc_mode == .optional) return null;
            if (!plan.silent or plan.show_error)
                try ctx.stderr.print("zurl: --netrc: cannot read '{f}'\n", .{safe.text(path)});
            return netrc_read_error_code;
        },
    };

    plan.options.netrc_text = text;
    return null;
}

/// The default netrc file's path, or null when the environment names none.
///
/// `NETRC` comes first and `$HOME/.netrc` second. Measured against curl
/// 8.21.0: with both set, and a different `login` in each file, the
/// `Authorization` header on the wire carried the user from the file
/// `NETRC` named. An empty `NETRC` names no file and reads as unset,
/// which is the rule `envPath` already holds for every other path this
/// program takes from the environment.
///
/// curl has one more candidate, `%USERPROFILE%`, which is for Windows
/// alone. zurl adds it when it grows a Windows build.
fn defaultNetrcPath(ctx: Context) Allocator.Error!?[]const u8 {
    if (ctx.env.get("NETRC")) |named| {
        if (named.len > 0) return named;
    }
    const home = ctx.env.get("HOME") orelse return null;
    if (home.len == 0) return null;
    return try std.fmt.allocPrint(ctx.arena, "{s}/.netrc", .{home});
}

fn printVersion(w: *Io.Writer) !void {
    try w.print("zurl {f}\n", .{zurl_core.version});
}

const build_options = @import("build_options");
const testing = std.testing;

/// `src/cli/run.zig` owns the `-O` name rule now, so the shipped binary
/// reaches `output` only through that file. The `-O` tests below still name
/// `output.fallback_name`, so the import stands in the test section alone.
const output = @import("cli/output.zig");
/// The progress meter's own shape. The tests below read its header and its
/// row width, and the shipped binary reaches it through `src/cli/run.zig`.
const progress = @import("cli/progress.zig");

/// The fixtures that spawn the installed binary and point it at a loopback
/// server. `src/cli/e2e_test.zig` shares the same file, so the two suites
/// run the same binary in the same environment.
const harness = @import("cli/testing.zig");

test {
    // **The reference that puts each CLI file's own tests in the run.**
    //
    // Zig collects a file's tests only when something the compiler
    // analyses names that file, and a test build analyses the tests and
    // whatever they reach, never `main`. So a file this binary imports
    // for its own work, and that no test here calls into, had its tests
    // silently skipped.
    //
    // `src/cli/help.zig` was exactly that: every test in it, including
    // the one that keeps the options block and the parser in step, was
    // written and never ran. The tests here reach `--help` by spawning
    // the binary, which is a subprocess and not a reference.
    //
    // One line for each file, so a file added later is one line away from
    // the same fault and a file already here cannot fall out of the run.
    _ = Args;
    _ = help;
    _ = output;
    _ = progress;
    _ = report;
    _ = run;
    _ = safe;
    _ = timecond;
    _ = writeout;
}

const test_server = harness.test_server;
const tls_test_server = harness.tls_test_server;
const runZurl = harness.runZurl;
const runZurlIn = harness.runZurlIn;
const loopbackUrl = harness.loopbackUrl;
const loopbackUrlAt = harness.loopbackUrlAt;
const loopbackTlsUrl = harness.loopbackTlsUrl;
const writeRootPem = harness.writeRootPem;
const afterMeter = harness.afterMeter;
const SandboxDir = harness.SandboxDir;
const closedPort = harness.closedPort;

/// The exit code curl gives a peer whose certificate failed to verify,
/// which is `CURLE_PEER_FAILED_VERIFICATION`.
const peer_failed_verification_code = 60;

test "the binary reports its version" {
    const result = try runZurl(&.{"--version"});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.startsWith(u8, result.stdout, "zurl "));

    var version_buf: [32]u8 = undefined;
    const version_text = try std.fmt.bufPrint(&version_buf, "{f}", .{zurl_core.version});
    try testing.expect(std.mem.indexOf(u8, result.stdout, version_text) != null);
}

test "the binary prints usage and exits non-zero with no arguments" {
    const result = try runZurl(&.{});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expect(result.stderr.len > 0);
}

test "an unknown flag names the flag and exits 2" {
    const result = try runZurl(&.{"--bogus-flag"});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--bogus-flag") != null);
}

test "--help lists the supported flags" {
    const result = try runZurl(&.{"--help"});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "--version") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "--help") != null);
    // The request body flags, and the one that is still a gap. `-F` is
    // named as accepted beside `-d`, and the sentence that called it a gap
    // must be gone, so a user reading this block learns what the build
    // really does.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-d, --data <data>") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-T, --upload-file <path>") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-F, --form <part>") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "--form-string <part>") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "--form-escape") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-F and --form are not accepted") == null);
    // IPv6 is no longer a gap, so the sentence that called it one must be
    // gone. A help text that refuses what the build does is worse than no
    // help at all. The gaps that remain around a host are named instead.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "No IPv6") == null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "underscored hostname") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "scope") != null);
    // The four flags this build now honours, each with both of the
    // spellings curl gives it. `src/cli/help.zig` renders these lines from
    // the same table the parser reads, so a spelling here is a spelling
    // `parse` accepts.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-o, --output <path>") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-O, --remote-name") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-D, --dump-header <path>") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-w, --write-out") != null);
    // -D is no longer named as a gap, so the sentence that refused it must
    // be gone too. A help text that still refuses a flag the build honours
    // is worse than no help at all. -w joined it in Task 8.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-D is refused") == null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-w is refused") == null);
    // -w has a limit of its own, and the help names it.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "http_code") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "65536") != null);
    // The meter joined the flags this build honours in Task 9, so the
    // sentence that refused it must be gone, and the flag must be listed.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "--progress-bar is refused") == null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "--progress-bar   ") != null);
    // -Z joined the flags this build honours in Task 10, so the sentence
    // that refused it must be gone, and the flag must be listed. The help
    // still names what -Z does differently from curl's own -Z.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-Z and --parallel are refused") == null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-Z, --parallel") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-Z draws no progress meter") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "-Z exits with the first failure") != null);
}

test "--version and --help still work" {
    // The two actions this binary answered before it could fetch anything.
    // A parser wired in ahead of them would turn both into
    // `error.UnknownFlag`, because `Args` knows neither flag.
    const version = try runZurl(&.{"--version"});
    defer testing.allocator.free(version.stdout);
    defer testing.allocator.free(version.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, version.term);
    try testing.expect(std.mem.startsWith(u8, version.stdout, "zurl "));

    // curl spells each of these two ways, `-V, --version` and
    // `-h, --help`, and zurl accepted only the long form of each. These
    // are the two flags no table drives, so each pair is checked here.
    const short_version = try runZurl(&.{"-V"});
    defer testing.allocator.free(short_version.stdout);
    defer testing.allocator.free(short_version.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, short_version.term);
    try testing.expectEqualStrings(version.stdout, short_version.stdout);

    // Not named `help`, because `src/cli/help.zig` already carries that
    // name in this file.
    const help_run = try runZurl(&.{"--help"});
    defer testing.allocator.free(help_run.stdout);
    defer testing.allocator.free(help_run.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, help_run.term);

    const short_help = try runZurl(&.{"-h"});
    defer testing.allocator.free(short_help.stdout);
    defer testing.allocator.free(short_help.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, short_help.term);
    try testing.expectEqualStrings(help_run.stdout, short_help.stdout);
    try testing.expect(std.mem.indexOf(u8, help_run.stdout, "Usage: zurl") != null);
}

test "a plain get writes the body to stdout and exits 0" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // **Standard output holds the body and nothing else.** The meter goes
    // to standard error, which is the whole reason it goes there. The two
    // streams are separate pipes here, so a meter byte that reached
    // standard output would show up in this one comparison.
    try testing.expectEqualStrings("payload", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));
}

test "the meter's rows carry the length the peer announced" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("payload", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));

    // The last row is the one the transfer ended on. It names the whole
    // seven bytes twice, at 100 percent, which is what curl writes for a
    // body it knew the length of.
    const rows = result.stderr[progress.header.len..];
    const last = rows[rows.len - 1 - progress.row_width .. rows.len - 1];
    try testing.expectEqualStrings("100      7 100      7", last[0..21]);
}

test "a body with no announced length draws the indeterminate row, not a false percentage" {
    // No `Content-Length` and no chunking, so the length arrives only when
    // the connection closes. This is the same shape a decoded body takes:
    // `zurl_stream.Progress` reports a total of zero, and the meter must
    // not divide by it.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("payload", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));

    const rows = result.stderr[progress.header.len..];
    const last = rows[rows.len - 1 - progress.row_width .. rows.len - 1];
    // curl fills the two "total" columns with what arrived and leaves
    // `% Received` at zero. The honest signal is the pair of blank time
    // columns, because zurl knows neither the whole time nor the time
    // left.
    try testing.expectEqualStrings("100      7   0      7", last[0..21]);
    try testing.expectEqualStrings("       ", last[47..54]);
    try testing.expectEqualStrings("       ", last[63..70]);
}

test "--progress-bar draws a bar on standard error, and the body still reaches standard output" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "--progress-bar", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("payload", result.stdout);

    // curl 8.21.0 writes no header for the bar. The whole of standard
    // error is one return, one row of `default_columns`, and a newline.
    // Nothing names COLUMNS here, and the tests run with no terminal, so
    // the fallback width answers.
    try testing.expectEqual(@as(usize, 2 + progress.default_columns), result.stderr.len);
    try testing.expectEqual(@as(u8, '\r'), result.stderr[0]);
    try testing.expect(std.mem.endsWith(u8, result.stderr, " 100.0%\n"));
}

test "-s draws no meter at all, and -S does not bring it back" {
    // Measured against curl 8.21.0: `-s` silences the meter, and `-S`
    // returns the failure message alone. Both shapes of meter go quiet.
    const cases = [_][]const []const u8{
        &.{"-s"},
        &.{ "-s", "-S" },
        &.{ "-s", "--progress-bar" },
        &.{ "-s", "-S", "--progress-bar" },
    };
    for (cases) |flags| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
        defer server.stop();

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(testing.allocator);
        try argv.appendSlice(testing.allocator, flags);
        try argv.append(testing.allocator, url);

        const result = try runZurl(argv.items);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("payload", result.stdout);
        try testing.expectEqualStrings("", result.stderr);
    }
}

test "a transfer that reached no server draws no meter, only the message" {
    // curl 8.21.0 prints one line for a refused connection and no meter
    // at all. The meter opens on the response, and there is none.
    const port = try closedPort();
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{port});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    try testing.expect(std.mem.startsWith(u8, result.stderr, "zurl: (7)"));
}

test "a failure message starts on a line of its own, after the meter" {
    // The meter's last row has no newline of its own until `finish`
    // writes one. Without it the message would land on the same line and
    // the row's own bytes would still be there.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 40\r\nConnection: close\r\n\r\nshort"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // The peer promised forty bytes and closed after five.
    try testing.expect(!std.meta.eql(std.process.Child.Term{ .exited = 0 }, result.term));
    const message = try afterMeter(result.stderr);
    try testing.expect(std.mem.startsWith(u8, message, "zurl: ("));
}

test "no message zurl writes carries a url password" {
    // **The enumeration behind the structural fix.** Every path below
    // ends in a line on standard error that can name a url. A password in
    // any one of them lands in a CI log, a systemd journal, or a shell
    // transcript.
    //
    // What makes the guarantee hold is not this list. It is
    // `zurl_core.Diagnostics`: there is no `url` field to assign, `record`
    // is the only writer, and `record` masks whatever text it is given, so
    // a path added after this test has nowhere to put an unmasked url.
    // `src/cli/safe.zig` is the second half, for the strings that never
    // pass through a `Diagnostics` at all.
    //
    // This list is what proves the guarantee reaches the user, path by
    // path. A row added here that leaks would mean the choke point was
    // bypassed, which is the failure this exists to catch.
    const secret = "hunter2";
    const cases = [_]struct { args: []const []const u8, why: []const u8 }{
        // `Client.perform` records the raw text on the url-parse fault.
        .{
            .args = &.{"http://alice:hunter2@127.0.0.1:not-a-port/x"},
            .why = "a url that does not parse",
        },
        // The same, on the protocol lookup.
        .{
            .args = &.{"rtmp://alice:hunter2@127.0.0.1:1935/x"},
            .why = "a scheme with no protocol",
        },
        // A connection that reaches nothing records the host alone.
        .{
            .args = &.{"http://alice:hunter2@127.0.0.1:1/x"},
            .why = "a refused connection",
        },
        // The `-O` refusal runs before any `Client` exists.
        .{
            .args = &.{ "-O", "http://alice:hunter2@127.0.0.1:1/dir/a\\b" },
            .why = "a -O name zurl will not write",
        },
        // A url in the wrong place still reaches a usage fault's sentence.
        .{
            .args = &.{ "--max-redirs", "http://alice:hunter2@127.0.0.1/x", "http://127.0.0.1:1/y" },
            .why = "a url given as a number",
        },
        .{
            .args = &.{ "-X", "http://alice:hunter2@127.0.0.1/x", "http://127.0.0.1:1/y" },
            .why = "a url given as a method",
        },
        .{
            .args = &.{"--http://alice:hunter2@127.0.0.1/x"},
            .why = "a url typed as a flag",
        },
        // `-w` writes the effective url to standard output, and its
        // unknown-variable line to standard error.
        .{
            .args = &.{ "-w", "%{bogus}", "http://alice:hunter2@127.0.0.1:1/x" },
            .why = "an unknown -w variable beside a password url",
        },
    };

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    for (cases) |case| {
        const result = try runZurlIn(sandbox.work, case.args);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        if (std.mem.indexOf(u8, result.stderr, secret) != null) {
            std.debug.print("the password reached stderr for {s}: {s}\n", .{ case.why, result.stderr });
            return error.TestUnexpectedResult;
        }
        // The url is masked, not dropped: a run with several urls has to
        // say which one failed. Wherever the line names the host, the
        // masked user survives beside it.
        if (std.mem.indexOf(u8, result.stderr, "alice:") != null) {
            try testing.expect(std.mem.indexOf(u8, result.stderr, "alice:***@") != null);
        }
    }
}

test "the last flush of standard output reports a fault instead of a stack trace" {
    // `main` used to let the final `flush` escape, so a standard output
    // that would not take the bytes gave a Zig stack trace and exit 1
    // where curl gives one sentence and its own exit code.
    //
    // `/dev/full` is the shape that reproduces it, and it is Linux's own
    // file, so this runs there alone. The shell puts it in front of the
    // child, which is what a user's own `> /dev/full` or a full disk does.
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nsmall",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nsmall",
    });
    defer server.stop();

    const url = try loopbackUrlAt(&server, "/x");
    defer testing.allocator.free(url);

    // A password in the url, because this is the path that leaked one.
    const with_password = try std.fmt.allocPrint(
        testing.allocator,
        "http://alice:hunter2@127.0.0.1:{d}/x",
        .{server.port()},
    );
    defer testing.allocator.free(with_password);

    for ([_][]const u8{ url, with_password }) |target| {
        const command = try std.fmt.allocPrint(
            testing.allocator,
            "{s} '{s}' > /dev/full",
            .{ build_options.exe_path, target },
        );
        defer testing.allocator.free(command);

        var empty_env: std.process.Environ.Map = .init(testing.allocator);
        defer empty_env.deinit();

        const result = try std.process.run(testing.allocator, testing.io, .{
            .argv = &.{ "/bin/sh", "-c", command },
            .environ_map = &empty_env,
        });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // 23 is `CURLE_WRITE_ERROR`, which is what curl 8.21.0 exits with
        // for the same command line.
        try testing.expectEqual(std.process.Child.Term{ .exited = 23 }, result.term);
        // One sentence, and no trace. A Zig trace names the source file.
        try testing.expect(std.mem.indexOf(u8, result.stderr, "WriteError") != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "src/main.zig") == null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "hunter2") == null);
    }
}

test "a transfer error exits with the curl code for that error" {
    // Nothing listens on this port, so the connect is refused.
    // `CURLE_COULDNT_CONNECT` is 7.
    const port = try closedPort();
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{port});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "(7)") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "CouldNotConnect") != null);
    // The host, so a run with several urls says which one failed. The
    // engine records no url of its own for a connect fault.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "127.0.0.1") != null);
}

test "a broken certificate directory still exits 7 on a plain http transfer" {
    // The fix from the previous commit: a certificate source zurl never
    // reads for a plain `http` url must not stop that transfer. `--capath`
    // gets no parse-time check, so this also proves that path reaches the
    // transfer rather than being refused as a usage fault.
    const port = try closedPort();
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{port});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "--capath", "/nonexistent/zurl-test-certs", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "(7)") != null);
}

test "a malformed url exits with the curl code for a malformed url" {
    // `CURLE_URL_MALFORMAT` is 3. This one needs no server at all: the
    // authority is empty, so `url.parse` refuses it.
    const result = try runZurl(&.{"http://"});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "(3)") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "InvalidUrl") != null);
}

test "a scheme with no protocol exits with the curl code for an unsupported protocol" {
    // `CURLE_UNSUPPORTED_PROTOCOL` is 1. The url names its port, so
    // `url.parse` needs no default for the scheme and the url parses. The
    // scheme lookup is what refuses it, and nothing connects.
    //
    // This url said `ftp` until zurl learned to speak it, then `smtp`,
    // then `ldap`, and each time zurl learned to speak the scheme the url
    // had to move on. The shape this test needs is a scheme that names its
    // own port and that no package registers. `rtmp` is one, and every
    // other `rtmp://` in this file is here for the same reason.
    //
    // curl 8.21.0 on this machine answers `rtmp://host.invalid/` with
    // exit 1 and `Protocol "rtmp" not supported`, measured, so the number
    // below is still the number curl gives the same shape.
    const result = try runZurl(&.{"rtmp://example.com:1935/file"});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "UnsupportedProtocol") != null);
}

test "-x on a protocol that carries no proxy is refused and never dials" {
    // **The control that failed open.** `-x socks5h://... ftp://host/f`
    // connected straight to the origin, and a user routing through Tor or
    // through the one permitted egress got a direct connection and no
    // diagnostic at all. `CURLE_NOT_BUILT_IN` is 4.
    //
    // Port 1 on loopback is closed, so a refusal that came too late would
    // show as exit 7 and not as exit 4. Nothing reaches the network here.
    const result = try runZurl(&.{
        "-x",
        "socks5h://127.0.0.1:9050",
        "ftp://127.0.0.1:1/file",
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 4 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "proxy") != null);

    // And `--noproxy` for that host runs the transfer, which then fails at
    // the closed port like any other direct dial.
    const excluded = try runZurl(&.{
        "-x",
        "socks5h://127.0.0.1:9050",
        "--noproxy",
        "127.0.0.1",
        "ftp://127.0.0.1:1/file",
    });
    defer testing.allocator.free(excluded.stdout);
    defer testing.allocator.free(excluded.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, excluded.term);
}

test "-u on smtp reaches the dial now, and the credential is still never echoed" {
    // **This test used to read the other way round**, and its two
    // assertions are inverted here rather than dropped, the way the `-Z`
    // test below inverts its own.
    //
    // The old claim: this package had no `AUTH` command, so `-u` was
    // refused by name with exit 4 rather than let the message go out with
    // no credential. That refusal was the right answer while the gap was
    // real, and SASL closes the gap: `zurl_smtp.Fetcher.authenticate`
    // sends the credential, and a login that fails still ends the
    // transfer before `MAIL FROM`. So `Fetcher.protocol` no longer names
    // `credentials` in its `unread` set, and the command line below now
    // runs a transfer.
    //
    // Port 1 accepts nothing, so the run reaches the dial and stops
    // there. That is what proves the refusal is gone: exit 7 says the
    // credential was carried far enough to open a socket, where exit 4
    // said it never left the argument parser.
    const result = try runZurl(&.{
        "-u",
        "alice:s3cret",
        "--mail-from",
        "a@b",
        "--mail-rcpt",
        "c@d",
        "-d",
        "hello",
        "smtp://127.0.0.1:1/",
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    // **The half of the old test that still holds, and it is the half
    // that matters.** No message this build writes carries the password,
    // whatever went wrong.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "s3cret") == null);
}

test "a usage fault names the problem and exits 2" {
    const missing_argument = try runZurl(&.{"--header"});
    defer testing.allocator.free(missing_argument.stdout);
    defer testing.allocator.free(missing_argument.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, missing_argument.term);
    try testing.expect(std.mem.indexOf(u8, missing_argument.stderr, "--header") != null);
    try testing.expect(std.mem.indexOf(u8, missing_argument.stderr, "needs an argument") != null);

    // A refusal `Args` raises after the whole walk, not at one token. It
    // must still reach stderr now that a parser sits between argv and the
    // transfer.
    //
    // This used to be `-X POST`, which the build refused for want of a
    // request body. The build sends one now, so that command line runs a
    // transfer and reaches the network, which no test may do. `-I -d` is
    // the refusal that took its place: curl 8.21.0 answers it with exit 2
    // and `You can only select one HTTP request method!`, and the parse
    // stops before any socket.
    const two_methods = try runZurl(&.{ "-I", "-d", "a=1", "http://example.com/" });
    defer testing.allocator.free(two_methods.stdout);
    defer testing.allocator.free(two_methods.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, two_methods.term);
    try testing.expect(std.mem.indexOf(u8, two_methods.stderr, "one HTTP request method") != null);
}

test "a flag with no url is a usage fault, not a silent success" {
    const result = try runZurl(&.{"-s"});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "no url") != null);
}

test "neither spelling of -Z is refused any more, and both reach the server" {
    // These two assertions used to read the other way round. `-Z` and
    // `--parallel` were the last two rows of a table of flags this build
    // refused at the command line, and one more test proved that the
    // refusal came before any network access. Task 10 makes both claims
    // false, so both are inverted here rather than dropped: the run must
    // not end with the usage code, and the transfer must really reach the
    // server.
    //
    // `-o` and `-O` left that table when Task 7 implemented them, `-D`
    // left it with the response head blocks, `-w` left it in Task 8, and
    // `--progress-bar` left it in Task 9. `-Z` is the last one, so the
    // table is empty and this test replaces it.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    for ([_][]const u8{ "-Z", "--parallel" }, 0..) |flag, index| {
        const result = try runZurl(&.{ flag, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("ok", result.stdout);
        try testing.expect(server.requestHead(index) != null);
    }
}

test "a -w format string past the bound is refused before it reaches a server" {
    // The one -w case that still ends the run early. curl 8.21.0 renders a
    // format string of any length, so this bound is zurl's own, and a user
    // must learn about it before a transfer runs rather than after.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const format = try testing.allocator.alloc(u8, writeout.max_format_bytes + 1);
    defer testing.allocator.free(format);
    @memset(format, 'x');

    const result = try runZurl(&.{ "-w", format, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "-w") != null);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "a -w format string at the bound is accepted and rendered" {
    // The boundary on the other side. One byte shorter than the refusal,
    // and the transfer runs.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const format = try testing.allocator.alloc(u8, writeout.max_format_bytes);
    defer testing.allocator.free(format);
    @memset(format, 'x');

    const result = try runZurlIn(sandbox.work, &.{ "-w", format, "-o", "out.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqual(writeout.max_format_bytes, result.stdout.len);
}

test "-w prints after the body on standard output" {
    // Measured against curl 8.21.0: with no -o the body reaches standard
    // output first, and the write-out follows it.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n" ++
            "Content-Length: 12\r\nConnection: close\r\n\r\nhello world\n",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-w", "[%{http_code} %{size_download} %{content_type}]", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings(
        "hello world\n[200 12 text/plain; charset=utf-8]",
        result.stdout,
    );
    try testing.expectEqualStrings("", try afterMeter(result.stderr));
}

test "-w with -o prints the format alone, because the body went to the file" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nhello world\n",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const result = try runZurlIn(sandbox.work, &.{ "-o", "body.txt", "-w", "%{size_download}", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The file holds the body, and standard output holds the format alone.
    try testing.expectEqualStrings("12", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));

    const written = try sandbox.work.readFileAlloc(testing.io, "body.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("hello world\n", written);
}

test "-w reports the url each transfer finished on, once for each url" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-w", "<%{http_code}:%{url_effective}>", url, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    const expected = try std.fmt.allocPrint(
        testing.allocator,
        "<200:{s}><404:{s}>",
        .{ url, url },
    );
    defer testing.allocator.free(expected);
    try testing.expectEqualStrings(expected, result.stdout);
}

test "-w after a failed transfer reports 000, and the exit code stays the transfer's" {
    // Measured against curl 8.21.0: a refused connection still prints the
    // format, with %{http_code} as 000, and the exit code stays 7.
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{try closedPort()});
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-w", "code=%{http_code} size=%{size_download}", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    try testing.expectEqualStrings("code=000 size=0", result.stdout);
}

test "-w with an unknown variable names it on standard error and still exits 0" {
    // The whole reason an unknown variable does not fail: a format string
    // is read after the transfer already worked.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-w", "A%{bogus_thing}B", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("okAB", result.stdout);
    // The line follows the meter, on a line of its own. The meter's own
    // newline is what puts it there.
    try testing.expectEqualStrings(
        "zurl: unknown --write-out variable: 'bogus_thing'\n",
        try afterMeter(result.stderr),
    );
}

test "-s does not hide the unknown-variable line, matching curl" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-s", "-w", "%{nope}", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("", result.stdout);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "'nope'") != null);
}

test "-w reports the size and a rate a real transfer could have had" {
    // The size is exact. The rate and the time come from a clock, so this
    // asserts the shape and the ordering they must hold, not a number.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const result = try runZurlIn(
        sandbox.work,
        &.{ "-o", "out.bin", "-w", "%{size_download}|%{time_total}|%{speed_download}", url },
    );
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    var parts = std.mem.splitScalar(u8, result.stdout, '|');
    try testing.expectEqualStrings("11", parts.first());

    // Seconds, a dot, then exactly six digits.
    const time = parts.next().?;
    const dot = std.mem.indexOfScalar(u8, time, '.').?;
    try testing.expectEqual(@as(usize, 6), time.len - dot - 1);
    try testing.expect(dot > 0);

    // A plain integer, with no dot of its own.
    const speed = parts.next().?;
    try testing.expect(speed.len > 0);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, speed, '.'));
    _ = try std.fmt.parseInt(u64, speed, 10);
    try testing.expectEqual(@as(?[]const u8, null), parts.next());
}

test "a second url is fetched after the first" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ url, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("firstsecond", result.stdout);
    try testing.expect(server.requestHead(1) != null);
}

test "a failing url does not stop the urls after it, and the last failure sets the exit code" {
    // curl 8.21.0 runs every url it was given and exits with the code of
    // the last transfer that failed. Checked against the real program.
    // Url 1 is malformed (3), url 2 succeeds, url 3 names a scheme with no
    // protocol (1). The run must reach url 2 and exit 1, not 3.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nmiddle"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "http://", url, "rtmp://example.com:1935/file" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try testing.expectEqualStrings("middle", result.stdout);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "InvalidUrl") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "UnsupportedProtocol") != null);
}

test "a success after a failure does not clear the failure's exit code" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "http://", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
    try testing.expectEqualStrings("ok", result.stdout);
}

test "-s hides the message for a failed transfer and keeps its exit code" {
    const result = try runZurl(&.{ "-s", "http://" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
    try testing.expectEqualStrings("", result.stderr);
}

test "-S with -s brings the message back" {
    const result = try runZurl(&.{ "-sS", "http://" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 3 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "InvalidUrl") != null);
}

test "a header from the command line reaches the wire" {
    // Proof that the parsed `Plan` really drives the transfer, and not
    // just the url out of it.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-H", "X-From: argv", "-A", "cli-agent/1", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "X-From: argv") != null);
    try testing.expect(std.mem.indexOf(u8, head, "cli-agent/1") != null);
}

test "--fail turns a 404 into the curl code for an http error" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nConnection: close\r\n\r\ngone!"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "--fail", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // `CURLE_HTTP_RETURNED_ERROR` is 22.
    try testing.expectEqual(std.process.Child.Term{ .exited = 22 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "status 404") != null);
}

test "a 404 without --fail writes the body and exits 0" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nConnection: close\r\n\r\ngone!"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("gone!", result.stdout);
}

test "a config file's options reach the transfer" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "zurl.conf",
        .data = "user-agent config-agent/1\n",
    });
    const config_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/zurl.conf",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(config_path);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-K", config_path, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "config-agent/1") != null);
}

test "--netrc-file supplies the credentials that reach the wire" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "netrc",
        .data = "machine 127.0.0.1 login alice password s3cret\n",
    });
    const netrc_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/netrc",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(netrc_path);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "--netrc-file", netrc_path, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(head));
}

test "a netrc token of 1200 characters authenticates, and never reaches the output" {
    // The bug the repo owner hit. `--netrc-file /nix/var/determinate/netrc`
    // holds four machine lines with tokens of about this length, and zurl
    // answered `zurl: (3) InvalidUrl: cache.flakehub.com: NoSpaceLeft`
    // where curl exits 0.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    const token = "t" ** 1200;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const netrc_text = try std.fmt.allocPrint(
        testing.allocator,
        "machine 127.0.0.1 login cache password {s}\n",
        .{token},
    );
    defer testing.allocator.free(netrc_text);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "netrc", .data = netrc_text });
    const netrc_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/netrc",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(netrc_path);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "--netrc-file", netrc_path, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    // The credential arrived whole, in one header, as the base64 of
    // "cache:" and the whole token.
    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(head));

    const size = zurl_core.auth.basicValueSize(.{ .user = "cache", .password = token });
    const expected_buf = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(expected_buf);
    const expected = try zurl_core.auth.basicValue(expected_buf, .{ .user = "cache", .password = token });
    try testing.expect(std.mem.indexOf(u8, head, expected) != null);

    // The token went on the wire and nowhere else.
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, result.stdout, token));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, result.stderr, token));
}

test "a credential past the header line bound names its source and prints no secret" {
    // The url is well formed. Only the credential is too long, so the
    // message must say so and must not send the user to look at the url.
    const marker = "SUPERSECRETTOKENMARKER";
    const padding = try testing.allocator.alloc(u8, 128 * 1024);
    defer testing.allocator.free(padding);
    @memset(padding, 'x');

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const netrc_text = try std.fmt.allocPrint(
        testing.allocator,
        "machine 127.0.0.1 login cache password {s}{s}\n",
        .{ marker, padding },
    );
    defer testing.allocator.free(netrc_text);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "netrc", .data = netrc_text });
    const netrc_path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/netrc",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(netrc_path);

    const result = try runZurl(&.{ "--netrc-file", netrc_path, "http://127.0.0.1:1/" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // curl answers an over-long credential with
    // `CURLE_BAD_FUNCTION_ARGUMENT`, and not with the exit 3 that means a
    // malformed url.
    const credential_too_large_code: u8 = 43;
    try testing.expectEqual(std.process.Child.Term{ .exited = credential_too_large_code }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "CredentialTooLarge") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "the netrc file") != null);

    // Nothing printed holds the secret, or any piece of it.
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, result.stderr, marker));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, result.stderr, "xxxxxxxx"));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, result.stdout, marker));
}

test "a --netrc-file zurl cannot read is a usage fault naming the path" {
    // Silently dropping the file would send the request with no
    // credentials and fail later with a 401 that names no cause.
    const result = try runZurl(&.{ "--netrc-file", "/nonexistent-zurl-netrc", "http://example.com/" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "/nonexistent-zurl-netrc") != null);
}

test "--cacert naming a missing file exits 2, matching curl, before any network access" {
    // A real curl 8.21.0 run of `--cacert /nonexistent` exits 2, not 35,
    // because curl checks the file when it parses the flag, before any
    // transfer. `http://example.com/` proves the check runs first: were
    // it reached, the fault would be a connect or a transfer result, not
    // a usage fault.
    const result = try runZurl(&.{ "--cacert", "/nonexistent/zurl-test-ca.pem", "http://example.com/" });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = usage_error_code }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--cacert") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "/nonexistent/zurl-test-ca.pem") != null);
}

test "the exit code for every error fits in an exit status" {
    // `run.exitCodeFor` asserts this. A row added to `zurl_core.errors`
    // with a code above 255 would make that assertion fire in a real run,
    // so prove it here instead.
    inline for (@typeInfo(zurl_core.Error).error_set.?) |field| {
        const err = @field(zurl_core.Error, field.name);
        try testing.expectEqual(zurl_core.errors.curlCode(err), run.exitCodeFor(err));
    }
}

test "-o writes the body to the named path" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-o", "out.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The body went to the file and not to standard output as well.
    try testing.expectEqualStrings("", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));

    const contents = try sandbox.work.readFileAlloc(testing.io, "out.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "-O takes the name from the last url segment" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    // A query after the name is not part of it, and neither is a
    // directory before it.
    const url = try loopbackUrlAt(&server, "/downloads/archive.tar.gz?v=2");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-O", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("", result.stdout);

    const contents = try sandbox.work.readFileAlloc(
        testing.io,
        "archive.tar.gz",
        testing.allocator,
        .limited(64),
    );
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

/// Runs `zurl -O url` in a fresh sandbox and fails unless it exits with
/// the curl code for a write failure and writes no file anywhere.
///
/// The two refusal tests below share this. Each one names the shape it
/// covers, and this holds the verdict both must reach: exit 23, a
/// sentence naming `-O`, and an empty working directory *and* an empty
/// parent directory. A refusal that wrote one directory up would pass a
/// check that only looked at the working directory.
fn expectRefusedOutputName(url: []const u8) !void {
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const result = try runZurlIn(sandbox.work, &.{ "-O", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // `CURLE_WRITE_ERROR` is 23. curl 8.21.0 exits 23 for an `-o` path it
    // cannot open, which is the same class of fault: zurl has nowhere to
    // put the body.
    testing.expectEqual(std.process.Child.Term{ .exited = 23 }, result.term) catch |err| {
        std.debug.print("url '{s}' gave stderr: {s}\n", .{ url, result.stderr });
        return err;
    };
    try testing.expectEqualStrings("", result.stdout);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "-O") != null);
    try sandbox.expectNothingWritten();
}

test "-O still refuses a name that carries a raw path separator" {
    // A raw `/` cannot survive the cut into a last segment, so the shape
    // that reaches this check is the raw `\`: the separator on the other
    // platform zurl builds for. curl 8.21.0 does not write this byte
    // either, checked against the real program: it treats a raw `\` as
    // another place to cut, the same as `/`, and writes `b` here rather
    // than a name that carries one. zurl instead refuses the whole name,
    // which is stricter than curl but never lets a `\` reach a file zurl
    // writes.
    try expectRefusedOutputName("http://example.com/dir/a\\b");
}

test "-O refuses a name longer than the bound, rather than letting the syscall decide" {
    // curl 8.21.0 refuses a name this long too, checked against the real
    // program: it exits 23 for the same command line. zurl's own bound
    // does not have to match curl's number, only stay on the same side
    // of it, so this proves zurl has one, not that the two agree on where
    // it sits.
    var url_buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&url_buf);
    try w.writeAll("http://example.com/");
    try w.splatByteAll('x', 256);

    try expectRefusedOutputName(w.buffered());
}

/// Runs `zurl -O url` against a fresh loopback server and fails unless it
/// writes `body` under `want_name`, exits 0, and leaves the parent
/// directory untouched.
///
/// `-O` reaches the network for every case this helper covers, unlike
/// `expectRefusedOutputName`'s cases: a name that survives `checkName`
/// only stops looking like a fault once the file is actually on disk.
fn expectOutputName(path: []const u8, want_name: []const u8) !void {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrlAt(&server, path);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-O", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term) catch |err| {
        std.debug.print("path '{s}' gave stderr: {s}\n", .{ path, result.stderr });
        return err;
    };
    try testing.expectEqualStrings("", result.stdout);

    const contents = sandbox.work.readFileAlloc(testing.io, want_name, testing.allocator, .limited(64)) catch |err| {
        std.debug.print("path '{s}' did not write '{s}'\n", .{ path, want_name });
        return err;
    };
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "-O falls back to curl's own name when the url's last segment names nothing" {
    // Every path here writes `curl_response` and exits 0 on curl 8.21.0,
    // checked against the real program in an empty directory.
    try expectOutputName("/", output.fallback_name);
    try expectOutputName("", output.fallback_name);
    try expectOutputName("/a/..", output.fallback_name);
    try expectOutputName("/a/%2e%2e", output.fallback_name);
    try expectOutputName("/a/%2E%2E", output.fallback_name);
    try expectOutputName("/a/.%2e", output.fallback_name);

    // `/dir/` and `/a/.` are the two shapes where zurl's answer is not
    // curl's: curl 8.21.0 walks back past the empty or `.` segment and
    // writes `dir` or `a`. `checkName` never looks past the last segment,
    // so both fall back here instead. See `output.zig`'s own doc comment.
    try expectOutputName("/dir/", output.fallback_name);
    try expectOutputName("/a/.", output.fallback_name);
}

test "-O writes curl's escaped names literally, never decoding a % into a path" {
    // curl 8.21.0 never decodes a `-O` name before it writes it, checked
    // against the real program for every row here. A name that would
    // decode to a path, an absolute path, or a byte no terminal can show
    // stays the literal, still-escaped text curl itself writes.
    try expectOutputName("/%2e%2e%2fpwned", "%2e%2e%2fpwned");
    try expectOutputName("/a%2fb", "a%2fb");
    try expectOutputName("/a%2Fb", "a%2Fb");
    try expectOutputName("/%2fetc%2fpasswd", "%2fetc%2fpasswd");
    try expectOutputName("/dir/%2e%2e%2f%2e%2e%2fetc", "%2e%2e%2f%2e%2e%2fetc");
    // The escaped separator zurl still refuses as a raw byte, `%5c`,
    // reaches this rule as a literal name instead: it is three ASCII
    // characters, `%`, `5`, `c`, and never the byte 0x5C.
    try expectOutputName("/dir/a%5cb", "a%5cb");
    // A NUL, a CR, and a DEL, all escaped. None of them is the byte it
    // names once nothing decodes the name: the six characters `%`, `0`,
    // `0` and so on are what `open` gets.
    try expectOutputName("/a%00b", "a%00b");
    try expectOutputName("/a%0db", "a%0db");
    try expectOutputName("/a%7fb", "a%7fb");
    // A `%` that does not decode is still a literal name, not a fault.
    try expectOutputName("/100%", "100%");
    try expectOutputName("/a%zzb", "a%zzb");
}

test "-O accepts the awkward names that are still one file" {
    // The other half of the rule. A name that looks odd but stays one new
    // entry in the working directory must be written, not refused: a rule
    // that refuses too much sends users back to `-o` for ordinary urls.
    // Only `.` and `..` name an entry that already exists.
    try expectOutputName("/...", "...");
    // A hidden file is one entry like any other.
    try expectOutputName("/.config", ".config");
    // zurl never hands the name to a shell, so a leading dash is just a
    // byte. curl writes this name too.
    try expectOutputName("/-rf", "-rf");
    // `%20` decodes to a space, which is safe, and zurl writes the
    // escaped form exactly as curl 8.21.0 does.
    try expectOutputName("/a%20b", "a%20b");
}

test "-O with -L takes the name from the command line, never from a Location header" {
    // **The phase's headline safety property.** `output.nameFromUrl` runs
    // on the url the user typed, before `client.perform`, so a peer
    // cannot choose the file zurl writes. Every other `-O` test points at
    // a url that answers 200 on the first hop, so none of them would
    // notice if the name moved after `perform` to read the effective url
    // or a `Content-Disposition`, which is a plausible feature request.
    //
    // The first hop is a 302 whose `Location` names a hostile last
    // segment: escaped `../../etc/passwd`. A run that took the name from
    // the redirect would write `%2e%2e%2f%2e%2e%2fetc%2fpasswd`, or,
    // worse, a decoded path outside the working directory.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /%2e%2e%2f%2e%2e%2fetc%2fpasswd\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\narrived",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrlAt(&server, "/wanted.bin");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-O", "-L", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    // The name comes from the command line's own last segment.
    const written = try sandbox.work.readFileAlloc(testing.io, "wanted.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("arrived", written);

    // And the run wrote nothing else, in the working directory or beside
    // it. The second check is the one that matters: a decoded name would
    // have climbed out of `work`.
    var work_it = sandbox.work.iterate();
    while (try work_it.next(testing.io)) |entry| {
        try testing.expectEqualStrings("wanted.bin", entry.name);
    }
    var root_it = sandbox.root.iterate();
    while (try root_it.next(testing.io)) |entry| {
        try testing.expectEqualStrings("work", entry.name);
    }
}

test "-O with -L is not saved by the name rule when the redirect target is a refused shape" {
    // The mirror of the test above. Here the command line's own name is
    // fine and the redirect target's last segment is one `-O` refuses, a
    // raw path separator. The refusal rule must not fire, because the
    // rule never looks at the redirect at all: the file keeps the name
    // the command line gave and the run exits 0.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /dir/inner.bin\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\ninner",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrlAt(&server, "/outer.bin");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-O", "-L", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const written = try sandbox.work.readFileAlloc(testing.io, "outer.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("inner", written);

    try testing.expectError(error.FileNotFound, sandbox.work.access(testing.io, "inner.bin", .{}));
}

test "a refused -O stops the url before it reaches a server" {
    // The same rule the refused flags follow. A name zurl will not write
    // is decided from the url alone, so nothing needs fetching to learn
    // it, and a body that has nowhere to go must never be asked for.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrlAt(&server, "/dir/a\\b");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-O", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 23 }, result.term);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
    try sandbox.expectNothingWritten();
}

test "-O writes one file for each url, and a refused name does not stop the rest" {
    // `run.transfers` runs every url and keeps the last failing code. A
    // refused name has to behave the same way as any other transfer
    // fault, and each url gets the name its own path holds.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const first = try loopbackUrlAt(&server, "/one.bin");
    defer testing.allocator.free(first);
    const refused = try loopbackUrlAt(&server, "/dir/a\\b");
    defer testing.allocator.free(refused);
    const second = try loopbackUrlAt(&server, "/two.bin");
    defer testing.allocator.free(second);

    // One `-O` for each url. curl 8.21.0 pairs the output list with the
    // url list, so a single `-O` covers the first url only and the rest
    // go to standard output. Measured: `curl -O URL1 URL2` wrote URL1 to
    // its own name and URL2 to standard output.
    const result = try runZurlIn(sandbox.work, &.{ "-O", "-O", "-O", first, refused, second });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 23 }, result.term);

    const one = try sandbox.work.readFileAlloc(testing.io, "one.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("first", one);

    const two = try sandbox.work.readFileAlloc(testing.io, "two.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(two);
    try testing.expectEqualStrings("second", two);

    // Nothing escaped, even though the run went on past the refusal.
    var root_it = sandbox.root.iterate();
    while (try root_it.next(testing.io)) |entry| {
        try testing.expectEqualStrings("work", entry.name);
    }
}

test "-O prints a note to stderr when it invents the name, and nothing when it does not" {
    // IronStyle: recovery is never silent. curl 8.21.0 invents
    // `curl_response` with no word to the user; zurl says so on stderr,
    // while keeping the exit code, the file, and standard output equal to
    // curl's, which is the one thing this file's own doc comment asks a
    // note here to preserve.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, "/");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-O", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "curl_response") != null);
    }
    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, "/file.bin");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-O", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        // The meter, and no note after it. A url that named its own file
        // earns no note.
        try testing.expectEqualStrings("", try afterMeter(result.stderr));
    }
}

test "-O never writes outside the working directory, for any hostile shape" {
    // The property that matters most, and the one meant to survive any
    // later change to the naming rule. Every shape below has, at some
    // point in this file's history, decoded to a path that leaves the
    // working directory. Whatever a shape resolves to today, refused,
    // curl's own invented name, or a literal escaped name, the run below
    // proves it stayed inside the sandbox: the parent directory holds
    // nothing but the sandbox's own working directory, and the working
    // directory holds nothing but plain files.
    const hostile_paths = [_][]const u8{
        // Names nothing: fall back today.
        "/",
        "",
        "/dir/",
        "/..",
        "/a/..",
        "/a/.",
        "/%2e%2e",
        "/%2E%2E",
        "/.%2e",
        "/%2e.",
        // Decode to a path or an absolute path: written literally today.
        "/%2e%2e%2fpwned",
        "/a%2fb",
        "/a%2Fb",
        "/%2fetc%2fpasswd",
        "/dir/%2e%2e%2f%2e%2e%2fetc",
        // Decode to a byte no name may carry: written literally today,
        // because the escape never becomes the byte.
        "/a%00b",
        "/a%0db",
        "/a%7fb",
        // A raw separator: refused today.
        "/dir/a\\b",
    };

    for (hostile_paths) |path| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"});
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, path);
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-O", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // Every run either exits 0 with a file written, or exits 23 with
        // none. Nothing else this test does depends on which, but the
        // term must be a plain exit: a run that instead crashed is its
        // own bug and must not read as a quiet pass here.
        const code = switch (result.term) {
            .exited => |code| code,
            else => {
                std.debug.print("path '{s}' did not exit cleanly\n", .{path});
                return error.TestUnexpectedResult;
            },
        };
        if (code != 0 and code != 23) {
            std.debug.print("path '{s}' exited {d}, neither 0 nor 23\n", .{ path, code });
            return error.TestUnexpectedResult;
        }

        var root_it = sandbox.root.iterate();
        while (try root_it.next(testing.io)) |entry| {
            if (!std.mem.eql(u8, entry.name, "work")) {
                std.debug.print("path '{s}' let a run write '{s}' into the parent directory\n", .{ path, entry.name });
                return error.TestUnexpectedResult;
            }
        }

        var work_it = sandbox.work.iterate();
        while (try work_it.next(testing.io)) |entry| {
            if (entry.kind != .file) {
                std.debug.print(
                    "path '{s}' wrote '{s}' as a {s}, not a file\n",
                    .{ path, entry.name, @tagName(entry.kind) },
                );
                return error.TestUnexpectedResult;
            }
        }
    }
}

test "-J never writes outside the working directory, for any hostile header" {
    // **The `-J` half of the property above, and the more important
    // half.** A `-O` name comes from a url a person typed. A `-J` name is
    // written by the server, so every byte of it is the peer's choice, and
    // the shapes below are the ones a peer would send to reach a file zurl
    // was never asked to write.
    //
    // The run below proves the same thing for each: the parent directory
    // holds nothing but the sandbox's own working directory, and the
    // working directory holds nothing but plain files. Whatever a shape
    // resolves to, a name cut back to one segment, a refusal, or the url's
    // own name, nothing left the sandbox.
    const hostile_headers = [_][]const u8{
        // A path, in every spelling a server may write it.
        "attachment; filename=\"../../escaped.txt\"",
        "attachment; filename=\"../escaped.txt\"",
        "attachment; filename=\"/tmp/zurl-j-escape.txt\"",
        "attachment; filename=\"/etc/zurl-j-escape\"",
        "attachment; filename=\"..\\..\\escaped.txt\"",
        "attachment; filename=\"a/../../escaped.txt\"",
        "attachment; filename=../../escaped.txt",
        "attachment; filename=/tmp/zurl-j-escape.txt",
        // A path that leaves nothing behind the last separator.
        "attachment; filename=\"dir/\"",
        "attachment; filename=\"/\"",
        "attachment; filename=\"\\\\\"",
        // Names of an entry that already exists.
        "attachment; filename=\".\"",
        "attachment; filename=\"..\"",
        "attachment; filename=\"\"",
        // Escapes, which zurl never decodes, so none of them becomes a
        // separator on the way to `open`.
        "attachment; filename=\"%2e%2e%2fescaped.txt\"",
        "attachment; filename=\"%2f%2fetc%2fpasswd\"",
        // Bytes a name may not carry. Each is refused.
        "attachment; filename=\"a\tb.txt\"",
        "attachment; filename=\"a\x1b[2Kb.txt\"",
        "attachment; filename=\"a\x7fb.txt\"",
        // Past the length bound.
        "attachment; filename=\"" ++ "x" ** 400 ++ "\"",
        // Shapes with no `filename=` at all, which keep the url's name.
        "attachment",
        "inline",
        "attachment; filename*=UTF-8''escaped.txt",
        "attachment; FILENAME=\"../../escaped.txt\"",
    };

    for (hostile_headers) |disposition| {
        var server: test_server.TestServer = undefined;
        const response = try std.fmt.allocPrint(
            testing.allocator,
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Disposition: {s}\r\n" ++
                "Connection: close\r\n\r\nbody",
            .{disposition},
        );
        defer testing.allocator.free(response);
        try server.start(&.{response});
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, "/wanted.bin");
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-O", "-J", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // Either the run wrote a file and exited 0, or it refused the
        // name and exited 23. Nothing else, and never a crash: a run that
        // faulted is its own bug and must not read as a quiet pass.
        const code = switch (result.term) {
            .exited => |code| code,
            else => {
                std.debug.print("header '{s}' did not exit cleanly\n", .{disposition});
                return error.TestUnexpectedResult;
            },
        };
        if (code != 0 and code != 23) {
            std.debug.print("header '{s}' exited {d}, neither 0 nor 23\n", .{ disposition, code });
            return error.TestUnexpectedResult;
        }

        var root_it = sandbox.root.iterate();
        while (try root_it.next(testing.io)) |entry| {
            if (!std.mem.eql(u8, entry.name, "work")) {
                std.debug.print(
                    "header '{s}' let a run write '{s}' into the parent directory\n",
                    .{ disposition, entry.name },
                );
                return error.TestUnexpectedResult;
            }
        }

        var work_it = sandbox.work.iterate();
        while (try work_it.next(testing.io)) |entry| {
            if (entry.kind != .file) {
                std.debug.print(
                    "header '{s}' wrote '{s}' as a {s}, not a file\n",
                    .{ disposition, entry.name, @tagName(entry.kind) },
                );
                return error.TestUnexpectedResult;
            }
            // And the name itself is one entry, never a path. This is
            // what `output.checkName` promises, checked on the real file
            // the real binary created.
            if (std.mem.indexOfAny(u8, entry.name, "/\\") != null) {
                std.debug.print(
                    "header '{s}' wrote the name '{s}', which is a path\n",
                    .{ disposition, entry.name },
                );
                return error.TestUnexpectedResult;
            }
        }
    }

    // The two absolute paths above named real places outside any sandbox.
    // Neither may exist, whatever the loop found in its own directories.
    try testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().access(testing.io, "/tmp/zurl-j-escape.txt", .{}),
    );
    try testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().access(testing.io, "/etc/zurl-j-escape", .{}),
    );
}

test "-J takes the name from the header and -O keeps the url's own" {
    // The behaviour the flag exists for, beside the refusals above.
    // Measured against curl 8.21.0: the same response wrote `hello.txt`
    // under `-OJ` and `from-url.bin` under `-O` alone.
    inline for (.{
        .{ &[_][]const u8{ "-O", "-J" }, "hello.txt" },
        .{ &[_][]const u8{"-O"}, "from-url.bin" },
    }) |shape| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{
            "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n" ++
                "Content-Disposition: attachment; filename=\"hello.txt\"\r\n" ++
                "Connection: close\r\n\r\npayload",
        });
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, "/from-url.bin");
        defer testing.allocator.free(url);

        var argv: [3][]const u8 = undefined;
        var argv_len: usize = 0;
        for (shape[0]) |flag| {
            argv[argv_len] = flag;
            argv_len += 1;
        }
        argv[argv_len] = url;
        argv_len += 1;

        const result = try runZurlIn(sandbox.work, argv[0..argv_len]);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        const written = try sandbox.work.readFileAlloc(testing.io, shape[1], testing.allocator, .limited(64));
        defer testing.allocator.free(written);
        try testing.expectEqualStrings("payload", written);

        // And exactly one file, so the other name was never written too.
        var it = sandbox.work.iterate();
        var count: usize = 0;
        while (try it.next(testing.io)) |entry| {
            try testing.expectEqualStrings(shape[1], entry.name);
            count += 1;
        }
        try testing.expectEqual(@as(usize, 1), count);
    }
}

test "-J reads no url that -O does not cover" {
    // Measured against curl 8.21.0: `-J` with no `-O` wrote the body to
    // standard output, and `-J -o named` wrote `named`. The flag names
    // where a `-O` name comes from and nothing else.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n" ++
            "Content-Disposition: attachment; filename=\"hello.txt\"\r\n" ++
            "Connection: close\r\n\r\npayload",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n" ++
            "Content-Disposition: attachment; filename=\"hello.txt\"\r\n" ++
            "Connection: close\r\n\r\npayload",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrlAt(&server, "/from-url.bin");
    defer testing.allocator.free(url);

    // `-J` alone: the body reaches standard output and no file appears.
    const bare = try runZurlIn(sandbox.work, &.{ "-J", url });
    defer testing.allocator.free(bare.stdout);
    defer testing.allocator.free(bare.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, bare.term);
    try testing.expectEqualStrings("payload", bare.stdout);
    try sandbox.expectNothingWritten();

    // `-J -o named`: the `-o` path wins and the header is not read.
    const named = try runZurlIn(sandbox.work, &.{ "-J", "-o", "named.bin", url });
    defer testing.allocator.free(named.stdout);
    defer testing.allocator.free(named.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, named.term);

    const written = try sandbox.work.readFileAlloc(testing.io, "named.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("payload", written);
    try testing.expectError(error.FileNotFound, sandbox.work.access(testing.io, "hello.txt", .{}));
}

test "-J never overwrites a file that is already there" {
    // **The rule that keeps a server from replacing a file it can name.**
    // Measured against curl 8.21.0: `-OJ` onto a directory already
    // holding the header's name exits 23 and leaves the old bytes alone.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n" ++
            "Content-Disposition: attachment; filename=\"hello.txt\"\r\n" ++
            "Connection: close\r\n\r\npayload",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n" ++
            "Content-Disposition: attachment; filename=\"hello.txt\"\r\n" ++
            "Connection: close\r\n\r\npayload",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "hello.txt", .data = "mine" });

    const url = try loopbackUrlAt(&server, "/from-url.bin");
    defer testing.allocator.free(url);

    const refused = try runZurlIn(sandbox.work, &.{ "-O", "-J", url });
    defer testing.allocator.free(refused.stdout);
    defer testing.allocator.free(refused.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 23 }, refused.term);

    const kept = try sandbox.work.readFileAlloc(testing.io, "hello.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("mine", kept);

    // **`--no-clobber` outranks it**, and writes the next free name
    // instead of failing the url. Measured: curl wrote `cd.txt.1` for
    // that pair and exited 0.
    const suffixed = try runZurlIn(sandbox.work, &.{ "-O", "-J", "--no-clobber", url });
    defer testing.allocator.free(suffixed.stdout);
    defer testing.allocator.free(suffixed.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, suffixed.term);

    const still_mine = try sandbox.work.readFileAlloc(testing.io, "hello.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(still_mine);
    try testing.expectEqualStrings("mine", still_mine);

    const written = try sandbox.work.readFileAlloc(testing.io, "hello.txt.1", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("payload", written);
}

test "--output-dir puts a -O and a -J name under the directory and nowhere else" {
    // Measured against curl 8.21.0, with `sub` already there:
    // `--output-dir sub -O` wrote `sub/from-url.bin`, and
    // `--output-dir sub -OJ` wrote `sub/cd.txt`. The flag moves the file
    // and never the name, whichever flag chose the name.
    inline for (.{
        .{ &[_][]const u8{"-O"}, "from-url.bin" },
        .{ &[_][]const u8{ "-O", "-J" }, "hello.txt" },
    }) |shape| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{
            "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n" ++
                "Content-Disposition: attachment; filename=\"hello.txt\"\r\n" ++
                "Connection: close\r\n\r\npayload",
        });
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrlAt(&server, "/from-url.bin");
        defer testing.allocator.free(url);

        // Three fixed flags, at most two from `shape`, and the url.
        var argv: [6][]const u8 = undefined;
        var argv_len: usize = 0;
        argv[argv_len] = "--output-dir";
        argv_len += 1;
        argv[argv_len] = "sub";
        argv_len += 1;
        argv[argv_len] = "--create-dirs";
        argv_len += 1;
        for (shape[0]) |flag| {
            argv[argv_len] = flag;
            argv_len += 1;
        }
        argv[argv_len] = url;
        argv_len += 1;

        const result = try runZurlIn(sandbox.work, argv[0..argv_len]);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        const path = try std.fmt.allocPrint(testing.allocator, "sub/{s}", .{shape[1]});
        defer testing.allocator.free(path);
        const written = try sandbox.work.readFileAlloc(testing.io, path, testing.allocator, .limited(64));
        defer testing.allocator.free(written);
        try testing.expectEqualStrings("payload", written);

        // The working directory itself holds nothing but `sub`, so the
        // name never landed twice.
        var it = sandbox.work.iterate();
        while (try it.next(testing.io)) |entry| {
            try testing.expectEqualStrings("sub", entry.name);
        }
    }
}

test "--etag-save and --etag-compare round trip through one file" {
    // **The property the pair exists for**, and the measurement behind
    // every byte of it. curl 8.21.0 wrote `"abc123"\n` into the file and
    // then sent `If-None-Match: "abc123"` off the back of it. zurl writes
    // and sends the same, so a file either program wrote is a file either
    // program reads.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"abc123\"\r\n" ++
            "Connection: close\r\n\r\nfirst",
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n" ++
            "Connection: close\r\n\r\n",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const saved = try runZurlIn(sandbox.work, &.{ "--etag-save", "tag.txt", "-o", "a.bin", url });
    defer testing.allocator.free(saved.stdout);
    defer testing.allocator.free(saved.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, saved.term);

    const tag = try sandbox.work.readFileAlloc(testing.io, "tag.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(tag);
    try testing.expectEqualStrings("\"abc123\"\n", tag);

    const compared = try runZurlIn(sandbox.work, &.{ "--etag-compare", "tag.txt", "-o", "b.bin", url });
    defer testing.allocator.free(compared.stdout);
    defer testing.allocator.free(compared.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, compared.term);

    // The newline the file ends in never reaches the wire: one there
    // would end the header line and let the rest read as more headers.
    try testing.expect(std.mem.indexOf(
        u8,
        server.requestHead(1).?,
        "If-None-Match: \"abc123\"\r\n",
    ) != null);
}

test "--etag-compare sends two quotes when it has no tag, and costs no exit code" {
    // Measured against curl 8.21.0: a `--etag-compare` naming a file that
    // is not there still put `If-None-Match: ""` on the wire, printed one
    // warning, and exited 0.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "--etag-compare", "missing.txt", "-o", "a.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "If-None-Match: \"\"\r\n") != null);
    // Recovery is never silent, so the missing file reaches stderr.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "--etag-compare") != null);
}

test "--etag-save leaves the file empty when the response carried no tag" {
    // curl creates the file there too, measured. A tag from an earlier
    // run left in place would claim a version the server never sent.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "tag.txt", .data = "\"stale\"\n" });

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "--etag-save", "tag.txt", "-o", "a.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const tag = try sandbox.work.readFileAlloc(testing.io, "tag.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(tag);
    try testing.expectEqualStrings("", tag);
}

test "-z sends the header curl sends, in both directions" {
    // Every line below was checked against curl 8.21.0 with a loopback
    // server, and curl put the same bytes on the wire.
    const cases = [_]struct { argument: []const u8, line: []const u8 }{
        .{
            .argument = "Wed, 21 Oct 2015 07:28:00 GMT",
            .line = "If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
        },
        .{
            .argument = "+21 Oct 2015 07:28:00 GMT",
            .line = "If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
        },
        .{
            .argument = "-21 Oct 2015 07:28:00 GMT",
            .line = "If-Unmodified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
        },
        // A shape the user typed one way and the wire carries another.
        .{
            .argument = "19941106 08:49:37",
            .line = "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
        },
    };

    for (cases) |case| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const url = try loopbackUrl(&server);
        defer testing.allocator.free(url);

        const result = try runZurlIn(sandbox.work, &.{ "-z", case.argument, "-o", "a.bin", url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

        if (std.mem.indexOf(u8, server.requestHead(0).?, case.line) == null) {
            std.debug.print("-z '{s}' did not send '{s}'\n", .{ case.argument, case.line });
            return error.TestUnexpectedResult;
        }
    }
}

test "-z reads a file's own time, and a = prefix sends no header on http" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    // A file with a time this test set, so the header it produces is
    // known. curl reads the same stamp for the same file.
    const stamped = try sandbox.work.createFile(testing.io, "stamp.bin", .{});
    stamped.setTimestamps(testing.io, .{
        .modify_timestamp = .{ .new = .{ .nanoseconds = 1445412480 * std.time.ns_per_s } },
    }) catch {};
    stamped.close(testing.io);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const forward = try runZurlIn(sandbox.work, &.{ "-z", "stamp.bin", "-o", "a.bin", url });
    defer testing.allocator.free(forward.stdout);
    defer testing.allocator.free(forward.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, forward.term);
    try testing.expect(std.mem.indexOf(
        u8,
        server.requestHead(0).?,
        "If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
    ) != null);

    // The dash turns the same file around, which is what curl does.
    const backward = try runZurlIn(sandbox.work, &.{ "-z", "-stamp.bin", "-o", "b.bin", url });
    defer testing.allocator.free(backward.stdout);
    defer testing.allocator.free(backward.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, backward.term);
    try testing.expect(std.mem.indexOf(
        u8,
        server.requestHead(1).?,
        "If-Unmodified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
    ) != null);

    // **A `=` prefix asks about a `Last-Modified`, which no http request
    // carries.** curl sends neither condition header for it, measured, and
    // zurl sends neither and says so.
    const last = try runZurlIn(sandbox.work, &.{ "-z", "=stamp.bin", "-o", "c.bin", url });
    defer testing.allocator.free(last.stdout);
    defer testing.allocator.free(last.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, last.term);
    const head = server.requestHead(2).?;
    try testing.expect(std.mem.indexOf(u8, head, "If-Modified-Since") == null);
    try testing.expect(std.mem.indexOf(u8, head, "If-Unmodified-Since") == null);
    try testing.expect(std.mem.indexOf(u8, last.stderr, "-z") != null);
}

test "-z refuses a date it cannot read by name, and still runs the transfer" {
    // Measured against curl 8.21.0: `-z 2015-10-21` printed `Illegal date
    // format for -z, --time-cond (and not a filename). Disabling time
    // condition.`, sent no condition header, and exited 0. zurl says the
    // same thing in its own words, so nothing is guessed and nothing is
    // dropped in silence.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-z", "2015-10-21", "-o", "a.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "If-Modified-Since") == null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "2015-10-21") != null);
}

test "a -H the user wrote outranks -z and --etag-compare" {
    // The rule every implied header here follows, and curl's own answer
    // for `-z`: measured, `-z <date> -H 'If-Modified-Since: <other>'` put
    // the `-H` line on the wire and no second one. Two of one conditional
    // header would let a server pick which one it answers.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();
    try sandbox.work.writeFile(testing.io, .{ .sub_path = "tag.txt", .data = "\"fromfile\"\n" });

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{
        "-z",             "21 Oct 2015 07:28:00 GMT",
        "-H",             "If-Modified-Since: Mon, 01 Jan 2001 00:00:00 GMT",
        "--etag-compare", "tag.txt",
        "-H",             "If-None-Match: \"fromH\"",
        "-o",             "a.bin",
        url,
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "If-Modified-Since: Mon, 01 Jan 2001 00:00:00 GMT\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "2015") == null);
    try testing.expect(std.mem.indexOf(u8, head, "If-None-Match: \"fromH\"\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "fromfile") == null);
}

test "with no output flag the body goes to stdout" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    // A url whose last segment is a usable name, so the only reason no
    // file appears is that no flag asked for one.
    const url = try loopbackUrlAt(&server, "/payload.bin");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("payload", result.stdout);
    try sandbox.expectNothingWritten();
}

test "-o and -O together write one file each, in the order they were given" {
    // This was `error.ConflictingOutput` and exit 2. curl 8.21.0 accepts
    // the pair: measured with two loopback servers, `curl -o a -O URL1
    // URL2` wrote URL1 into `a` and URL2 into the name URL2 ends with,
    // and left standard output empty. `curl -O -o a URL1 URL2` did the
    // mirror of that. zurl now matches, so the refusal is gone.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const first = try loopbackUrlAt(&server, "/one.bin");
    defer testing.allocator.free(first);
    const second = try loopbackUrlAt(&server, "/two.bin");
    defer testing.allocator.free(second);

    const result = try runZurlIn(sandbox.work, &.{ "-o", "out.bin", "-O", first, second });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("", result.stdout);

    const one = try sandbox.work.readFileAlloc(testing.io, "out.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("first", one);

    const two = try sandbox.work.readFileAlloc(testing.io, "two.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(two);
    try testing.expectEqualStrings("second", two);
}

test "-o pairs with one url, and a url past the last -o goes to standard output" {
    // The defect this closes: zurl held one destination for the whole
    // run, so two urls with one `-o` both opened the same file, the
    // second truncated what the first had written, and the run exited 0
    // with no word about the lost body.
    //
    // Measured against curl 8.21.0 with two loopback servers:
    // `curl -o out.bin URL1 URL2` left `AAAAA` in `out.bin` and printed
    // `BBBBB` on standard output.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const first = try loopbackUrlAt(&server, "/one.bin");
    defer testing.allocator.free(first);
    const second = try loopbackUrlAt(&server, "/two.bin");
    defer testing.allocator.free(second);

    const result = try runZurlIn(sandbox.work, &.{ "-o", "out.bin", first, second });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("second", result.stdout);

    const one = try sandbox.work.readFileAlloc(testing.io, "out.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("first", one);
}

test "-D appends every url's head blocks to one file" {
    // The other half of the same defect: `-D` truncated on each url, so
    // a run over two urls kept the last head alone. Measured:
    // `curl -D head.txt -o /dev/null URL1 URL2` left eight lines in
    // `head.txt`, one head block for each url.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Which: one\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 404 Not Found\r\nContent-Length: 6\r\nX-Which: two\r\nConnection: close\r\n\r\nsecond",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const first = try loopbackUrlAt(&server, "/one.bin");
    defer testing.allocator.free(first);
    const second = try loopbackUrlAt(&server, "/two.bin");
    defer testing.allocator.free(second);

    const result = try runZurlIn(sandbox.work, &.{ "-D", "head.txt", "-o", "a.bin", "-o", "b.bin", first, second });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const head = try sandbox.work.readFileAlloc(testing.io, "head.txt", testing.allocator, .limited(1024));
    defer testing.allocator.free(head);
    try testing.expect(std.mem.indexOf(u8, head, "X-Which: one") != null);
    try testing.expect(std.mem.indexOf(u8, head, "X-Which: two") != null);
    try testing.expect(std.mem.indexOf(u8, head, "HTTP/1.1 200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, head, "HTTP/1.1 404 Not Found") != null);
}

test "-o - writes the body to standard output and creates no file called -" {
    // The defect this closes: zurl read `-` as an ordinary file name, so
    // `-o -` created a file called `-` in the working directory instead
    // of writing to standard output. Measured against curl 8.21.0:
    // `curl -o - URL` writes the body to standard output and creates no
    // file.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-o", "-", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("payload", result.stdout);
    try sandbox.expectNothingWritten();
}

test "-o ./- still writes a file literally called -" {
    // The escape hatch `-o -` must not close off. Measured against curl
    // 8.21.0: `curl -o ./- URL` writes a file named `-`, because the
    // argument is not spelled exactly `-`.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-o", "./-", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("", result.stdout);

    const dash = try sandbox.work.readFileAlloc(testing.io, "-", testing.allocator, .limited(64));
    defer testing.allocator.free(dash);
    try testing.expectEqualStrings("payload", dash);
}

test "-D - writes the head block to standard output and creates no file called -" {
    // The same mistake `-o -` had, in the second place zurl reads a `-`
    // argument as a destination. Measured against curl 8.21.0:
    // `curl -D - -o /dev/null URL` writes the head block to standard
    // output and creates no file.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nX-Which: one\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-D", "-", "-o", "out.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "HTTP/1.1 200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "X-Which: one") != null);

    const written = try sandbox.work.readFileAlloc(testing.io, "out.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("payload", written);
}

test "-D - puts the head block ahead of the body on standard output" {
    // Measured: `curl -D - -o - -w '...'` puts the head block ahead of
    // the body, which stays ahead of the write-out. `transferOne` writes
    // the headers before the body already, for a file destination; this
    // pins the same order for standard output.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-s", "-D", "-", "-o", "-", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    const head_at = std.mem.indexOf(u8, result.stdout, "HTTP/1.1 200 OK") orelse
        return error.TestUnexpectedResult;
    const body_at = std.mem.indexOf(u8, result.stdout, "payload") orelse
        return error.TestUnexpectedResult;
    try testing.expect(head_at < body_at);
    try sandbox.expectNothingWritten();
}

test "-o onto a path zurl cannot open exits with the curl code for a write failure" {
    // curl 8.21.0 exits 23 for the same command line, checked against the
    // real program. The message names the operating system's own cause,
    // so a user can tell a missing directory from a denied one.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-o", "no-such-directory/out.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 23 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "(23)") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "FileNotFound") != null);
}

test "a failed -o leaves the bytes that arrived, the way curl does" {
    // The peer announces 10 bytes and sends 2, so the transfer ends as
    // `CURLE_PARTIAL_FILE`, which is 18. curl 8.21.0 leaves the 2 bytes
    // it received in the file, and truncates whatever was there before.
    // Checked against the real program. `zurl.download.toFile` behaves
    // the opposite way on purpose, for a cache that must never publish a
    // partial artifact. The CLI serves a person who ran curl.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhi"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{
        .sub_path = "out.bin",
        .data = "a much longer old file",
    });

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-o", "out.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 18 }, result.term);

    const contents = try sandbox.work.readFileAlloc(testing.io, "out.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("hi", contents);
}

test {
    _ = Args;
    _ = report;
    _ = writeout;
    _ = safe;
    // The run, and through it `output` and `progress`. Every file the CLI
    // holds is reachable from this one reference or from the four above.
    _ = run;
    _ = body;
    // `body.zig` reaches this file for a `-F` run, but a reference through
    // a call is not one `zig build test` collects tests from.
    _ = @import("cli/form.zig");
    _ = harness;
    // The end to end tests. They live in a file of their own because they
    // test the product and not a part of it, and they take their fixtures
    // from `src/cli/testing.zig`. This reference is what puts them in
    // `zig build test`, and it stands in the test section, so the shipped
    // binary never carries them.
    _ = @import("cli/e2e_test.zig");
}

test "-D writes the response head to a file, byte for byte" {
    // The file must hold the status line through the empty line, with CRLF
    // endings and no body. curl 8.21.0 writes exactly these bytes for the
    // same response, checked against the real program.
    var server: test_server.TestServer = undefined;
    const head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
        "Content-Length: 7\r\nConnection: close\r\n\r\n";
    try server.start(&.{head ++ "payload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-D", "head.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The body still goes to standard output, the way curl's does.
    try testing.expectEqualStrings("payload", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));

    const written = try sandbox.work.readFileAlloc(testing.io, "head.txt", testing.allocator, .limited(1024));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings(head, written);
}

test "-D writes every hop of a followed redirect, the way curl -D -L does" {
    var server: test_server.TestServer = undefined;
    const first = "HTTP/1.1 302 Found\r\nLocation: /body\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const second = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\n";
    try server.start(&.{ first, second ++ "payload" });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrlAt(&server, "/start");
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-L", "-D", "head.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("payload", result.stdout);

    const written = try sandbox.work.readFileAlloc(testing.io, "head.txt", testing.allocator, .limited(1024));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings(first ++ second, written);
}

test "-D beside -o writes both files" {
    var server: test_server.TestServer = undefined;
    const head = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n";
    try server.start(&.{head ++ "payload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-D", "head.txt", "-o", "out.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // Neither file's content reached standard output.
    try testing.expectEqualStrings("", result.stdout);
    try testing.expectEqualStrings("", try afterMeter(result.stderr));

    const written_head = try sandbox.work.readFileAlloc(testing.io, "head.txt", testing.allocator, .limited(1024));
    defer testing.allocator.free(written_head);
    try testing.expectEqualStrings(head, written_head);

    const written_body = try sandbox.work.readFileAlloc(testing.io, "out.bin", testing.allocator, .limited(1024));
    defer testing.allocator.free(written_body);
    try testing.expectEqualStrings("payload", written_body);
}

test "-D onto a path zurl cannot open exits with the curl code for a write failure" {
    // The same fault `-o` reports for the same shape, and the same code.
    // The body is not written either: the user asked for the headers, and
    // a body beside a missing header file would hide that they never came.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-D", "no-such-directory/head.txt", "-o", "out.bin", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 23 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "FileNotFound") != null);
    try testing.expectError(error.FileNotFound, sandbox.work.access(testing.io, "out.bin", .{}));
}

test "-D truncates whatever the file held before" {
    var server: test_server.TestServer = undefined;
    const head = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
    try server.start(&.{head});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    try sandbox.work.writeFile(testing.io, .{
        .sub_path = "head.txt",
        .data = "a much longer file from an older run",
    });

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurlIn(sandbox.work, &.{ "-D", "head.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const written = try sandbox.work.readFileAlloc(testing.io, "head.txt", testing.allocator, .limited(1024));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings(head, written);
}

test "two urls without -Z run one after the other" {
    // One server, and a script of two responses it serves in the order it
    // accepts connections. The first url therefore reaches the server
    // before the second one does, and the request heads say which url
    // arrived first. That order is what "one after the other" means from
    // outside the process.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    });
    defer server.stop();

    const one = try loopbackUrlAt(&server, "/one");
    defer testing.allocator.free(one);
    const two = try loopbackUrlAt(&server, "/two");
    defer testing.allocator.free(two);

    const result = try runZurl(&.{ "-s", one, two });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("firstsecond", result.stdout);

    // The head the server answered first asked for /one, and the head it
    // answered second asked for /two.
    try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "GET /one ") != null);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(1).?, "GET /two ") != null);
}

test "two urls with -Z both complete" {
    // Two servers, because one `TestServer` accepts one connection at a
    // time and would serialise the very thing this test runs. `Multi`'s
    // own tests start several for the same reason.
    //
    // `-O` gives each url a file of its own, which is the one output
    // shape `-Z` overlaps. Every other shape has one destination for
    // every url, and `parallelBlocker` sends those down the one-at-a-time
    // path instead.
    var server_a: test_server.TestServer = undefined;
    try server_a.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst"});
    defer server_a.stop();

    var server_b: test_server.TestServer = undefined;
    try server_b.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond"});
    defer server_b.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url_a = try loopbackUrlAt(&server_a, "/one.bin");
    defer testing.allocator.free(url_a);
    const url_b = try loopbackUrlAt(&server_b, "/two.bin");
    defer testing.allocator.free(url_b);

    const result = try runZurlIn(sandbox.work, &.{ "-Z", "-O", url_a, "-O", url_b });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // No note, because nothing forced the run down to one transfer at a
    // time. A build with no concurrency is the one case that prints here,
    // and that build skips this test with the servers it cannot start.
    try testing.expectEqualStrings("", result.stderr);

    const one = try sandbox.work.readFileAlloc(testing.io, "one.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(one);
    try testing.expectEqualStrings("first", one);

    const two = try sandbox.work.readFileAlloc(testing.io, "two.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(two);
    try testing.expectEqualStrings("second", two);
}

test "with -Z a failing url does not stop the others, and the exit code reports a failure" {
    // Port 1 is closed on loopback, the fixture every other test in this
    // project uses for a connection that never succeeds. It is the only
    // failing url here, so the exit code is its own code whichever rule
    // reads the results: the test below is the one that tells the first
    // failure from the last.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood"});
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const good = try loopbackUrlAt(&server, "/good.bin");
    defer testing.allocator.free(good);
    const dead = "http://127.0.0.1:1/dead.bin";

    // One `-O` for each url, which is how curl pairs them.
    const result = try runZurlIn(sandbox.work, &.{ "-Z", "-O", "-O", dead, good });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // 7 is `CURLE_COULDNT_CONNECT`.
    try testing.expectEqual(std.process.Child.Term{ .exited = 7 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "127.0.0.1") != null);

    // The url that could run, ran, and wrote its whole body.
    const written = try sandbox.work.readFileAlloc(testing.io, "good.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("good", written);

    // And the url that failed wrote nothing, because it reached no server.
    try testing.expectError(error.FileNotFound, sandbox.work.access(testing.io, "dead.bin", .{}));
}

test "-Z keeps the first failure, where no -Z keeps the last" {
    // The rule `runParallel` and `runSerial` disagree on. Measured against
    // curl 8.21.0 on loopback: with `-Z` it reports the transfer that
    // failed first and never replaces that code, and with no `-Z` it
    // reports the last failure the command line named.
    //
    // Neither url reaches a server, so this test needs no fixture and
    // runs in every build configuration, including one with no
    // concurrency. One `-O` for each url keeps the run on the parallel
    // path: each url ends in a name of its own, so nothing forces one
    // transfer at a time.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    // 1 is `CURLE_UNSUPPORTED_PROTOCOL` and 7 is `CURLE_COULDNT_CONNECT`.
    const unsupported = "rtmp://127.0.0.1:1935/first.bin";
    const refused = "http://127.0.0.1:1/second.bin";

    const cases = [_]struct { args: []const []const u8, code: u8 }{
        .{ .args = &.{ "-Z", "-s", "-O", "-O", unsupported, refused }, .code = 1 },
        .{ .args = &.{ "-Z", "-s", "-O", "-O", refused, unsupported }, .code = 7 },
        .{ .args = &.{ "-s", "-O", "-O", unsupported, refused }, .code = 7 },
        .{ .args = &.{ "-s", "-O", "-O", refused, unsupported }, .code = 1 },
    };

    for (cases) |case| {
        const result = try runZurlIn(sandbox.work, case.args);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = case.code }, result.term);
    }

    try sandbox.expectNothingWritten();
}

test "-Z with one url behaves like no -Z" {
    // One transfer cannot overlap anything, so `-Z` there must take the
    // same path a run with no `-Z` takes: the body on standard output, the
    // meter on standard error, and no note about running one at a time.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const with = try runZurl(&.{ "-Z", url });
    defer testing.allocator.free(with.stdout);
    defer testing.allocator.free(with.stderr);

    const without = try runZurl(&.{url});
    defer testing.allocator.free(without.stdout);
    defer testing.allocator.free(without.stderr);

    try testing.expectEqual(without.term, with.term);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, with.term);
    try testing.expectEqualStrings(without.stdout, with.stdout);
    try testing.expectEqualStrings("ok", with.stdout);

    // The meter is the proof that this is the same path. `runParallel`
    // draws none, so a `-Z` that had taken it would leave standard error
    // empty here.
    try testing.expectEqualStrings("", try afterMeter(with.stderr));
    try testing.expectEqualStrings("", try afterMeter(without.stderr));
}

test "-Z draws no meter while transfers overlap, and no -Z still draws one" {
    // curl 8.21.0 draws a second meter for `-Z`, of columns
    // `DL% UL% Dled Uled Xfers Live Total Current Left Speed`, which
    // counts every transfer on one row. zurl has one meter, for one
    // transfer, and several of those on one standard error would
    // overwrite each other's row. So `-Z` draws none, and `--help` says
    // so.
    // Two responses in each script, because this test runs the same two
    // urls twice: once with `-Z` and once as the control.
    var server_a: test_server.TestServer = undefined;
    try server_a.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
    });
    defer server_a.stop();

    var server_b: test_server.TestServer = undefined;
    try server_b.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    });
    defer server_b.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url_a = try loopbackUrlAt(&server_a, "/one.bin");
    defer testing.allocator.free(url_a);
    const url_b = try loopbackUrlAt(&server_b, "/two.bin");
    defer testing.allocator.free(url_b);

    const parallel = try runZurlIn(sandbox.work, &.{ "-Z", "-O", url_a, "-O", url_b });
    defer testing.allocator.free(parallel.stdout);
    defer testing.allocator.free(parallel.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, parallel.term);
    try testing.expectEqualStrings("", parallel.stderr);

    // The control. The same two urls with no `-Z` draw one meter for each
    // transfer, so an empty standard error above is `-Z`'s own doing and
    // not a meter that stopped working. `afterMeter` reads the first one
    // and the second follows it.
    const serial = try runZurlIn(sandbox.work, &.{ "-O", url_a, "-O", url_b });
    defer testing.allocator.free(serial.stdout);
    defer testing.allocator.free(serial.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, serial.term);
    try testing.expectEqualStrings("", try afterMeter(try afterMeter(serial.stderr)));
}

test "-Z says why it runs one at a time when every url writes to one destination" {
    // Two transfers cannot fill one file, or one standard output, at the
    // same time. `output.toFile` truncates and then writes as the body
    // arrives, and an `Io.Writer` holds one buffer and one end index, so
    // either shared destination would take two workers' bytes and keep
    // neither. curl instead mixes the bytes of parallel bodies into
    // standard output as they arrive, byte by byte, measured against
    // curl 8.21.0 with two slow chunked responses.
    //
    // zurl runs those shapes one transfer at a time and says so.
    // IronStyle: recovery is never silent.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const one = try loopbackUrlAt(&server, "/one.bin");
    defer testing.allocator.free(one);
    const two = try loopbackUrlAt(&server, "/two.bin");
    defer testing.allocator.free(two);

    const result = try runZurlIn(sandbox.work, &.{ "-Z", "-s", "-S", one, two });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // Every url still runs, and the bodies arrive whole and in the order
    // the command line named them, never mixed together.
    try testing.expectEqualStrings("firstsecond", result.stdout);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "-Z") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "standard output") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "one at a time") != null);
}

test "-s hides the note that -Z runs one at a time, and -S brings it back" {
    // The same `-s` and `-S` rule every other note in this file follows.
    // Neither url reaches a server, so this needs no fixture.
    const one = "rtmp://127.0.0.1:1935/one";
    const two = "rtmp://127.0.0.1:1935/two";

    const quiet = try runZurl(&.{ "-Z", "-s", one, two });
    defer testing.allocator.free(quiet.stdout);
    defer testing.allocator.free(quiet.stderr);
    try testing.expectEqualStrings("", quiet.stderr);

    const loud = try runZurl(&.{ "-Z", "-s", "-S", one, two });
    defer testing.allocator.free(loud.stdout);
    defer testing.allocator.free(loud.stderr);
    try testing.expect(std.mem.indexOf(u8, loud.stderr, "one at a time") != null);
}

test "-Z names each shared destination it cannot overlap" {
    // One row for each shape `parallelBlocker` refuses to overlap. None of
    // these urls reaches a server: the note comes before the first
    // transfer, so a failing transfer cannot hide it.
    //
    // The last row is the one curl has no answer for at all. Two urls can
    // end in the same last path segment, and `-O` then gives both the same
    // file. curl writes them both anyway; zurl runs them one at a time.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const cases = [_]struct { args: []const []const u8, names: []const u8 }{
        .{
            .args = &.{ "-Z", "rtmp://127.0.0.1:1935/a", "rtmp://127.0.0.1:1935/b" },
            .names = "standard output",
        },
        // One `-o` and two urls is the same shape: curl pairs the output
        // list with the url list, so the second url goes to standard
        // output and standard output is one stream.
        .{
            .args = &.{ "-Z", "-o", "out.bin", "rtmp://127.0.0.1:1935/a", "rtmp://127.0.0.1:1935/b" },
            .names = "standard output",
        },
        // Two `-o` naming one path is the file collision.
        .{
            .args = &.{ "-Z", "-o", "out.bin", "-o", "out.bin", "rtmp://127.0.0.1:1935/a", "rtmp://127.0.0.1:1935/b" },
            .names = "the same file",
        },
        .{
            .args = &.{ "-Z", "-O", "-O", "rtmp://127.0.0.1:1935/same", "rtmp://127.0.0.2:1935/same" },
            .names = "the same file",
        },
    };

    for (cases) |case| {
        const result = try runZurlIn(sandbox.work, case.args);
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        // 1 is `CURLE_UNSUPPORTED_PROTOCOL`, which every url here earns.
        try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
        try testing.expect(std.mem.indexOf(u8, result.stderr, case.names) != null);
        try testing.expect(std.mem.indexOf(u8, result.stderr, "one at a time") != null);
    }

    try sandbox.expectNothingWritten();
}

test "-Z runs one at a time when -D names one file for every url" {
    // `-D` is the one destination `-o` and `-O` cannot spread over the
    // urls: measured, `curl -D h1 -D h2` keeps `h2` alone, so a later
    // `-D` replaces an earlier one rather than pairing with a url. Every
    // url appends to that one file, so the transfers cannot overlap.
    //
    // This case has a sandbox of its own, because `-D` creates its file
    // before the first transfer, the way curl does, so the run is not one
    // that writes nothing.
    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const result = try runZurlIn(sandbox.work, &.{
        "-Z",                      "-O",
        "-O",                      "-D",
        "head.txt",                "rtmp://127.0.0.1:1935/a",
        "rtmp://127.0.0.1:1935/b",
    });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "-D names one file") != null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "one at a time") != null);

    // The file is there and empty, which is what curl leaves behind when
    // no transfer reaches a server.
    const head = try sandbox.work.readFileAlloc(testing.io, "head.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(head);
    try testing.expectEqualStrings("", head);
}

test "-Z still renders -w once for each url" {
    // The write-out is the one thing `-Z` writes to standard output, and
    // two workers share that stream. The lock in `fetchOne` is what keeps
    // one url's write-out whole, so this test asks for a format with a
    // beginning and an end and reads both lines back.
    var server_a: test_server.TestServer = undefined;
    try server_a.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst"});
    defer server_a.stop();

    var server_b: test_server.TestServer = undefined;
    try server_b.start(&.{"HTTP/1.1 404 Not Found\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond"});
    defer server_b.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const url_a = try loopbackUrlAt(&server_a, "/one.bin");
    defer testing.allocator.free(url_a);
    const url_b = try loopbackUrlAt(&server_b, "/two.bin");
    defer testing.allocator.free(url_b);

    const result = try runZurlIn(sandbox.work, &.{ "-Z", "-O", "-O", "-w", "[%{http_code}]\n", url_a, url_b });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The two urls finish in whichever order the workers reach them, so
    // this counts the lines instead of pinning their order.
    try testing.expect(std.mem.indexOf(u8, result.stdout, "[200]\n") != null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "[404]\n") != null);
    try testing.expectEqual(@as(usize, 12), result.stdout.len);
}

/// Writes `text` into a temporary directory as `name` and returns the path
/// to it, relative to the working directory the test suite runs in.
///
/// The spawned binary runs with the suite's own working directory, so a
/// relative path reaches the same file. This is the pattern the netrc
/// tests already use.
fn writeTempFile(tmp: *testing.TmpDir, name: []const u8, text: []const u8) ![]u8 {
    try tmp.dir.writeFile(testing.io, .{ .sub_path = name, .data = text });
    return std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/{s}",
        .{ tmp.sub_path, name },
    );
}

/// The path `name` would take inside `tmp`, for a file the binary writes.
fn tempPath(tmp: *const testing.TmpDir, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/{s}",
        .{ tmp.sub_path, name },
    );
}

test "-b puts its cookie text on the wire exactly as curl does" {
    // Every row measured against curl 8.21.0 on a loopback listener. curl
    // never reformats the text: it writes what the user typed.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    // `-b 'a=1; b=2'` reaches the wire byte for byte.
    const one = try runZurl(&.{ "-b", "a=1; b=2", url });
    defer testing.allocator.free(one.stdout);
    defer testing.allocator.free(one.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, one.term);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "Cookie: a=1; b=2\r\n") != null);

    // Two `-b` flags join with a semicolon and a space, which is what curl
    // sends for `-b 'a=1' -b 'b=2'`.
    const two = try runZurl(&.{ "-b", "a=1", "-b", "b=2", url });
    defer testing.allocator.free(two.stdout);
    defer testing.allocator.free(two.stderr);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(1).?, "Cookie: a=1; b=2\r\n") != null);

    // A `-H Cookie:` replaces the `-b` text outright, and one `Cookie`
    // line goes out and never two.
    const header = try runZurl(&.{ "-b", "a=1", "-H", "Cookie: z=9", url });
    defer testing.allocator.free(header.stdout);
    defer testing.allocator.free(header.stderr);
    const third = server.requestHead(2).?;
    try testing.expect(std.mem.indexOf(u8, third, "Cookie: z=9\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, third, "a=1") == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, third, "ookie:"));
}

test "-c writes the Netscape jar file curl writes for the same response" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n" ++
            "Set-Cookie: sess=abc123\r\n\r\nok",
    });
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const jar_path = try tempPath(&tmp, "out.jar");
    defer testing.allocator.free(jar_path);

    const url = try loopbackUrlAt(&server, "/dir/page");
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-c", jar_path, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);

    const written = try tmp.dir.readFileAlloc(testing.io, "out.jar", testing.allocator, .limited(4096));
    defer testing.allocator.free(written);

    // Byte for byte what curl 8.21.0 wrote for this response, apart from
    // the third comment line, where curl names libcurl and zurl names
    // zurl. The default path is the directory of the request path, the
    // second column is FALSE for a host-only cookie, and the fifth is 0
    // for a session cookie.
    try testing.expectEqualStrings(
        "# Netscape HTTP Cookie File\n" ++
            "# https://curl.se/docs/http-cookies.html\n" ++
            "# This file was generated by zurl! Edit at your own risk.\n" ++
            "\n" ++
            "127.0.0.1\tFALSE\t/dir\tFALSE\t0\tsess\tabc123\n",
        written,
    );
}

test "-c writes the four header lines even when nothing set a cookie" {
    // Measured: `curl -c jar URL` on a response with no `Set-Cookie` still
    // writes the file, and writes the header alone.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const jar_path = try tempPath(&tmp, "empty.jar");
    defer testing.allocator.free(jar_path);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-c", jar_path, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    const written = try tmp.dir.readFileAlloc(testing.io, "empty.jar", testing.allocator, .limited(4096));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings(zurl_core.cookie.jar_header, written);
}

test "-b with no equals sign reads a jar file, and -j drops its session cookies" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const jar_path = try writeTempFile(
        &tmp,
        "in.jar",
        "# Netscape HTTP Cookie File\n" ++
            "\n" ++
            "127.0.0.1\tFALSE\t/\tFALSE\t0\tsess\tsvalue\n" ++
            "127.0.0.1\tFALSE\t/\tFALSE\t2000000000\tperm\tpvalue\n" ++
            "#HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t0\tho\thvalue\n" ++
            "other.test\tFALSE\t/\tFALSE\t0\telsewhere\tevalue\n",
    );
    defer testing.allocator.free(jar_path);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const loaded = try runZurl(&.{ "-b", jar_path, url });
    defer testing.allocator.free(loaded.stdout);
    defer testing.allocator.free(loaded.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, loaded.term);

    const head = server.requestHead(0).?;
    // The three cookies of this host, and never the cookie of another
    // host. A `#HttpOnly_` line is read the way curl reads it.
    try testing.expect(std.mem.indexOf(u8, head, "perm=pvalue") != null);
    try testing.expect(std.mem.indexOf(u8, head, "sess=svalue") != null);
    try testing.expect(std.mem.indexOf(u8, head, "ho=hvalue") != null);
    try testing.expect(std.mem.indexOf(u8, head, "elsewhere") == null);

    // Measured: `curl -b jar -j` sent `Cookie: perm=pvalue` and nothing
    // else, because `-j` drops every session cookie of the file.
    const junked = try runZurl(&.{ "-b", jar_path, "-j", url });
    defer testing.allocator.free(junked.stdout);
    defer testing.allocator.free(junked.stderr);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(1).?, "Cookie: perm=pvalue\r\n") != null);
}

test "a jar file that names another host never reaches the wire" {
    // **The rule a malicious jar file must not break.** A file the user
    // did not write can hold any domain it likes, and none of them puts a
    // cookie on a host that domain does not own.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const jar_path = try writeTempFile(
        &tmp,
        "evil.jar",
        "bank.test\tTRUE\t/\tFALSE\t0\tsteal\tSTOLENVALUE\n" ++
            "example.com\tTRUE\t/\tFALSE\t0\talso\tSTOLENTOO\n",
    );
    defer testing.allocator.free(jar_path);

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-b", jar_path, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, head, "ookie:"));
    try testing.expect(std.mem.indexOf(u8, head, "STOLEN") == null);
}

test "no cookie flag keeps every Set-Cookie out, which is curl's own default" {
    // Measured against curl 8.21.0: two urls in one invocation, the first
    // answering `Set-Cookie`, sent no `Cookie` header on the second
    // without a cookie flag on the command line.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n" ++
            "Set-Cookie: sid=zz9\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    const first = try loopbackUrlAt(&server, "/one");
    defer testing.allocator.free(first);
    const second = try loopbackUrlAt(&server, "/two");
    defer testing.allocator.free(second);

    const result = try runZurl(&.{ first, second });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, server.requestHead(1).?, "ookie:"));
}

test "a cookie value reaches no message this program writes" {
    // **A cookie is a credential, so no diagnostic may echo one.** The jar
    // here holds one good cookie, one line that is not a cookie at all,
    // and one cookie for a host this run never reaches. Each of the three
    // makes zurl write something, and none of the three may write a
    // value. The transfer itself then fails, so the fault message is in
    // the output too.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const jar_path = try writeTempFile(
        &tmp,
        "secret.jar",
        "127.0.0.1\tFALSE\t/\tFALSE\t0\tsid\tSUPERSECRETVALUE\n" ++
            "this line is not a cookie at all\n" ++
            "bank.test\tTRUE\t/\tFALSE\t0\tsteal\tANOTHERSECRET\n",
    );
    defer testing.allocator.free(jar_path);

    const port = try closedPort();
    const url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{port});
    defer testing.allocator.free(url);

    const jar_out = try tempPath(&tmp, "written.jar");
    defer testing.allocator.free(jar_out);

    const result = try runZurl(&.{ "-b", jar_path, "-c", jar_out, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // The run said something: recovery is never silent.
    try testing.expect(result.stderr.len != 0);
    // And it said nothing that could be replayed as a session.
    try testing.expect(std.mem.indexOf(u8, result.stderr, "SUPERSECRETVALUE") == null);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "ANOTHERSECRET") == null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "SUPERSECRETVALUE") == null);
    try testing.expect(std.mem.indexOf(u8, result.stdout, "ANOTHERSECRET") == null);

    // The jar file is the one place a value may be written, and the value
    // that belongs to this host is there.
    const written = try tmp.dir.readFileAlloc(testing.io, "written.jar", testing.allocator, .limited(4096));
    defer testing.allocator.free(written);
    try testing.expect(std.mem.indexOf(u8, written, "SUPERSECRETVALUE") != null);
}

test "a jar file that cannot be read costs no exit code and is not silent" {
    // Measured: `curl -b /nope/x URL` exits 0, sends no cookie, and prints
    // nothing. zurl keeps the exit code and the wire bytes, and adds the
    // line, because a session file that was not there is a fault the user
    // has to hear about.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-b", "/nope/no-such-cookie-jar.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "cannot read the cookie file") != null);
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, server.requestHead(0).?, "ookie:"));

    // `-s` hides it, the way `-s` hides every other note.
    const silent = try runZurl(&.{ "-s", "-b", "/nope/no-such-cookie-jar.txt", url });
    defer testing.allocator.free(silent.stdout);
    defer testing.allocator.free(silent.stderr);
    try testing.expectEqualStrings("", silent.stderr);
}

test "-c to a path that cannot be written keeps the exit code and says so" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-c", "/nope/dir/jar.txt", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // Measured: curl exits 0 here and prints nothing at all.
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "cannot write the cookie jar") != null);
}

test "-c - writes the jar to standard output, the way -D - writes the heads" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n" ++
            "Set-Cookie: sid=zz9\r\n\r\nok",
    });
    defer server.stop();

    const url = try loopbackUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-c", "-", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    // The body first, then the jar. Both go to the same stream, in the
    // order they were written.
    try testing.expectEqualStrings(
        "ok" ++ zurl_core.cookie.jar_header ++ "127.0.0.1\tFALSE\t/\tFALSE\t0\tsid\tzz9\n",
        result.stdout,
    );
}

// ---------------------------------------------------------------------
// TLS, end to end, over `zurl-tls`'s loopback server.
//
// Every test below runs the shipped binary against a server on 127.0.0.1
// that completes a real TLS 1.3 handshake. None of them reaches the
// network. Before this fixture existed, `-k` had no offline test at all
// and the phase review recorded that as accepted.
// ---------------------------------------------------------------------

/// The reply each TLS test below scripts.
const tls_ok_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

test "a certificate no trust store holds fails the transfer with curl's code 60" {
    var server: tls_test_server.TlsTestServer = undefined;
    try server.startWith(&.{tls_ok_response}, .{ .chain = .self_signed });
    defer server.stop();

    const url = try loopbackTlsUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(
        std.process.Child.Term{ .exited = peer_failed_verification_code },
        result.term,
    );
    try testing.expectEqualStrings("", result.stdout);
    try testing.expect(std.mem.indexOf(u8, result.stderr, "PeerFailedVerification") != null);
}

test "-k takes the certificate that has no trusted root, and --insecure does the same" {
    // **The test that fails if `-k` becomes a no-op.** A run with no flag
    // exits 60, in the test above; these two exit zero and write the body.
    // Nothing else in the suite can tell the two apart, because every
    // other test of `-k` reads the parsed flag and never a transfer.
    for ([_][]const u8{ "-k", "--insecure" }) |flag| {
        var server: tls_test_server.TlsTestServer = undefined;
        try server.startWith(&.{tls_ok_response}, .{ .chain = .self_signed });
        defer server.stop();

        const url = try loopbackTlsUrl(&server);
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ flag, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
        try testing.expectEqualStrings("ok", result.stdout);
        try testing.expectEqualStrings("", try afterMeter(result.stderr));
        // The session came all the way up, so the body above came through
        // a handshake this fixture finished and not through anything else.
        try testing.expectEqual(@as(usize, 1), server.handshakes());
    }
}

test "--cacert names the root of the chain and the transfer completes" {
    // The other half of `-k`: a trusted certificate needs no flag that
    // turns the check off. Without this, a `-k` that turned the whole of
    // TLS off would still pass the test above.
    var server: tls_test_server.TlsTestServer = undefined;
    try server.startWith(&.{tls_ok_response}, .{ .chain = .ca_issued });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const cacert = try writeRootPem(&server, sandbox.work);
    defer testing.allocator.free(cacert);

    const url = try loopbackTlsUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "--cacert", cacert, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("ok", result.stdout);
    try testing.expectEqual(@as(usize, 1), server.handshakes());
}

test "a leaf that is no certificate authority cannot issue a leaf for another name" {
    // The chain rule of `verifyIssued`, proved by a transfer and not by a
    // unit test over hand-built certificates.
    //
    // The server presents three certificates: a leaf for the host the url
    // names, the real leaf of `attacker.test` that signed it, and the root
    // that issued that real leaf. **`--cacert` names that very root**, so
    // the trust store holds it, every signature in the chain holds, and
    // the host name check passes. Only RFC 5280 section 4.2.1.9 refuses
    // it, because the middle certificate says `cA` FALSE.
    //
    // A build with the `verifyIssued` call taken out writes `ok` here and
    // exits zero, which is a machine in the middle of an HTTPS transfer.
    var server: tls_test_server.TlsTestServer = undefined;
    try server.startWith(&.{tls_ok_response}, .{ .chain = .forged_by_leaf });
    defer server.stop();

    var sandbox = try SandboxDir.init();
    defer sandbox.deinit();

    const cacert = try writeRootPem(&server, sandbox.work);
    defer testing.allocator.free(cacert);

    const url = try loopbackTlsUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "--cacert", cacert, url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(
        std.process.Child.Term{ .exited = peer_failed_verification_code },
        result.term,
    );
    try testing.expectEqualStrings("", result.stdout);
    // The client stopped inside the handshake, so the forged name never
    // reached a request.
    try testing.expectEqual(@as(usize, 0), server.handshakes());
}

test "-k takes the forged chain, which says the refusal above is the chain rule" {
    // The control for the test above. The same three certificates, the
    // same server, and the one difference is the check. So the refusal
    // there is the certificate rules and nothing else in the handshake.
    var server: tls_test_server.TlsTestServer = undefined;
    try server.startWith(&.{tls_ok_response}, .{ .chain = .forged_by_leaf });
    defer server.stop();

    const url = try loopbackTlsUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-k", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result.term);
    try testing.expectEqualStrings("ok", result.stdout);
}

test "an expired certificate and a certificate for another name both fail with 60" {
    // The two ordinary reasons a certificate is refused. Both used to have
    // live hosts at badssl.com and nothing offline.
    const chains = [_]tls_test_server.Chain{ .expired, .wrong_host };
    for (chains) |chain| {
        var server: tls_test_server.TlsTestServer = undefined;
        try server.startWith(&.{tls_ok_response}, .{ .chain = chain });
        defer server.stop();

        var sandbox = try SandboxDir.init();
        defer sandbox.deinit();

        const cacert = try writeRootPem(&server, sandbox.work);
        defer testing.allocator.free(cacert);

        const url = try loopbackTlsUrl(&server);
        defer testing.allocator.free(url);

        const result = try runZurl(&.{ "--cacert", cacert, url });
        defer testing.allocator.free(result.stdout);
        defer testing.allocator.free(result.stderr);

        try testing.expectEqual(
            std.process.Child.Term{ .exited = peer_failed_verification_code },
            result.term,
        );
        try testing.expectEqualStrings("", result.stdout);
    }
}

test "a certificate no parser can read stops the transfer and never faults the process" {
    // **The shipped binary crashed on this certificate.**
    // `std.crypto.Certificate`'s `der.Element.parse` bounds nothing: it
    // reads its identifier and length octets with no test that they are
    // inside the buffer, and it computes an element's end as unchecked
    // `u32` arithmetic over as many as four octets the peer chose. The
    // client parses every server certificate before it checks the host
    // name and before it asks the trust store, so every server could
    // reach it.
    //
    // One certificate gave three different faults, chosen by whatever sat
    // after it in memory, which the peer also writes: a read out of
    // bounds, the octets of that read coming back as certificate fields,
    // or a walk that steps backwards over a wrapped end and never stops.
    // Measured on a `ReleaseFast` build: ten octets exited 139.
    //
    // `zurl_tls.certificate.parse` bounds every read now. This test holds
    // the binary to an exit code, because a signal is the defect coming
    // back and a clean refusal is the whole fix.
    var server: tls_test_server.TlsTestServer = undefined;
    try server.startWith(&.{tls_ok_response}, .{ .chain = .malformed });
    defer server.stop();

    const url = try loopbackTlsUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{url});
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    // `.exited` and not `.signal` is the assertion. A crash arrives here
    // as a signal, and no exit code can stand in for one.
    try testing.expect(result.term == .exited);
    try testing.expectEqual(
        std.process.Child.Term{ .exited = peer_failed_verification_code },
        result.term,
    );
    try testing.expectEqualStrings("", result.stdout);
}

test "a certificate no parser can read is refused even when the run says -k" {
    // **`-k` turns off the trust check, not the parse.** A caller that
    // passes `--insecure` still hands the peer's octets to the parser, so
    // the crash was reachable with the flag as well as without it. The
    // fix has to hold on both paths, and this is the one that would be
    // missed: every other `-k` test presents a certificate that parses.
    var server: tls_test_server.TlsTestServer = undefined;
    try server.startWith(&.{tls_ok_response}, .{ .chain = .malformed });
    defer server.stop();

    const url = try loopbackTlsUrl(&server);
    defer testing.allocator.free(url);

    const result = try runZurl(&.{ "-k", url });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);

    try testing.expect(result.term == .exited);
    try testing.expect(result.term.exited != 0);
    try testing.expectEqualStrings("", result.stdout);
}
