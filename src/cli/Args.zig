//! Turns argv into a `Plan`. No I/O, no globals, no assertion on argv's
//! content: argv comes from the shell, and the shell is untrusted input the
//! same way a socket is.
//!
//! `parse` reads every flag in one pass and builds a `Transfer.Options` from
//! `lib/zurl/Transfer.zig`'s own doc comments, which name the curl flag each
//! field maps to. Three flags need a decision this file writes down:
//!
//! - `-u` splits its argument on the FIRST colon, because a password may
//!   hold one and a user name may not. Splitting on the last colon is the
//!   classic bug this avoids.
//! - The method comes from whichever flag names one, and `-X` outranks
//!   every other. `resolveRequestBody` holds the whole table, each row
//!   measured against curl 8.21.0, and it refuses the pairs curl refuses:
//!   two flags that each name a different method, such as `-I` with `-d`.
//! - `--limit-rate` and `--max-filesize` take a `k`, `M`, or `G` suffix the
//!   way curl does. An unrecognised suffix is a usage error, not bytes
//!   silently read as part of the number.
//!
//! `-L`/`--location` turns redirect following on. `Transfer.Options.redirects`
//! defaults to following, because `curl_transport.zig`, the file this
//! package replaces, set `CURLOPT_FOLLOWLOCATION` unconditionally. curl's own
//! command-line default is the opposite: no `-L` means no redirect is
//! followed, only reported. So `parse` writes `options.redirects` itself
//! instead of leaving it at the library default: `.unfollowed` with no `-L`,
//! `.{ .follow = curl_default_max_redirects }` with `-L` and no
//! `--max-redirs`. `--max-redirs` sets the limit `-L` follows to; given with
//! no `-L`, it changes nothing, matching curl's own manual: "When --location
//! or --follow are used, this option prevents curl from following too many
//! redirects."
//!
//! `-o`, `-O`, and `-D` are captured into `OutputSpec` here, but nothing
//! opens a file: writing the body and validating a `-O` name pulled from an
//! untrusted url are `src/cli/output.zig`'s job. Likewise `--netrc-file`
//! captures a path into `Plan.netrc_path`; reading that file into
//! `Transfer.Options.netrc_text` happens wherever the plan is executed, not
//! here.
//!
//! A plain `error.UnknownFlag` cannot say which flag was unknown, and
//! argv's own fault needs to reach whoever prints it. `Fault` carries that
//! sentence the way `zurl_core.Diagnostics` carries detail alongside a
//! transfer error: an optional out-parameter the caller may pass `null` to
//! ignore.
//!
//! `-K`/`--config` and `-q`/`--disable` are recognised by `parse` itself,
//! since they are ordinary flags in argv, but neither does anything here:
//! `parse` never opens a file. `parseWithConfigFiles` is the impure
//! entry point that reads a config file's text, turns it into argv-shaped
//! tokens with `expandConfig`, and hands `parse` those tokens followed by
//! the real command line, so a command-line flag still wins over the same
//! option from a file.
//!
//! Each of those tokens carries a `Source`, the config file and the line
//! it came from, so a fault reads `zurl: rc.conf:3: unknown flag:
//! '--evIL'` and not as though the user had typed it. `walk` is the one
//! place that attaches it, so a fault added below cannot forget.
//!
//! A fault in the *default* config file is a warning and the run goes on,
//! and a fault in a `-K` file stops the run. That is curl's own split,
//! measured. See `ConfigKind`.

const std = @import("std");
const zurl = @import("zurl");
const zurl_core = @import("zurl-core");
/// Imported for its two `blksize` bounds alone. `--tftp-blksize` is
/// checked here, before any datagram, and the numbers that bound it belong
/// to the package that writes the request.
const zurl_tftp = @import("zurl-tftp");
const safe = @import("safe.zig");
const Transfer = zurl.Transfer;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Where the response body and headers go. `-o`, `-O`, and `-D` fill this;
/// `src/cli/output.zig` acts on it.
pub const OutputSpec = struct {
    /// One destination for each `-o` and each `-O`, in the order the
    /// command line named them. Url *n* uses element *n*. Read it through
    /// `bodyTarget`, which answers for a url past the end too.
    ///
    /// **This is curl's rule, measured.** curl 8.21.0 keeps one ordered
    /// list of output destinations and pairs it with the url list:
    ///
    /// - `-o a URL1 URL2` writes URL1 to `a` and URL2 to standard output.
    /// - `-o a -o b URL1 URL2` writes URL1 to `a` and URL2 to `b`.
    /// - `-O -O URL1 URL2` writes one file for each url.
    /// - `-o a -O URL1 URL2` mixes the two in the same list, so `-o` and
    ///   `-O` together is not a fault.
    /// - `-o a -o b -o c URL1 URL2` leaves `c` unused, and creates no
    ///   third file.
    ///
    /// zurl used to hold one destination for the whole run, so url *n*
    /// truncated the file url *n-1* had just written and the run still
    /// exited 0. The list is what closes that.
    body: []const BodyTarget = &.{},
    /// Where a url past the end of `body` writes.
    ///
    /// `.stdout` is the default and it is curl's own: `-o a URL1 URL2`
    /// writes `URL1` to the file and `URL2` to standard output.
    ///
    /// `--remote-name-all` makes it `.url_name`, so every uncovered url
    /// writes a file named from its own last path element, and
    /// `--out-null` makes it `.discard`. Measured against curl 8.21.0 on
    /// a loopback listener: `--remote-name-all URL1 URL2` wrote one file
    /// for each url and nothing to standard output, and `--out-null` with
    /// two urls wrote nothing anywhere and still exited 0.
    ///
    /// The last of the two flags wins, which is what curl does. Neither
    /// one replaces an `-o` or an `-O` the user wrote: `body` is read
    /// first, and this answers for the tail alone.
    tail: BodyTarget = .stdout,
    /// `-D`: also write the response headers to this destination.
    ///
    /// One destination for the whole run, and not a list. Measured: `-D h1
    /// -D h2` writes `h2` only, so a later `-D` replaces an earlier one
    /// instead of pairing with the next url. Each url appends its own head
    /// blocks to that one destination.
    headers_file: ?HeadersTarget = null,

    /// Where the body of url `index` goes.
    ///
    /// A url past the last `-o`/`-O` goes to standard output, which is
    /// what curl does with `-o a URL1 URL2`.
    pub fn bodyTarget(spec: OutputSpec, index: usize) BodyTarget {
        return if (index < spec.body.len) spec.body[index] else spec.tail;
    }

    /// Whether the body of url `index` goes to standard output.
    ///
    /// `src/cli/run.zig` reads this to decide whether that url draws a
    /// progress meter. A body on standard output shares the screen with
    /// the meter whenever standard output is a terminal, and curl draws
    /// nothing there.
    pub fn bodyToStdout(spec: OutputSpec, index: usize) bool {
        return switch (spec.bodyTarget(index)) {
            .stdout => true,
            .file, .url_name, .discard => false,
        };
    }

    /// Whether any of `url_count` urls writes its body to standard output.
    ///
    /// `src/cli/run.zig` reads this to decide whether transfers may overlap:
    /// standard output is one stream with one buffer, and two workers
    /// writing a body into it would race on that buffer's end index.
    pub fn anyToStdout(spec: OutputSpec, url_count: usize) bool {
        // The tail answers for every url past `body`, so a tail that
        // writes no body to standard output leaves the stream free even
        // when the list is short. `--remote-name-all` and `--out-null`
        // are what put a tail there.
        if (spec.tail != .stdout) return false;
        return spec.body.len < url_count;
    }
};

pub const BodyTarget = union(enum) {
    /// No `-o` or `-O` covers this url, or `-o -` named standard output
    /// outright. Both read the same way from here on: see `applyEffect`'s
    /// `.output_file` case for the measurement behind treating `-o -` as
    /// this variant instead of a file named `-`.
    stdout,
    /// `-o`: an explicit path. Never `-`; that spells `.stdout` instead.
    file: []const u8,
    /// `-O`: derive the name from the url's last path segment.
    url_name,
    /// `--out-null`: throw the body away. No file is opened and nothing
    /// reaches standard output.
    ///
    /// **The transfer still runs.** curl reads the whole body and reports
    /// the status, the timings, and the size, and `-w` still prints them.
    /// The flag is for a run that wants the answer and not the bytes,
    /// such as a health check or a benchmark. Measured against curl
    /// 8.21.0: `--out-null` wrote nothing and exited 0.
    discard,
};

/// How one `-d`, `--data-raw`, `--data-binary`, `--data-urlencode`, or
/// `--json` argument is read.
///
/// Each spelling reads its argument differently, and the difference is
/// visible on the wire. Measured against curl 8.21.0 with a loopback
/// listener and a file holding `a=1\nb=2\n`:
///
/// ```
/// -d @file             a=1b=2          6 bytes, the newlines gone
/// --data-ascii @file   a=1b=2          the same flag under another name
/// --data-binary @file  a=1\nb=2\n      8 bytes, the file byte for byte
/// --data-raw @file     @file           the text, and no file is opened
/// --data-urlencode @f  x+y%26z%0A      percent encoded, nothing dropped
/// ```
pub const DataKind = enum {
    /// `-d`, `--data`, and `--data-ascii`. `@name` reads a file and drops
    /// every CR and LF in it. `@-` reads standard input the same way.
    ascii,
    /// `--data-raw`. The argument is the data, and a leading `@` is data
    /// too.
    raw,
    /// `--data-binary`. `@name` reads a file byte for byte.
    binary,
    /// `--data-urlencode`. The argument names what to encode and, for
    /// some forms, a name to put in front of it. See `body.zig`.
    urlencode,
    /// `--json`. The argument is the data, like `--data-raw`, and the flag
    /// also asks for the two JSON headers.
    json,
};

/// One `-d`-family argument, in the order the command line gave it.
pub const DataItem = struct {
    kind: DataKind,
    /// The argument text, exactly as it was typed. No file is opened here:
    /// `parse` does no I/O, so `src/cli/body.zig` reads any `@name` later.
    text: []const u8,
};

/// How one `-F` or `--form-string` argument is read.
///
/// The two spellings differ in one rule, and the difference is the whole
/// reason the second exists. Measured against curl 8.21.0:
///
/// ```
/// -F 'n=@a.txt'            the file a.txt, with a filename and a type
/// --form-string 'n=@a.txt' the six characters @a.txt
/// -F 'n=va;lue'            va, because a ; starts a parameter
/// --form-string 'n=va;lue' va;lue
/// ```
pub const FormKind = enum {
    /// `-F`/`--form`. A leading `@` names a file to upload, a leading `<`
    /// names a file whose content is the value, and a `;` starts a
    /// parameter.
    form,
    /// `--form-string`. Everything behind the first `=` is the value, byte
    /// for byte.
    string,
};

/// One `-F` or `--form-string` argument, in the order the command line
/// gave it.
pub const FormItem = struct {
    kind: FormKind,
    /// The argument text, exactly as it was typed. Nothing is parsed and
    /// no file is opened here: `parse` does no I/O, so `src/cli/form.zig`
    /// reads the syntax and opens the files later.
    text: []const u8,
};

/// What the command line said about the request body.
///
/// `parse` fills this and opens nothing. `src/cli/body.zig` turns it into
/// the bytes that go on the wire, because that step reads files and this
/// one does no I/O.
pub const RequestBody = struct {
    /// Every `-d`-family argument, in command-line order. curl joins them
    /// into one body. See `body.zig` for the separator each kind adds.
    data: []const DataItem = &.{},
    /// Every `--url-query` argument, in command-line order.
    ///
    /// **These land in the url query and never in the body.** That is the
    /// whole difference from `-G`, which moves the `-d` data there and
    /// leaves the request with no body at all. `--url-query` adds to the
    /// query and lets a body go out beside it, so `-d` and `--url-query`
    /// on one command line send both. Measured against curl 8.21.0:
    /// `--url-query 'ab=c' 'http://h/p?x=1'` sent `GET /p?x=1&ab=c`.
    ///
    /// Every entry is read the way `--data-urlencode` reads its argument,
    /// which is what curl documents: the flag is "--data-urlencode for the
    /// query part". So `name=text`, `name@file`, `@file`, and a bare
    /// `text` all work, and `src/cli/body.zig` is the one reader.
    query: []const DataItem = &.{},
    /// Every `-F` and `--form-string` argument, in command-line order.
    /// Empty for a command line that named no form part.
    form: []const FormItem = &.{},
    /// `--form-escape`: write a quote and a backslash in a form header
    /// with a backslash in front, rather than percent-encoded. A CR and an
    /// LF stay percent-encoded either way. See
    /// `zurl.multipart.Escape`.
    form_escape: bool = false,
    /// `-T`/`--upload-file`: the path to send. `-` names standard input.
    /// Null when the flag was not given.
    upload: ?[]const u8 = null,
    /// `-G`/`--get`: put the data in the url's query instead of in a body.
    get: bool = false,
    /// `-I`/`--head`: ask for the head alone.
    head: bool = false,
    /// The `Content-Type` the `-d` family implies, or null when the
    /// command line implies none.
    ///
    /// **It rides on the body and not among the headers.** A redirect that
    /// drops the body drops this with it, which is what curl does:
    /// measured, `-L -d 'a=1'` through a `302` sends a `GET` with no
    /// `Content-Type`, and the same chain with `-H 'Content-Type:
    /// text/plain'` keeps that header, because a header the user wrote is
    /// the user's. So a `-H` of this name lands in `options.headers` and
    /// leaves this null.
    ///
    /// Null for three flags. `--json`'s two headers are ordinary headers
    /// that survive a redirect, measured. `-G` sends no body. `-T` names
    /// no content type at all.
    content_type: ?[]const u8 = null,
};

/// Where `-D` writes the response head blocks.
pub const HeadersTarget = union(enum) {
    /// `-D -`: standard output. curl 8.21.0 treats `-D -` as standard
    /// output the same way it treats `-o -`, measured.
    stdout,
    /// `-D`: an explicit path. Never `-`; that spells `.stdout` instead.
    file: []const u8,
};

/// Where `-c`/`--cookie-jar` writes the jar after the run.
///
/// The same two shapes `-D` has, and for the same measured reason: curl
/// 8.21.0 treats `-c -` as standard output and writes the jar there.
pub const CookieJarTarget = union(enum) {
    /// `-c -`: standard output.
    stdout,
    /// `-c`: an explicit path. Never `-`; that spells `.stdout` instead.
    file: []const u8,
};

/// A flag this build reads on the command line and will not run with.
///
/// **A refusal by name is better than a flag accepted and dropped.** A
/// dropped flag leaves the user believing something happened: a client
/// certificate that never went out reads as a server that refused it, and
/// a cipher list that changed nothing reads as a policy that was applied.
/// Neither reading is corrected by anything the run prints afterwards, so
/// the run stops instead, with the flag and the reason on standard error.
///
/// This is not the same seam as an unknown flag. An unknown flag is a
/// spelling zurl has never heard of. A flag here is one zurl knows, one
/// `--help` lists, and one that says in its own help line that it is
/// refused.
pub const UnsupportedFlag = struct {
    /// The spelling as the user wrote it, such as `--cert` or `-E`. It is
    /// untrusted text and must reach a message through `src/cli/safe.zig`.
    flag: []const u8,
    /// One sentence saying why this build cannot honour the flag. Written
    /// here, so it is a constant and never user text.
    reason: []const u8,
};

/// The result of a successful parse: what to fetch, and how.
pub const Plan = struct {
    urls: []const []const u8,
    options: Transfer.Options,
    output: OutputSpec = .{},
    /// What the command line said about the request body. Unresolved: see
    /// `RequestBody`, and `src/cli/body.zig`, which reads the files it
    /// names and fills `options.body`.
    request_body: RequestBody = .{},
    /// `-w`/`--write-out`: an unparsed format string. `src/cli/writeout.zig`
    /// reads it.
    write_out: ?[]const u8 = null,
    silent: bool = false,
    show_error: bool = false,
    /// `--progress-bar`: draw a bar instead of the default meter.
    progress_bar: bool = false,
    /// `--no-progress-meter`: draw no meter, and keep every message.
    ///
    /// Not the same flag as `-s`. `-s` also hides the message a failed
    /// transfer prints; this hides the meter alone. Measured against curl
    /// 8.21.0: `--no-progress-meter` on a refused connection still writes
    /// `curl: (7) ...` to standard error, and `-s` writes nothing.
    no_progress_meter: bool = false,
    parallel: bool = false,
    /// `--netrc-file`'s path. Unread: see the module doc comment.
    netrc_path: ?[]const u8 = null,
    /// `--netrc`, `-n`, and `--netrc-optional`: read the default netrc
    /// file. `src/main.zig` owns the path search, because `parse` opens
    /// nothing.
    netrc_mode: NetrcMode = .off,
    /// `-m`/`--max-time`: a bound on the whole transfer, not on the
    /// connect alone.
    ///
    /// **Held here and not in `Transfer.Options`.** The library hands the
    /// caller a response body to read, and the read happens after
    /// `Client.perform` has returned, so no field of `Options` could bound
    /// it. `src/cli/run.zig` owns the bound, because that file is what
    /// drains the body. `.none` waits for as long as the peer does, which
    /// is what curl's own `-m 0` means, measured.
    max_time: std.Io.Timeout = .none,
    /// `--create-dirs`: create the directory tree an `-o` path names.
    create_dirs: bool = false,
    /// `--skip-existing`: leave a url alone when its output file is
    /// already there.
    ///
    /// **The decision happens before the transfer starts**, which is what
    /// the flag is for: a run that skips has opened no socket and sent no
    /// request. That is what makes it different from `--no-clobber`,
    /// which fetches the body and then writes it under another name.
    ///
    /// It reads a url whose destination is a real path, which is `-o` and
    /// `-O`. A url that writes to standard output has no file to find, so
    /// the flag passes it through. Measured against curl 8.21.0: with a
    /// file already there, `--skip-existing -o x` left the file byte for
    /// byte as it was and exited 0.
    skip_existing: bool = false,
    /// `--dump-ca-embed`: write the trust bundle this binary carries to
    /// standard output, and run no transfer.
    ///
    /// **It answers even for a command line that names a url.** curl does
    /// the same, measured: `curl --dump-ca-embed http://...` wrote the
    /// bundle and fetched nothing. `src/main.zig` acts on it, because
    /// `parse` writes nothing.
    dump_ca_embed: bool = false,
    /// `--no-clobber`: never overwrite a file that already exists.
    /// `--clobber` puts it back to false, so the pair reads in either
    /// order and the last one wins.
    no_clobber: bool = false,
    /// `-v`, `--verbose`: say what the transfer did, on standard error.
    ///
    /// **A verbose run prints no credential, and that is a rule and not a
    /// habit.** It writes no request header at all, so an `Authorization`
    /// line zurl built or a `-H` line the user wrote cannot reach the
    /// output. Every other string goes through `src/cli/safe.zig`, which
    /// masks a userinfo password and drops a control byte. See
    /// `src/cli/run.zig`'s `verboseNote`.
    verbose: bool = false,
    /// `-i`, `--show-headers`, `--include`: write the response head to the
    /// body's own destination, before the body.
    ///
    /// Not the same flag as `-D`. `-D` names a file of its own and writes
    /// the head of every hop into it. This writes the head of the last hop
    /// where the body goes, which is what curl's `-i` does.
    show_headers: bool = false,
    /// `--stderr`: the file every message goes to, or null for standard
    /// error. The text `-` names standard output.
    stderr_path: ?[]const u8 = null,
    /// `--output-dir`: the directory every `-o` and `-O` file goes under,
    /// or null when each path stands on its own.
    output_dir: ?[]const u8 = null,
    /// `--create-file-mode`: the octal mode a file zurl creates gets, or
    /// null for the default of the platform.
    create_file_mode: ?u32 = null,
    /// `--remove-on-error`: delete the output file when the transfer
    /// failed, instead of leaving what did arrive.
    remove_on_error: bool = false,
    /// `-R`, `--remote-time`: give the output file the `Last-Modified`
    /// time the server sent, instead of the time of the write.
    remote_time: bool = false,
    /// `-J`, `--remote-header-name`: take the `-O` file name from the
    /// response's own `Content-Disposition` header.
    ///
    /// **This is the one flag that lets a server name a file zurl
    /// writes.** `-O` reads the url the user typed; `-J` reads a header
    /// the peer wrote. `src/cli/output.zig`'s `nameFromDisposition` is
    /// the only reader, and it answers through the very same `checkName`
    /// that judges a `-O` name, so the two flags share one rule and there
    /// is no second copy to drift.
    ///
    /// It changes nothing without `-O`. Measured against curl 8.21.0:
    /// `-J` alone wrote the body to standard output, and `-J -o named`
    /// wrote `named`, so the flag reads only a url whose destination is
    /// `-O`.
    remote_header_name: bool = false,
    /// `--etag-compare`: the file whose text goes out as `If-None-Match`,
    /// or null when the flag was not given.
    ///
    /// Nothing is opened here. `parse` does no I/O, so `src/main.zig`
    /// reads the file, the same way it reads a `--netrc-file`.
    etag_compare: ?[]const u8 = null,
    /// `--etag-save`: the file the response's own `ETag` goes into after
    /// the transfer, or null when the flag was not given.
    etag_save: ?[]const u8 = null,
    /// `-z`, `--time-cond`: the argument exactly as the command line wrote
    /// it, prefix and all, or null when the flag was not given.
    ///
    /// Unresolved on purpose. The argument may name a file, and reading a
    /// file's timestamp is I/O, which `parse` never does. `src/main.zig`
    /// splits the prefix off with `src/cli/timecond.zig`, reads the
    /// moment, and adds the one header.
    time_cond: ?[]const u8 = null,
    /// `--rate`: how long a serial run waits between the start of one
    /// transfer and the start of the next, in milliseconds. Null when the
    /// flag was not given.
    ///
    /// Held as a wait and not as a rate, because a wait is what
    /// `src/cli/run.zig` acts on. See `parseRate` for the grammar and the
    /// bounds, both measured.
    rate_wait_ms: ?u64 = null,
    /// `--parallel-max-host`: the largest number of transfers `-Z` may run
    /// at once against one host. Null keeps the run at `--parallel-max`.
    ///
    /// **zurl reads it as a bound on the whole run, which is stricter than
    /// curl's own per-host bound.** Each `-Z` worker holds one `Client`
    /// and runs one url at a time, so a run of *n* workers opens at most
    /// *n* connections and at most *n* of them can reach any one host.
    /// Capping the workers therefore keeps the promise for every host,
    /// whatever mix of hosts the url list holds. A run over several hosts
    /// may use fewer workers than curl would; it never uses more than the
    /// flag allows. `src/cli/run.zig` writes a note when the cap is what
    /// decided the count, so the narrower reading is never silent.
    parallel_max_host: ?usize = null,
    /// The first flag this build accepts and cannot run, or null when the
    /// command line named none.
    ///
    /// **Refused by name, and never accepted and dropped.** Each flag
    /// here asks for something that fails quietly when it is ignored: a
    /// client certificate that never goes out reads to a user like a
    /// server that refused it, and a cipher list that changed nothing
    /// reads like a policy that was applied. `src/main.zig` prints the
    /// sentence and stops the run before any socket opens.
    unsupported_flag: ?UnsupportedFlag = null,
    /// `--fail-with-body`: an HTTP error status is a failure, and the body
    /// is still written.
    ///
    /// This is not `options.fail_on_error`. That field stops the transfer
    /// before the body reaches the caller, which is what `--fail` does.
    /// The two are mutually exclusive and the last one on the command line
    /// wins, measured: `--fail --fail-with-body` writes the body and
    /// `--fail-with-body --fail` does not. Both exit 22.
    fail_with_body: bool = false,
    /// `--fail-early`: stop at the first url that fails, instead of
    /// running every url the command line named.
    fail_early: bool = false,
    /// The proxy authentication flag this build refuses, or null when none
    /// was given.
    ///
    /// **`--proxy-digest` and `--proxy-anyauth` are refused and never
    /// downgraded.** Only `Basic` is built, and a user who asked for
    /// `Digest` asked for a scheme where the password never travels.
    /// Answering with `Basic` would put that password on the wire in
    /// reversible base64, to a proxy, in cleartext. `src/main.zig` prints
    /// the sentence and stops the run.
    proxy_auth_refused: ?[]const u8 = null,
    /// `-C`/`--continue-at`: where to resume a transfer from. Null when
    /// the flag was not given.
    resume_at: ?ResumeAt = null,
    /// `-r`/`--range`: the byte range to ask for, already carrying the
    /// `bytes=` prefix, so it is the `Range` header value byte for byte.
    /// Null when the flag was not given.
    ///
    /// **`-r` and `-C` are refused together**, which is curl's own answer:
    /// measured, `curl -r 0-99 -C 5 URL` exits 2 with `--continue-at is
    /// mutually exclusive with --range`, and no socket opens. Both flags
    /// write the one `Range` header, so a command line that names both
    /// names two answers to one question.
    range: ?[]const u8 = null,
    /// The `--retry` family. See `Retry`, which carries every measurement.
    retry: Retry = .{},
    /// `--parallel-max`: how many transfers `-Z` may run at once. Null
    /// keeps zurl's own default of eight.
    ///
    /// curl reads a value outside 1 to 300 as though the flag were not
    /// there. `src/cli/run.zig` does the same and writes a note, because
    /// a number silently thrown away is recovery with no word to the user.
    parallel_max: ?usize = null,
    /// One line for each option the *default* config file named and this
    /// build could not use. Arena-owned, already sanitised, and each one
    /// names the file and the line it came from.
    ///
    /// curl treats its own default config file as advice, not as a
    /// command line: an option it cannot use there is a warning and the
    /// run goes on. `src/main.zig` writes these to standard error before
    /// the first transfer, under the same `-s` and `-S` rule every other
    /// note follows.
    warnings: []const []const u8 = &.{},
    /// `-b`/`--cookie`: every jar file the command line named, in order.
    ///
    /// **A `-b` value that holds an `=` is cookie text, and one that does
    /// not names a file.** That is curl's own rule, and it is decided
    /// here, in `applyEffect`: text goes into a `Cookie` header among
    /// `options.headers`, and a path lands in this list.
    ///
    /// Nothing here is opened. `parse` does no I/O, so `src/main.zig`
    /// reads each file into the `zurl.Jar` it builds, the same way it
    /// reads a `--netrc-file`.
    cookie_files: []const []const u8 = &.{},
    /// `-c`/`--cookie-jar`: where the jar goes after the run, or null when
    /// the flag was not given.
    cookie_jar: ?CookieJarTarget = null,
    /// `-j`/`--junk-session-cookies`: drop the session cookies a jar file
    /// holds, rather than load them.
    ///
    /// Measured against curl 8.21.0: `-b jar -j` sent only the cookies of
    /// that file that carried an expiry, and a session cookie a server set
    /// during the same run was still sent. So the flag acts on the load.
    junk_session_cookies: bool = false,
    /// Whether any cookie flag was given at all.
    ///
    /// **This is what turns the cookie engine on.** curl keeps no cookie
    /// unless `-b`, `-c`, or `-j` asked it to: measured with two urls in
    /// one invocation, a plain run dropped the `Set-Cookie` of the first
    /// and sent no `Cookie` header on the second. zurl reads this one
    /// field so that a run with no cookie flag reaches the wire byte for
    /// byte as it did before cookies existed.
    cookies_enabled: bool = false,
};

/// Which default netrc file, if any, the run must read.
///
/// `--netrc-file` is a different flag and keeps its own field: it names an
/// explicit path, and a path the user named and zurl cannot read is a
/// usage fault. These two ask for the *default* file instead, and they
/// differ only in what a missing file means.
///
/// Measured against curl 8.21.0, with `HOME` pointed at a directory that
/// holds no `.netrc`:
///
/// ```
/// curl --netrc URL            exit 26, and no request goes out
/// curl --netrc-optional URL   exit 0,  and the request goes out with no credential
/// ```
pub const NetrcMode = enum {
    /// Neither flag was given. No default file is read.
    off,
    /// `--netrc` or `-n`. A file that cannot be read stops the run.
    required,
    /// `--netrc-optional`. A file that cannot be read is not a fault.
    optional,
};

/// What `-C`/`--continue-at` asks for.
///
/// Measured against curl 8.21.0 with a loopback server that answers a
/// `Range` request with `206`:
///
/// ```
/// -C -  and a 5 byte file      Range: bytes=5-   the answer is appended
/// -C -  and no file at all     no Range header   the whole body is written
/// -C 5  and any file           Range: bytes=5-   the answer is written at offset 5
/// -C -  and -o -               no Range header   nothing can be measured
/// ```
///
/// A server that answers `200` to a request that carried a `Range` header
/// is exit 33, and the file keeps the bytes it already held. curl calls
/// that `CURLE_RANGE_ERROR`.
pub const ResumeAt = union(enum) {
    /// `-C -`: read the offset off the destination file. A destination
    /// that is standard output, or a file that does not exist, gives zero,
    /// and zero sends no `Range` header at all.
    file_size,
    /// `-C <n>`: the offset the user named. Zero sends no `Range` header
    /// either, the same as no flag at all.
    offset: u64,
};

/// What the `--retry` family asks for.
///
/// **Every rule here was measured against curl 8.21.0 on a loopback
/// server that logs each request with the seconds since the first one.**
/// `src/cli/run.zig` acts on this; `Args` only reads the flags.
///
/// Which failures a bare `--retry` covers:
///
/// ```
/// 408, 429, 500, 502, 503, 504   two tries with --retry 1
/// 400, 401, 403, 404, 405, 409, 425, 501, 507   one try
/// a transfer that ran out of time   three tries with --retry 2
/// a refused connection              one try
/// a body that stopped short         one try
/// ```
///
/// So the transient statuses and a timeout are the whole default set. A
/// refused connection joins it with `--retry-connrefused`, and every
/// other failure joins it with `--retry-all-errors`.
///
/// `--retry-all-errors` reads the *failure*, not the status: measured,
/// `--retry-all-errors` alone on a `404` sends one request, and
/// `--retry-all-errors --fail` on the same `404` sends three, because
/// `--fail` turns the status into a failure.
///
/// The wait between two tries:
///
/// ```
/// --retry 4                 tries at 0, 1, 3, 7, and 15 seconds
/// --retry 3 --retry-delay 2 tries at 0, 2, 4, and 6 seconds
/// --retry 3 --retry-delay 0 tries at 0, 1, 3, and 7 seconds
/// --retry 10 --retry-max-time 5   tries at 0, 1, 3, and 7 seconds
/// ```
///
/// So the wait starts at one second and doubles, a `--retry-delay` holds
/// it still, and `--retry-delay 0` reads as no delay named at all.
/// `--retry-max-time` bounds when a try may *start*: the last row started
/// a try at 3 seconds, under the bound of 5, and waited 4 seconds for it.
pub const Retry = struct {
    /// `--retry`: how many times more to send the request. Zero is the
    /// default and asks for no retry at all.
    attempts: u32 = 0,
    /// `--retry-delay`: a fixed wait in seconds. Null asks for the
    /// doubling wait, and so does `--retry-delay 0`, measured.
    delay_s: ?u32 = null,
    /// `--retry-max-time`: no try may start once this many seconds have
    /// passed since the first one. Zero is no bound, which is curl's own
    /// default and its own reading of `0`.
    max_time_s: u32 = 0,
    /// `--retry-connrefused`: a refused connection is a failure to retry.
    connrefused: bool = false,
    /// `--retry-all-errors`: every failure is one to retry.
    all_errors: bool = false,

    /// Whether any retry was asked for at all.
    pub fn enabled(r: Retry) bool {
        return r.attempts != 0;
    }
};

/// Where a token came from, when it did not come from the command line.
///
/// curl names both parts in the same shape: `curl: rc.conf:1 config file
/// option 'evIL' is unknown`. Without them, a fault from a `~/.curlrc`
/// reads as a fault in what the user just typed, and a user cannot tell
/// which of three candidate files is wrong.
pub const Source = struct {
    /// The config file's path, as `-K` or the environment named it.
    file: []const u8,
    /// The line in that file, counting from 1.
    line: u32,
    /// Whether a fault from this line is advice rather than a usage
    /// fault. True for the default config file and false for a `-K` file.
    /// See `ConfigKind`.
    advisory: bool = false,
};

/// Detail for a `ParseError`. `parse` fills `message` before it returns an
/// error whenever the caller passes a non-null pointer.
pub const Fault = struct {
    /// Arena-owned. Names the offending flag, or the limitation that
    /// refused it. Already carries the `file:line` prefix when `source` is
    /// set, so a printer needs no second rule.
    message: []const u8 = "",
    /// Which config file and line the fault came from, or null when it
    /// came from the command line.
    source: ?Source = null,
};

/// Puts `source`'s file and line in front of the sentence `fault` already
/// holds.
///
/// Does nothing when there is no fault to fill, when the token came from
/// the command line, or when a source is already recorded: the first
/// source that reaches a fault is the one nearest the fault.
fn attributeFault(arena: Allocator, fault: ?*Fault, source: ?Source) Allocator.Error!void {
    const f = fault orelse return;
    const s = source orelse return;
    if (f.source != null) return;
    f.source = s;
    f.message = try prefixSource(arena, s, f.message);
}

/// Returns `message` with `source`'s file and line in front of it.
///
/// The file path comes from a `-K` argument or from the environment, so it
/// goes through `safe.Text` like every other untrusted string zurl prints.
/// Every message this file builds already starts with `zurl: `, and the
/// prefix goes after that word, so the line still opens with the program's
/// name the way every other line does.
fn prefixSource(arena: Allocator, source: Source, message: []const u8) Allocator.Error![]const u8 {
    const opening = "zurl: ";
    const tail = if (std.mem.startsWith(u8, message, opening)) message[opening.len..] else message;
    return std.fmt.allocPrint(
        arena,
        "zurl: {f}:{d}: {s}",
        .{ safe.text(source.file), source.line, tail },
    );
}

/// Every member names one class of usage fault. None of these mean zurl's
/// own code is broken; they all mean argv said something parse cannot act
/// on.
pub const ParseError = error{
    UnknownFlag,
    MissingArgument,
    InvalidNumber,
    InvalidSizeSuffix,
    InvalidMethod,
    /// Two flags on one command line each named a different method. curl
    /// 8.21.0 answers this with exit 2 and `You can only select one HTTP
    /// request method!`, before any socket. Measured: `-I -d a=1`, `-I -T
    /// f`, and `-T f -d a=1` each report it, and `-I -X POST` and `-I -G`
    /// do not, because `-X` names the method text and `-G` moves the data
    /// rather than name a method.
    ConflictingMethods,
    /// `--proto` or `--proto-redir` was given a list zurl could not use: a
    /// list that leaves no protocol enabled, or one past either bound in
    /// `zurl_core.redirect.Set`. curl 8.21.0 answers the first with exit
    /// 2 and `option --proto: is badly used here`, before any transfer.
    InvalidProtocolList,
    /// `--proto-default` was given a name no protocol carries. curl 8.21.0
    /// answers this with **exit 1** and `option --proto-default: a
    /// specified protocol is unsupported by libcurl`, and not with the
    /// usage code, so `src/main.zig` gives this one member its own exit
    /// code. Measured, with a url that already carried a scheme: curl
    /// still refuses before any transfer.
    UnsupportedProtocolName,
    /// `--proto-default` was given an empty name. curl answers this with
    /// exit 2 and `option --proto-default: blank argument where content is
    /// expected`.
    MissingProtocolName,
    /// `--tls-max` was given a value curl does not read. curl 8.21.0 takes
    /// `default`, `1.0`, `1.1`, `1.2`, and `1.3`, and answers every other
    /// value with exit 2 and `option --tls-max: is badly used here`.
    InvalidTlsVersion,
    /// `-x`, a `--socks` flag, or a proxy environment variable named a
    /// proxy that is not a usable host and port. curl 8.21.0 answers a bad
    /// proxy port with **exit 5**, `CURLE_COULDNT_RESOLVE_PROXY`, and not
    /// with the usage code, so `src/main.zig` gives this member that code.
    /// Measured with `-x http://127.0.0.1:notaport`.
    InvalidProxy,
    /// A proxy url named a scheme this build does not speak. curl 8.21.0
    /// prints `Unsupported proxy scheme` and answers with **exit 7**,
    /// `CURLE_COULDNT_CONNECT`. Measured with `-x ftp://127.0.0.1`.
    UnsupportedProxyScheme,
    /// A `--tlsv1.x` flag and a `--tls-max` on one command line left no
    /// version between them. curl reports this while it parses, exits 2,
    /// and never opens a socket. See `applyEffect` for the two messages
    /// and for why the order of the two flags decides which one prints.
    TlsVersionRangeEmpty,
    /// `-K`/`--config` named a file `parseWithConfigFiles` could not open
    /// or read. A missing *default* config file is not this: it is
    /// silent, per curl's own manual.
    ConfigFileUnreadable,
    /// A `-K`/`--config` file was larger than `max_config_file_bytes`.
    ConfigFileTooLarge,
    /// A config file's line failed to parse: a quoted value with no
    /// closing quote, or one longer than `max_config_value_bytes`.
    ConfigFileMalformed,
    /// A config file named more options than `max_config_options`.
    ConfigFileTooManyOptions,
    /// A config file itself named `-K`/`--config`. `parse` refuses this so
    /// a file cannot pull in an unbounded chain of further files.
    ConfigFileNested,
    /// `-r`/`--range` and `-C`/`--continue-at` were both given. Both write
    /// the one `Range` header, so the pair names two answers to one
    /// question. curl 8.21.0 refuses it with exit 2 and `--continue-at is
    /// mutually exclusive with --range`, before any socket. Measured.
    ConflictingRangeAndResume,
    /// `-J`/`--remote-header-name` and `-C`/`--continue-at` were both
    /// given. `-C` reads the length of the file it will add to, and `-J`
    /// does not learn the name of that file until the response head has
    /// arrived, which is after the request that carries the `Range`
    /// header has gone out. curl 8.21.0 refuses the pair for the same
    /// reason, with exit 2 and `--continue-at and --remote-header-name
    /// cannot be combined`. Measured against the real program.
    ConflictingResumeAndHeaderName,
    /// A `--resolve` or `--connect-to` entry did not read. curl 8.21.0
    /// answers this with **exit 49**, `CURLE_SETOPT_OPTION_SYNTAX`, and
    /// the sentence `Could not parse CURLOPT_RESOLVE entry`. It reports it
    /// at the transfer and not at the parse; zurl reports it at the parse,
    /// which is earlier and never after a request has gone out.
    /// `src/main.zig` gives this member curl's own exit code.
    InvalidHostOverride,
    /// More `--resolve` and `--connect-to` entries than
    /// `max_host_overrides`. curl keeps no such bound. See that constant.
    TooManyHostOverrides,
    /// More `--mail-rcpt` entries than `max_recipients`. curl keeps no
    /// such bound. See that constant.
    TooManyRecipients,
    /// `--cacert` named a file that does not exist. curl checks this when
    /// it parses the flag, before any transfer, and exits 2. `--capath`
    /// gets no such check: a real curl 8.21.0 run of `--capath
    /// /nonexistent` still reaches the TLS handshake and fails there
    /// instead, so `parseWithConfigFiles` checks `--cacert` alone.
    CacertMissing,
    /// `--disallow-username-in-url` was given and a url carried a user
    /// name. curl 8.21.0 answers this with **exit 67**,
    /// `CURLE_LOGIN_DENIED`, and the sentence `URL rejected: Credentials
    /// was passed in the URL when prohibited`, so `src/main.zig` gives
    /// this member that code. Measured with
    /// `--disallow-username-in-url http://alice@host/`.
    UsernameInUrl,
};

/// Parses `argv` into a `Plan`.
///
/// `arena` backs every allocation `parse` makes: the url list, the header
/// list, and any fault message. It must outlive the returned `Plan`.
///
/// `env` fills `options.ca`'s `curl_ca_bundle`, `ssl_cert_file`, and
/// `ssl_cert_dir` from `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, and `SSL_CERT_DIR`.
/// `parse` writes these unconditionally; it does not check whether a flag
/// such as `--cacert` was also given, because `zurl_core.ca.resolve` already
/// puts `--cacert` ahead of every environment variable. An environment
/// variable set to the empty string is read as unset, the same as a flag
/// that was never given, since an empty path names no file. Every value
/// borrows from `env`, so `env` must outlive the returned `Plan` the same
/// way `arena` must.
///
/// `fault` is optional. Pass `null` to ignore the message and act on the
/// error alone.
///
/// `-K`/`--config` and `-q`/`--disable` are recognised as flags here, so
/// argv naming them is not `error.UnknownFlag`, but neither has any effect
/// on the returned `Plan`: reading a file is `parseWithConfigFiles`'s job,
/// not this pure function's.
pub fn parse(
    arena: Allocator,
    argv: []const []const u8,
    env: *std.process.Environ.Map,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!Plan {
    return (try parseAttributed(arena, argv, &.{}, env, fault)).plan;
}

/// A finished parse, plus the one piece of attribution that outlives it.
const Parsed = struct {
    plan: Plan,
    /// Where `--cacert` came from, when a config file set it.
    /// `parseWithConfigFiles` checks that path exists after the parse, so
    /// it needs the source after the `Builder` has gone.
    cacert_source: ?Source = null,
};

/// `parse`, with one source for each token.
///
/// `sources` is parallel to `argv`, and an element is null for a token the
/// user typed. An empty `sources` means every token came from the command
/// line, which is what `parse` itself passes.
fn parseAttributed(
    arena: Allocator,
    argv: []const []const u8,
    sources: []const ?Source,
    env: *std.process.Environ.Map,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!Parsed {
    var b: Builder = .{ .arena = arena, .sources = sources };
    b.options.ca.curl_ca_bundle = envPath(env, "CURL_CA_BUNDLE");
    b.options.ca.ssl_cert_file = envPath(env, "SSL_CERT_FILE");
    b.options.ca.ssl_cert_dir = envPath(env, "SSL_CERT_DIR");

    try walk(&b, argv, fault);

    // Read after the whole command line has been seen, not inside
    // `applyEffect`, so flag order does not matter: `-L` before or after
    // `--max-redirs` reads the same, matching curl.
    b.options.redirects = if (b.location)
        .{ .follow = b.max_redirects_arg orelse curl_default_max_redirects }
    else
        .unfollowed;

    try resolveCustomRequest(&b, fault);
    try resolveProxy(&b, env, fault);
    try resolveRequestBody(&b, arena, fault);
    try resolveCookieHeader(&b, arena);
    try resolveRefererHeader(&b, arena);
    const range = try resolveRange(&b, arena, fault);
    try resolveHeaderName(&b, arena, fault);
    try resolveUsernameInUrl(&b, arena, fault);

    b.options.headers = try b.headers.toOwnedSlice(arena);
    b.options.connect_to = try b.overrides.toOwnedSlice(arena);
    b.options.mail_rcpt = try b.recipients.toOwnedSlice(arena);
    b.output.body = try b.output_targets.toOwnedSlice(arena);
    b.output.tail = b.output_tail;

    return .{
        .plan = .{
            .urls = try b.urls.toOwnedSlice(arena),
            .options = b.options,
            .output = b.output,
            .write_out = b.write_out,
            .silent = b.silent,
            .show_error = b.show_error,
            .progress_bar = b.progress_bar,
            .no_progress_meter = b.no_progress_meter,
            .parallel = b.parallel,
            .netrc_path = b.netrc_path,
            .netrc_mode = b.netrc_mode,
            .max_time = b.max_time,
            .create_dirs = b.create_dirs,
            .no_clobber = b.no_clobber,
            .skip_existing = b.skip_existing,
            .dump_ca_embed = b.dump_ca_embed,
            .verbose = b.verbose,
            .show_headers = b.show_headers,
            .stderr_path = b.stderr_path,
            .output_dir = b.output_dir,
            .create_file_mode = b.create_file_mode,
            .remove_on_error = b.remove_on_error,
            .remote_time = b.remote_time,
            .remote_header_name = b.remote_header_name,
            .etag_compare = b.etag_compare,
            .etag_save = b.etag_save,
            .time_cond = b.time_cond,
            .rate_wait_ms = b.rate_wait_ms,
            .parallel_max_host = b.parallel_max_host,
            .unsupported_flag = b.unsupported_flag,
            .fail_with_body = b.fail_with_body,
            .fail_early = b.fail_early,
            .proxy_auth_refused = b.proxy_auth_refused,
            .resume_at = b.resume_at,
            .range = range,
            .retry = b.retry,
            .parallel_max = b.parallel_max,
            .warnings = try b.notes.toOwnedSlice(arena),
            .cookie_files = try b.cookie_files.toOwnedSlice(arena),
            .cookie_jar = b.cookie_jar,
            .junk_session_cookies = b.junk_session_cookies,
            .cookies_enabled = b.cookies_enabled,
            .request_body = .{
                .data = try b.data_items.toOwnedSlice(arena),
                .query = try b.query_items.toOwnedSlice(arena),
                .form = try b.form_items.toOwnedSlice(arena),
                .form_escape = b.form_escape,
                .upload = b.upload,
                .get = b.get,
                .head = b.head,
                .content_type = b.body_content_type,
            },
        },
        .cacert_source = b.sourceOf(.cacert),
    };
}

/// The url schemes that read `-X`/`--request` as a whole command line
/// rather than as an HTTP method.
///
/// A mail protocol names its own commands, and none of them is an HTTP
/// method: POP3 has `TOP 1 0`, IMAP has `FETCH 1 BODY[]`, and SMTP has
/// `VRFY bob`. Each of the three is a value a user may write, and each
/// would be refused by the HTTP rule.
///
/// The list is by scheme and not by package, because `src/cli/run.zig` may
/// leave a package out of a build and the refusal below must not change
/// when it does. A url naming a scheme this build does not speak is
/// refused later, by name, with exit 1.
const custom_request_schemes = [_][]const u8{
    "pop3", "pop3s", "imap", "imaps", "smtp", "smtps",
    // `-X DESCRIBE rtsp://host/stream` names an RFC 2326 method and not
    // an HTTP one. `zurl-rtsp` reads it, and it refuses a method this
    // build does not send with its own sentence and exit 4.
    "rtsp",
};

/// Refuses a `-X` value that names no HTTP method, unless every url of the
/// run uses a scheme that reads it as a command.
///
/// **This runs after the walk and not inside `applyEffect`**, because
/// nothing at the flag knows which scheme the url uses, and `-X` may come
/// before the url on the command line.
///
/// `-X FROBNICATE http://x` is exit 2 and the same sentence it always
/// gave. `-X FETCH imap://x` reaches the protocol package instead, through
/// `Transfer.Options.custom_request`.
///
/// A run with no url at all keeps the refusal. A user who typed a method
/// zurl does not know made a mistake whichever url follows, and saying so
/// beats waiting for the url.
fn resolveCustomRequest(b: *Builder, fault: ?*Fault) (ParseError || Allocator.Error)!void {
    const value = b.unknown_method orelse return;
    if (b.urls.items.len != 0) {
        var every = true;
        for (b.urls.items) |url| {
            if (!readsCustomRequest(url)) every = false;
        }
        if (every) return;
    }
    return fail(
        b.arena,
        fault,
        error.InvalidMethod,
        "zurl: '{f}' is not a method zurl knows",
        .{safe.text(value)},
    );
}

/// Whether `url` names a scheme that reads `-X` as a command line.
///
/// The scheme is what stands before the first `:`. A string with no `:` at
/// all names no scheme, so it is read as an HTTP url, which is what
/// `zurl_core.url.parse` does with one.
fn readsCustomRequest(url: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, url, ':') orelse return false;
    const named = url[0..colon];
    for (custom_request_schemes) |known| {
        if (std.ascii.eqlIgnoreCase(named, known)) return true;
    }
    return false;
}

/// Settles the method and the two headers a body flag implies, after the
/// whole command line has been read.
///
/// **Every rule here was measured against curl 8.21.0 on a loopback
/// listener.** Flag order does not decide any of them, so this runs once
/// over the finished walk rather than inside `applyEffect`.
///
/// The method:
///
/// ```
/// -d 'a=1'                POST /x        data with no -G is a POST
/// -T file                 PUT /x         an upload is a PUT
/// -I                      HEAD /x
/// -G -d 'a=1'             GET /x?a=1     -G moves the data, and it is a GET
/// -X GET -d 'a=1'         GET /x         -X names the method, body and all
/// -X POST                 POST /x        and a POST may carry no body
/// -I -X POST              POST /x        -X outranks -I
/// -I -G                   HEAD /x        -I outranks -G
/// -X DELETE -d 'a=1'      DELETE /x      any method may carry a body
/// -F 'a=1'                POST /x        a form is a POST
/// -X PUT -F 'a=1'         PUT /x         -X outranks -F too
/// -F 'a=1' -G             POST /x        -G does not move a form
/// ```
///
/// The conflicts. curl refuses two flags that each name a different
/// method, with exit 2 and `You can only select one HTTP request method!`,
/// before it opens a socket:
///
/// ```
/// -I -d 'a=1'      exit 2, POST and HEAD
/// -I --json '{}'   exit 2, POST and HEAD
/// -I -T file       exit 2, PUT and HEAD
/// -T file -d 'a=1' exit 2, PUT and POST
/// -F 'a=1' -I      exit 2, POST and HEAD
/// -F 'a=1' -T file exit 2, PUT and POST
/// -F 'a=1' -d 'b=2' exit 2, two bodies, both POST
/// -F 'a=1' --json '{}' exit 2, the same pair
/// ```
///
/// The last two rows are not two methods. They are two bodies, and curl
/// refuses them under the same message and the same exit code, because a
/// request carries one body. zurl names them `POST` and `POST`, which
/// reads oddly on its own and is what the measurement says.
///
/// `-X` is not in that list, and neither is `-G`: `-X` names the method
/// text and leaves the body alone, and `-G` moves the data out of the body
/// rather than name a method of its own. Measured, `-F 'a=1' -G` sends the
/// form as a `POST` body and puts nothing in the query, so a `-G` beside a
/// form does nothing at all.
///
/// The headers. `-d` and its family ask for
/// `Content-Type: application/x-www-form-urlencoded`, and `--json` asks
/// for `Content-Type: application/json` and `Accept: application/json`. A
/// `-H` of the same name replaces the one zurl would add, and adds no
/// second copy. Measured: `--json '{"k":1}' -H 'Content-Type: text/plain'`
/// sends `Content-Type: text/plain` beside `Accept: application/json`, and
/// no `application/json` content type at all.
///
/// A `-G` sends neither header. Measured: `-d a=1 -G` sends a request with
/// no `Content-Type` and no `Content-Length`, because there is no body to
/// describe. `--json` is the exception: measured, `-G --json '{"a":1}'`
/// still sends both JSON headers, because those two describe what the user
/// asked for and not the framing.
fn resolveRequestBody(
    b: *Builder,
    arena: Allocator,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    const has_data = b.data_items.items.len != 0;
    const has_form = b.form_items.items.len != 0;

    // The conflicts first, so a command line that names two methods is
    // refused before anything reads the one it would have chosen.
    if (b.head and has_data) return conflict(arena, fault, "POST", "HEAD");
    if (b.head and b.upload != null) return conflict(arena, fault, "PUT", "HEAD");
    if (b.upload != null and has_data) return conflict(arena, fault, "PUT", "POST");
    if (b.head and has_form) return conflict(arena, fault, "POST", "HEAD");
    if (b.upload != null and has_form) return conflict(arena, fault, "PUT", "POST");
    // Two bodies, not two methods. curl gives this pair the same refusal
    // and the same exit 2, measured.
    if (has_data and has_form) return conflict(arena, fault, "POST", "POST");

    if (!b.method_given) {
        // `-I` first, because it outranks `-G`, and `-G` before the data,
        // because `-G` moves the data into the query and leaves a `GET`.
        // A form is last, and it never reads `-G`: measured,
        // `-F 'a=1' -G` still sends the form as a `POST` body.
        if (b.head) {
            b.options.method = .HEAD;
        } else if (b.upload != null) {
            b.options.method = .PUT;
        } else if (has_data and !b.get) {
            b.options.method = .POST;
        } else if (has_form) {
            b.options.method = .POST;
        }
    }

    if (!has_data) return;

    // Whether any `--json` is among the data. One is enough: measured,
    // `--json '{"a":1}' -d 'b=2'` sends both JSON headers over the joined
    // body `{"a":1}&b=2`.
    var any_json = false;
    for (b.data_items.items) |item| {
        if (item.kind == .json) any_json = true;
    }

    if (any_json) {
        // **`--json`'s two headers are ordinary headers.** curl documents
        // the flag as a shorthand for `-d` with two `-H` lines, and it
        // behaves like one: measured, `-L --json '{"a":1}'` through a
        // `302` sends a `GET` that still carries both. So they go in the
        // header list, where a redirect keeps them.
        try addImpliedHeader(b, arena, "content-type", "application/json");
        try addImpliedHeader(b, arena, "accept", "application/json");
        return;
    }
    // A `-G` has no body, so there is nothing for a content type to
    // describe.
    if (b.get) return;
    // **The form content type belongs to the body.** curl drops it on the
    // `GET` a `301`, a `302`, or a `303` rewrites the request into, and
    // keeps a `-H Content-Type` there. `RequestBody.content_type` says
    // how the two are told apart. A user header of this name wins, and
    // then nothing is implied at all.
    for (b.headers.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) return;
    }
    b.body_content_type = "application/x-www-form-urlencoded";
}

/// Turns every `-b` value that held an `=` into one `Cookie` header.
///
/// **Measured against curl 8.21.0.** Each row below is one capture from a
/// loopback listener:
///
/// ```
/// -b 'a=1; b=2'            Cookie: a=1; b=2      the text, byte for byte
/// -b 'a=1;b=2'             Cookie: a=1;b=2       no reformatting at all
/// -b 'a=1' -b 'b=2'        Cookie: a=1; b=2      joined with "; "
/// -b 'a=1' -H 'Cookie: z'  Cookie: z             the -H wins outright
/// ```
///
/// So the text is never parsed into cookies and never tidied. curl puts it
/// on the wire as written, and so does zurl.
///
/// **A `-H Cookie:` replaces the whole `-b` text**, which is the last row.
/// curl lets a header the user wrote replace the one it would have built,
/// and this keeps that. With such a header present the `-b` text is
/// dropped, rather than sent as a second `Cookie` line. Two of that header
/// would let a peer read one cookie list as two.
///
/// The header goes among `options.headers`, and `zurl.Client.splitHeaders`
/// lifts it out into `zurl_http.engine.Request.secrets`, because a cookie
/// the user wrote is origin bound: the engine cannot know which host that
/// text belongs to, so it withholds it on every redirect. A cookie from a
/// **jar** takes the other path and carries its own domain. See
/// `zurl_http.engine.CookieJar`.
///
/// Runs after the whole command line is read, the way `resolveRequestBody`
/// does, so a `-H` before or after a `-b` reads the same. curl answers the
/// same way.
fn resolveCookieHeader(b: *Builder, arena: Allocator) Allocator.Error!void {
    if (b.cookie_texts.items.len == 0) return;
    for (b.headers.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Cookie")) return;
    }

    const text = try std.mem.join(arena, "; ", b.cookie_texts.items);
    try b.headers.append(arena, .{ .name = "Cookie", .value = text });
}

/// Turns `-r`'s argument into the `Range` header value, and refuses the
/// pair curl refuses.
///
/// **Measured against curl 8.21.0 on a loopback server that logs the
/// request head.** Each row is one capture:
///
/// ```
/// -r 0-99         Range: bytes=0-99
/// -r 100-         Range: bytes=100-
/// -r -100         Range: bytes=-100    the last 100 bytes
/// -r 0-9,20-29    Range: bytes=0-9,20-29
/// -r 5            Range: bytes=5-      a bare number gains the dash
/// -r 'a-b'        Range: bytes=a-b     sent, with a warning
/// -r ''           exit 2, no socket
/// -r 0-9 -r 5-6   Range: bytes=5-6     the last one wins
/// -r 0-9 -H 'Range: bytes=7-8'   Range: bytes=7-8   the -H wins outright
/// -r 0-99 -C 5    exit 2, no socket
/// ```
///
/// So the text is never rewritten beyond the two rules above: a bare
/// number gains a dash, and everything else goes on the wire as written.
/// curl warns about a character that is not a digit, a dash, or a comma
/// and sends the value anyway, and this keeps both halves.
///
/// A `-H Range:` replaces the whole thing, the same way a `-H Cookie:`
/// replaces a `-b`. `run.zig` reads `Plan.range` only when the header list
/// carries no `Range` of the user's own.
fn resolveRange(
    b: *Builder,
    arena: Allocator,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!?[]const u8 {
    const text = b.range_arg orelse return null;

    // Both flags write the one `Range` header, so the pair asks the peer
    // two things at once. curl refuses it before any socket, and names
    // `-C` in the sentence because that is the flag it checks last.
    if (b.resume_at != null) return fail(
        arena,
        fault,
        error.ConflictingRangeAndResume,
        "zurl: -C/--continue-at and -r/--range cannot both be given",
        .{},
    );

    if (text.len == 0) return fail(
        arena,
        fault,
        error.InvalidNumber,
        "zurl: option '-r': blank argument where content is expected",
        .{},
    );
    if (text.len > range_arg_max) return fail(
        arena,
        fault,
        error.InvalidNumber,
        "zurl: option '-r': the range is longer than {d} bytes",
        .{range_arg_max},
    );

    var plain = true;
    var dashed = false;
    for (text) |byte| {
        if (byte == '-') dashed = true;
        if (!std.ascii.isDigit(byte) and byte != '-' and byte != ',') plain = false;
    }
    if (!plain) try b.notes.append(arena, try std.fmt.allocPrint(
        arena,
        "zurl: -r: '{f}' holds a character that is not a digit. The peer decides what it means.",
        .{safe.text(text)},
    ));

    // A bare number names a start with no end, and curl adds the dash for
    // it. Measured: `-r 5` sends `Range: bytes=5-`.
    return if (dashed)
        try std.fmt.allocPrint(arena, "bytes={s}", .{text})
    else
        try std.fmt.allocPrint(arena, "bytes={s}-", .{text});
}

/// How long a `-r` argument may be.
///
/// A range list is a handful of numbers. This bound is far past any real
/// one, and it stops a command line or a config file handing a header
/// value of unbounded length to the engine, which checks the length again
/// through `zurl_http.h1.head_field_len_max`.
const range_arg_max: usize = 512;

/// Turns `-e`'s url into one `Referer` header.
///
/// **A `-H Referer:` replaces it**, which is the rule every implied header
/// follows here, and it is curl's own: measured, `-e x -H 'Referer: y'`
/// sends `Referer: y` and no second line.
///
/// An empty url adds no header at all. That covers `-e ''`, measured to
/// send no `Referer`, and `-e ';auto'`, measured to send none on the first
/// request and to gain one on each redirect after it.
fn resolveRefererHeader(b: *Builder, arena: Allocator) Allocator.Error!void {
    const url = b.referer orelse return;
    if (url.len == 0) return;
    try addImpliedHeader(b, arena, "Referer", url);
}

/// Refuses `-J` beside `-C`, the way curl does.
///
/// **The two flags disagree about the order of the work.** `-C` opens the
/// output file, reads how much of the body it already holds, and puts that
/// offset in a `Range` header on the request. `-J` learns the name of the
/// output file from the response head, which arrives after that request
/// has gone out. So a run with both would have to ask for a range of one
/// file and then write the answer into another.
///
/// curl 8.21.0 refuses the pair for the same reason: measured, it prints
/// `--continue-at and --remote-header-name cannot be combined` and exits 2
/// before any socket opens.
fn resolveHeaderName(
    b: *Builder,
    arena: Allocator,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    if (!b.remote_header_name) return;
    if (b.resume_at == null) return;
    return fail(
        arena,
        fault,
        error.ConflictingResumeAndHeaderName,
        "zurl: -C/--continue-at and -J/--remote-header-name cannot both be given",
        .{},
    );
}

/// Refuses a url that carries a user name when
/// `--disallow-username-in-url` asked for that.
///
/// **The flag exists because a url is often written by somebody else.** A
/// url in a redirect chain, in a config file, or in a script argument can
/// carry `user:password@` in front of the host, and a run that follows it
/// sends that credential to that host. The flag lets a caller state that
/// no url of this run may carry one, so a url that does is a refusal and
/// never a quiet login as somebody.
///
/// **Every url of the run is checked, and the first one that carries a
/// name stops the run.** A run that refused only the url it reached first
/// would still have sent the credential in url two.
///
/// The check reads the authority of the url text itself and does not need
/// a full parse: a `@` in front of the first `/`, `?`, or `#` after the
/// scheme is what a userinfo is, RFC 3986 section 3.2. A url this build
/// cannot parse at all is left alone here and refused later, where every
/// other bad url is refused.
///
/// A password with no user name, which is `http://:pw@host/`, is a
/// credential too and is refused the same way. curl refuses it as well,
/// measured.
fn resolveUsernameInUrl(
    b: *Builder,
    arena: Allocator,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    if (!b.disallow_username_in_url) return;
    for (b.urls.items) |url| {
        if (!hasUserinfo(url)) continue;
        return fail(
            arena,
            fault,
            error.UsernameInUrl,
            "zurl: url '{f}': a credential is in the url, and --disallow-username-in-url refuses one",
            // `safe.text` masks a userinfo password, so the message names
            // the url and never the secret inside it.
            .{safe.text(url)},
        );
    }
}

/// Whether `url` carries a userinfo before its host.
///
/// Reads the text and never a parsed url, because `parse` runs before any
/// url is parsed and a url that does not parse still has to be judged. The
/// answer is the RFC 3986 one: an authority runs from after `//` to the
/// first `/`, `?`, or `#`, and a `@` inside it separates the userinfo from
/// the host.
///
/// A url with no `//` carries no authority and therefore no userinfo, so
/// `mailto:` and a bare `example.com/path` both read false.
fn hasUserinfo(url: []const u8) bool {
    const marker = std.mem.indexOf(u8, url, "//") orelse return false;
    // A `//` past the first `/` of a path is inside the path and not the
    // start of an authority, as in `http:/a//b`.
    const scheme_end = std.mem.indexOfScalar(u8, url, ':') orelse return false;
    if (marker != scheme_end + 1) return false;

    const authority_start = marker + 2;
    var authority_end = url.len;
    for (url[authority_start..], authority_start..) |c, i| {
        if (c == '/' or c == '?' or c == '#') {
            authority_end = i;
            break;
        }
    }
    return std.mem.indexOfScalar(u8, url[authority_start..authority_end], '@') != null;
}

/// Refuses a command line whose flags name two different methods, the way
/// curl does.
///
/// The fault carries no config-file source. Two flags caused it, and
/// naming one of them would point at the wrong line as often as at the
/// right one.
fn conflict(
    arena: Allocator,
    fault: ?*Fault,
    first: []const u8,
    second: []const u8,
) (ParseError || Allocator.Error) {
    return fail(
        arena,
        fault,
        error.ConflictingMethods,
        "zurl: you can only select one HTTP request method, and this asks for both {s} and {s}",
        .{ first, second },
    );
}

/// Adds `name: value` unless the caller's own `-H` already named that
/// header.
///
/// The name is lower case, which is the case the engine writes every
/// header it owns in. A field name has no case to a server, and a stable
/// case keeps the wire bytes stable.
fn addImpliedHeader(
    b: *Builder,
    arena: Allocator,
    name: []const u8,
    value: []const u8,
) Allocator.Error!void {
    for (b.headers.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return;
    }
    try b.headers.append(arena, .{ .name = name, .value = value });
}

/// Walks `argv` once, applying every flag's effect to `b`.
///
/// `parse` calls this over the final, already-expanded token list.
/// `scanConfigPaths` calls it over the raw, unexpanded command line, before
/// any config file is read, just to learn which files `-K`/`--config`
/// name: sharing this walk means that discovery pass agrees with `parse`'s
/// own, later, real one about which value belongs to which flag, with no
/// second tokeniser to drift out of sync.
fn walk(
    b: *Builder,
    argv: []const []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    var stop_flags = false;

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];

        if (!stop_flags and std.mem.eql(u8, arg, "--")) {
            stop_flags = true;
            continue;
        }
        if (stop_flags or arg.len < 2 or arg[0] != '-') {
            try b.urls.append(b.arena, arg);
            continue;
        }

        // The token this flag starts at. A flag that takes a separate
        // value moves `i` past that value, so the fault must name where
        // the flag began and not where the walk stopped.
        const start = i;
        b.token = start;
        if (arg[1] == '-') {
            parseLong(b, argv, &i, arg, fault) catch |err| {
                // The one place a token-level fault learns which config
                // file and line it came from. Every fault `parseLong`,
                // `parseShortCluster`, and `applyEffect` raise passes
                // through here, so a fault added below cannot skip the
                // attribution.
                try attributeFault(b.arena, fault, b.sourceAt(start));
                return err;
            };
        } else {
            parseShortCluster(b, argv, &i, arg, fault) catch |err| {
                try attributeFault(b.arena, fault, b.sourceAt(start));
                return err;
            };
        }
    }
    b.token = null;
}

/// The mutable state one `parse` call builds up. Kept apart from `Plan` so
/// `Plan` stays a plain result with no parsing-only fields, such as which of
/// `-o`/`-O` came first.
const Builder = struct {
    arena: Allocator,
    urls: std.ArrayList([]const u8) = .empty,
    headers: std.ArrayList(std.http.Header) = .empty,
    options: Transfer.Options = .{},
    output: OutputSpec = .{},
    write_out: ?[]const u8 = null,
    netrc_path: ?[]const u8 = null,
    netrc_mode: NetrcMode = .off,
    silent: bool = false,
    show_error: bool = false,
    progress_bar: bool = false,
    no_progress_meter: bool = false,
    parallel: bool = false,
    max_time: std.Io.Timeout = .none,
    create_dirs: bool = false,
    no_clobber: bool = false,
    verbose: bool = false,
    show_headers: bool = false,
    stderr_path: ?[]const u8 = null,
    output_dir: ?[]const u8 = null,
    create_file_mode: ?u32 = null,
    remove_on_error: bool = false,
    remote_time: bool = false,
    remote_header_name: bool = false,
    etag_compare: ?[]const u8 = null,
    etag_save: ?[]const u8 = null,
    time_cond: ?[]const u8 = null,
    rate_wait_ms: ?u64 = null,
    parallel_max_host: ?usize = null,
    unsupported_flag: ?UnsupportedFlag = null,
    /// The jar files `-b` named, in order.
    cookie_files: std.ArrayList([]const u8) = .empty,
    /// The cookie text each `-b` named, in order. Joined into one `Cookie`
    /// header after the walk. See `resolveCookieHeader`.
    cookie_texts: std.ArrayList([]const u8) = .empty,
    cookie_jar: ?CookieJarTarget = null,
    junk_session_cookies: bool = false,
    /// Whether any of `-b`, `-c`, or `-j` was given.
    cookies_enabled: bool = false,
    /// Whether `--fail-with-body` is the one in force. `--fail` and
    /// `--fail-with-body` each clear the other, so the last one on the
    /// command line wins. Measured: see `Plan.fail_with_body`.
    fail_with_body: bool = false,
    fail_early: bool = false,
    resume_at: ?ResumeAt = null,
    /// `-r`/`--range`'s argument, exactly as the command line wrote it and
    /// with no `bytes=` in front. Null when the flag was not given.
    /// `resolveRange` turns it into the header value after the walk, so a
    /// `-r` before or after a `-C` reads the same.
    range_arg: ?[]const u8 = null,
    /// The `--retry` family, filled flag by flag. See `Retry`.
    retry: Retry = .{},
    /// `--parallel-max`'s argument. Null when the flag was not given.
    parallel_max: ?usize = null,
    /// `-e`/`--referer`'s url part, with any `;auto` suffix taken off.
    /// Null when the flag was not given, and empty for `-e ';auto'`, which
    /// asks for the automatic value alone.
    referer: ?[]const u8 = null,
    /// Every `--resolve` and `--connect-to` entry, in command-line order.
    /// `parse` hands this to `options.connect_to`.
    overrides: std.ArrayList(Transfer.HostOverride) = .empty,
    /// Every `--mail-rcpt`, in the order the command line named them,
    /// which is the order the `RCPT TO` commands go out in.
    recipients: std.ArrayList([]const u8) = .empty,
    /// `-x`/`--proxy`'s argument, or the argument of whichever `--socks`
    /// flag came last. Null when neither was given, and empty for `-x ""`,
    /// which turns proxying off. `resolveProxy` reads it after the walk.
    proxy_arg: ?[]const u8 = null,
    /// Which kind a `--socks4`, `--socks4a`, `--socks5`, or
    /// `--socks5-hostname` flag named. Null for `-x`, whose own scheme
    /// picks the kind.
    proxy_kind: ?zurl_core.proxy.Kind = null,
    /// `--noproxy`'s argument. Null when the flag was not given, which is
    /// what lets the environment answer instead. An empty string is a list
    /// that excludes nothing, which is what curl does: measured,
    /// `--noproxy ""` still sent the request through the proxy.
    noproxy_arg: ?[]const u8 = null,
    /// The proxy authentication scheme a flag named, or null when none
    /// did. Only `basic` is in this build; see `Plan.proxy_auth_refused`.
    proxy_auth_refused: ?[]const u8 = null,
    /// Sentences the parse itself earned: a flag that was accepted and
    /// whose value the user should hear about. `parse` hands these to
    /// `Plan.warnings`, which `src/main.zig` writes to standard error
    /// under the same `-s` and `-S` rule every other note follows.
    notes: std.ArrayList([]const u8) = .empty,
    /// Every `-o` and `-O` destination, in command-line order. `parse`
    /// hands this to `OutputSpec.body`.
    output_targets: std.ArrayList(BodyTarget) = .empty,
    /// Where a url past the end of `output_targets` writes.
    /// `--remote-name-all` and `--out-null` fill this, and the last of the
    /// two wins. See `OutputSpec.tail`.
    output_tail: BodyTarget = .stdout,
    /// Whether `--skip-existing` was given.
    skip_existing: bool = false,
    /// Whether `--disallow-username-in-url` was given. `parse` reads it
    /// after the walk, when every url has been seen. See
    /// `resolveUsernameInUrl`.
    disallow_username_in_url: bool = false,
    /// Whether `--dump-ca-embed` was given. `src/main.zig` acts on it and
    /// runs no transfer.
    dump_ca_embed: bool = false,
    /// Every `--url-query` argument, in command-line order. `parse` hands
    /// this to `RequestBody.query`. Kept apart from `data_items` because
    /// these land in the url and those land in the body, whether or not
    /// `-G` was given.
    query_items: std.ArrayList(DataItem) = .empty,
    /// Every `-d`-family argument, in command-line order. `parse` hands
    /// this to `RequestBody.data`.
    data_items: std.ArrayList(DataItem) = .empty,
    /// Every `-F` and `--form-string` argument, in command-line order.
    /// `parse` hands this to `RequestBody.form`.
    form_items: std.ArrayList(FormItem) = .empty,
    /// Whether `--form-escape` was given.
    form_escape: bool = false,
    /// `-T`/`--upload-file`'s path. curl keeps the last one: measured,
    /// `-T a -T b` on one url uploads `b`.
    upload: ?[]const u8 = null,
    /// Whether `-G`/`--get` was given.
    get: bool = false,
    /// Whether `-I`/`--head` was given.
    head: bool = false,
    /// The content type the `-d` family implies, filled after the walk.
    /// See `RequestBody.content_type`.
    body_content_type: ?[]const u8 = null,
    /// Whether `-X`/`--request` named a method.
    ///
    /// Read after the walk, to decide the method: `-X` outranks every
    /// other flag that would choose one. Measured, `curl -I -X POST` sends
    /// `POST`. It is not the same question as `options.method != .GET`,
    /// because `-X GET` is a method the user named too.
    method_given: bool = false,
    /// The `-X`/`--request` value that named no HTTP method, or null.
    ///
    /// **A mail protocol reads `-X` as a whole command line**, so `FETCH`
    /// and `TOP 1 0` are values a user may write, and neither is an HTTP
    /// method. The refusal therefore cannot happen where the flag is read:
    /// nothing there knows which scheme the url uses. `resolveCustomRequest`
    /// answers it after the walk, when every url has been seen.
    unknown_method: ?[]const u8 = null,
    /// Whether `-L`/`--location` was given. `parse` reads this once, after
    /// every flag has been seen, to fill `options.redirects`: flag order
    /// does not matter to curl, so `--max-redirs 3 -L` and `-L
    /// --max-redirs 3` must read the same.
    location: bool = false,
    /// `--max-redirs`'s argument, if given. `null` when the flag was not
    /// given, so `parse` can tell "not given" apart from "given as the
    /// library's own default", and fill in curl's default limit instead.
    max_redirects_arg: ?u16 = null,
    /// Every `-K`/`--config` path `walk` has seen, in order. `parse`
    /// itself never reads them; `scanConfigPaths` is the only reader of
    /// this field.
    config_paths: std.ArrayList([]const u8) = .empty,
    /// One source for each token of the list `walk` is reading, or empty
    /// when every token came from the command line. Read it through
    /// `sourceAt`, which answers for a short list too.
    sources: []const ?Source = &.{},
    /// Which token `walk` is on, so `applyEffect` can record where a flag
    /// came from without threading the index through every call.
    token: ?usize = null,
    /// The token that last set each flag, so a fault raised after the
    /// walk can still name the file and line that caused it.
    flag_tokens: std.EnumArray(FlagId, ?usize) = .initFill(null),
    /// The version the last `--tlsv1.x` flag **named**, and null when no
    /// such flag was given.
    ///
    /// This is not `options.tls_min_version`. That field is the floor this
    /// build can hold, so `--tlsv1.0` leaves it at TLS 1.2; this field
    /// keeps TLS 1.0, which is what the user wrote. Only the named version
    /// can tell curl's two answers apart: `--tls-max 1.0 --tlsv1.0` runs
    /// and fails at the handshake, and `--tls-max 1.0 --tlsv1.1` exits 2
    /// and never opens a socket. Measured against curl 8.21.0.
    tls_named_min: ?zurl_core.tls.Version = null,
    /// The ceiling the last `--tls-max` named, and null when the flag was
    /// not given. curl keeps the last one: measured,
    /// `--tls-max 1.2 --tls-max 1.3 --tlsv1.3` runs, so the second flag
    /// replaced the first rather than tightening it.
    tls_named_max: ?zurl_core.tls.Version = null,

    /// The source of token `index`, or null when it came from the command
    /// line.
    fn sourceAt(b: *const Builder, index: usize) ?Source {
        if (index >= b.sources.len) return null;
        return b.sources[index];
    }

    /// The source of the token that last set `id`, or null when the
    /// command line set it or nothing did.
    fn sourceOf(b: *const Builder, id: FlagId) ?Source {
        return b.sourceAt(b.flag_tokens.get(id) orelse return null);
    }
};

/// curl's own default redirect limit, used with `-L` and no `--max-redirs`.
/// `man curl` names it under `--max-redirs`: "By default the limit is set
/// to 50 redirects."
const curl_default_max_redirects: u16 = 50;

const FlagId = enum {
    method,
    data_ascii,
    data_raw,
    data_binary,
    data_urlencode,
    json,
    form,
    form_string,
    form_escape,
    upload_file,
    get,
    head,
    header,
    max_redirects,
    location,
    location_trusted,
    fail_on_error,
    fail_with_body,
    fail_early,
    connect_timeout,
    max_time,
    continue_at,
    speed_limit,
    speed_time,
    limit_rate,
    max_filesize,
    user,
    netrc_file,
    netrc,
    netrc_optional,
    user_agent,
    cacert,
    capath,
    ca_native,
    insecure,
    output_file,
    output_url_name,
    headers_file,
    create_dirs,
    no_clobber,
    silent,
    show_error,
    progress_bar,
    no_progress_meter,
    no_buffer,
    write_out,
    parallel,
    config_file,
    disable_default_config,
    compressed,
    protocols,
    redirect_protocols,
    default_protocol,
    tls_v1_0,
    tls_v1_1,
    tls_v1_2,
    tls_v1_3,
    tls_max,
    http_1_1,
    http_2,
    http2_prior_knowledge,
    no_tcp_nodelay,
    no_keepalive,
    cookie,
    cookie_jar,
    junk_session_cookies,
    retry,
    retry_delay,
    retry_max_time,
    retry_connrefused,
    retry_all_errors,
    range,
    referer,
    resolve,
    connect_to,
    parallel_max,
    no_alpn,
    globoff,
    list_only,
    ssl_required,
    mail_from,
    mail_rcpt,
    // How a mail login picks its SASL mechanism. All three reach
    // `zurl-smtp`, `zurl-imap`, and `zurl-pop3` and nothing else.
    sasl_authzid,
    sasl_ir,
    login_options,
    // What an mqtt url does. Both reach `zurl-mqtt` and nothing else.
    mqtt_client_id,
    mqtt_messages,
    // What an rtsp url sends. All four reach `zurl-rtsp` and nothing else.
    // curl's own command line has none of them: they are `CURLOPT_RTSP_*`
    // options a program sets through libcurl. See `zurl.Transfer.Options`.
    rtsp_request,
    rtsp_session_id,
    rtsp_stream_uri,
    rtsp_transport,
    proxy,
    noproxy,
    proxy_user,
    proxy_basic,
    proxy_digest,
    proxy_anyauth,
    proxy_insecure,
    proxy_cacert,
    proxy_capath,
    socks4,
    socks4a,
    socks5,
    socks5_hostname,
    // What a run says about itself. See `Plan.verbose`.
    verbose,
    show_headers,
    stderr_file,
    suppress_connect_headers,
    // The trace family. Every one of the four is refused by name: this
    // build has no tap on the wire to dump. See `Plan.unsupported_flag`.
    trace,
    trace_ascii,
    trace_time,
    trace_ids,
    // Which scheme answers a `401`, and when the password goes out. See
    // `zurl.Transfer.AuthMode`.
    auth_basic,
    auth_digest,
    auth_anyauth,
    // Client certificates. All five are refused by name: the vendored TLS
    // client sends none. See `Plan.unsupported_flag`.
    client_cert,
    client_cert_type,
    client_key,
    client_key_type,
    client_key_pass,
    // Host key trust for `sftp://` and `scp://`. These three are the only
    // way a person
    // says which SSH host key is the right one, so none of them is
    // refused: a flag that carries a trust decision and does nothing is
    // worse than one that is not there.
    known_hosts,
    host_pub_md5,
    host_pub_sha256,
    // The TLS suite and the curve list. Both refused by name: the
    // vendored client carries one fixed list.
    ciphers,
    curves,
    // Where a body lands, and what happens to the file afterwards.
    output_dir,
    create_file_mode,
    remove_on_error,
    remote_time,
    remote_header_name,
    clobber,
    url_arg,
    // The two flags that ask the server whether the body changed at all.
    etag_compare,
    etag_save,
    time_cond,
    // How often a serial run starts a transfer.
    rate,
    // The `-Z` pair. `parallel_immediate` names the state every run here
    // is already in, and `parallel_max_host` bounds what this build never
    // exceeds. See `applyEffect` for the measurement behind each.
    parallel_immediate,
    parallel_max_host,
    // Waits this build does not keep. Each is accepted, each checks its
    // own argument, and each changes nothing. See the help text.
    expect100_timeout,
    happy_eyeballs_timeout_ms,
    keepalive_time,
    keepalive_cnt,

    // ==== Flags with behaviour, added to close the gap against curl ====

    /// `--tcp-nodelay`: the other half of `--no-tcp-nodelay`.
    tcp_nodelay,
    /// `-B`/`--use-ascii`: the FTP transfer type.
    use_ascii,
    /// `--disable-epsv`: send `PASV` and never `EPSV`.
    disable_epsv,
    /// The two TFTP request options.
    tftp_blksize,
    tftp_no_options,
    /// Where a body lands when no `-o` or `-O` covers the url.
    remote_name_all,
    out_null,
    /// `--skip-existing`: leave a file that is already there alone.
    skip_existing,
    /// `--url-query`: percent-encode this and add it to the url query.
    url_query,
    /// `--disallow-username-in-url`: refuse a url that carries userinfo.
    disallow_username_in_url,
    /// `--dump-ca-embed`: write the built-in trust bundle and exit.
    dump_ca_embed,
    /// `--oauth2-bearer`: the token an `Authorization: Bearer` carries.
    oauth2_bearer,
    /// `--proxy-ca-native`: the platform trust store, for the proxy.
    proxy_ca_native,
    /// The four redirect flags that keep a method and a body.
    post301,
    post302,
    post303,
    follow,

    // ==== Flags accepted, documented, and changing nothing ====
    //
    // Each one names a state this build is already in, or names a curl
    // feature curl itself has dropped. Accepted rather than refused
    // because none of them asks for a guarantee the run then breaks: the
    // transfer the flag was trying to shape is the transfer that runs.
    // See `applyEffect`, which carries the reason for each.
    path_as_is,
    ftp_pasv,
    ftp_skip_pasv_ip,
    disable_eprt,
    no_sessionid,
    ssl_allow_beast,
    proxy_ssl_allow_beast,
    ssl_auto_client_cert,
    proxy_ssl_auto_client_cert,
    ssl_no_revoke,
    ssl_revoke_best_effort,
    false_start,
    no_npn,
    egd_file,
    random_file,
    metalink,
    ntlm_wb,
    socks5_basic,
    styled_output,
    tcp_fastopen,
    mptcp,

    // ==== Flags refused by name ====
    //
    // Each asks for something this build cannot do, and each fails
    // quietly if it is accepted and dropped. `applyEffect` names the
    // sentence that says why for every one of them, and `--help` prints
    // that verdict on the flag's own line.

    // Names and addresses this build cannot choose.
    interface_name,
    local_port,
    dns_interface,
    dns_ipv4_addr,
    dns_ipv6_addr,
    dns_servers,
    doh_url,
    doh_insecure,
    doh_cert_status,
    unix_socket,
    abstract_unix_socket,
    ip_tos,
    vlan_priority,
    ipfs_gateway,

    // TLS controls with nothing behind them.
    cert_status,
    crlfile,
    proxy_crlfile,
    pinnedpubkey,
    proxy_pinnedpubkey,
    sigalgs,
    tls13_ciphers,
    proxy_tls13_ciphers,
    proxy_ciphers,
    tls_earlydata,
    ssl_sessions,
    ech,
    engine,
    tls_auth_type,
    tls_user,
    tls_password,
    proxy_tls_auth_type,
    proxy_tls_user,
    proxy_tls_password,
    opportunistic_ssl,
    proxy_client_cert,
    proxy_client_cert_type,
    proxy_client_key,
    proxy_client_key_type,
    proxy_client_key_pass,
    proxy_tls_v1,

    // Authentication schemes this build does not speak.
    auth_negotiate,
    auth_ntlm,
    proxy_negotiate,
    proxy_ntlm,
    service_name,
    proxy_service_name,
    delegation,
    krb,
    socks5_gssapi,
    socks5_gssapi_nec,
    socks5_gssapi_service,
    aws_sigv4,

    // HTTP shapes this engine does not carry.
    http_0_9,
    http3,
    http3_only,
    raw,
    tr_encoding,
    ignore_content_length,
    request_target,
    alt_svc,
    hsts,
    trace_config,

    // Proxy shapes this build does not carry.
    proxy_header,
    proxy_tunnel,
    proxy_1_0,
    preproxy,
    proxy_http2,
    proxy_http3,
    haproxy_protocol,
    haproxy_clientip,

    // FTP commands this build does not send.
    ftp_account,
    ftp_alternative_to_user,
    ftp_create_dirs,
    ftp_method,
    ftp_port,
    ftp_pret,
    ftp_ssl_ccc,
    ftp_ssl_ccc_mode,
    ftp_ssl_control,
    append,
    quote,

    // Mail commands this build does not send.
    mail_auth,
    mail_rcpt_allowfails,
    upload_flags,

    // The rest.
    telnet_option,
    compressed_ssh,
    ssh_pubkey,
    crlf,
    xattr,
    variable,
    libcurl,
    manual,
};

const FlagSpec = struct {
    id: FlagId,
    takes_value: bool,
};

/// One flag this build accepts, with every spelling it answers to and the
/// line `--help` prints for it.
///
/// **This table is the only place a spelling is written down.**
/// `longFlagSpec` and `shortFlagSpec` both read it, so the two spellings of
/// one flag cannot drift apart, and `src/cli/help.zig` renders its options
/// block from it, so the help text and the parser cannot disagree about
/// which spellings exist.
///
/// The three fixes this shape exists to make permanent: `-o`, `-O`, and
/// `-D` were written straight into a `switch` beside a long-form table that
/// never named them, so each was a short form with no long form and a help
/// line that showed only the short. Three more, `-Y`, `-y`, and `-#`, were
/// the mirror fault: a long form in the table with the short form curl has
/// left out. One row for one flag closes both directions at once, and the
/// test `every flag row answers to every spelling it declares` walks the
/// table and proves it.
pub const Flag = struct {
    id: FlagId,
    /// The long spelling, with no leading dashes. Null when curl gives the
    /// flag no long form.
    long: ?[]const u8 = null,
    /// The short spelling, with no leading dash. Null when curl gives the
    /// flag no short form.
    short: ?u8 = null,
    takes_value: bool = false,
    /// What `--help` calls the argument, such as `<path>`. Empty when the
    /// flag takes none.
    arg: []const u8 = "",
    /// The one line `--help` prints after the spellings. One sentence.
    help: []const u8,

    fn spec(f: Flag) FlagSpec {
        return .{ .id = f.id, .takes_value = f.takes_value };
    }
};

/// Every flag `parse` accepts, in the order `--help` lists them.
///
/// `--version` and `--help` are not here. `src/main.zig` reads those two
/// out of argv itself, before any parse, and `parse` never sees them. See
/// `src/cli/help.zig`, which prints their two lines after this block.
pub const flag_table = [_]Flag{
    .{ .id = .output_file, .long = "output", .short = 'o', .takes_value = true, .arg = "<path>", .help = "Write one url's body to this path." },
    .{ .id = .output_url_name, .long = "remote-name", .short = 'O', .help = "Write one url's body to its last path segment." },
    .{ .id = .headers_file, .long = "dump-header", .short = 'D', .takes_value = true, .arg = "<path>", .help = "Write every response head to this path." },
    .{ .id = .create_dirs, .long = "create-dirs", .help = "Create the directory tree an -o path names." },
    .{ .id = .no_clobber, .long = "no-clobber", .help = "Never overwrite a file. Add .1, .2, and so on instead." },
    .{ .id = .continue_at, .long = "continue-at", .short = 'C', .takes_value = true, .arg = "<offset>", .help = "Resume from this offset. - reads it off the file." },
    .{ .id = .range, .long = "range", .short = 'r', .takes_value = true, .arg = "<range>", .help = "Ask for these bytes alone. Refused beside -C." },
    .{ .id = .compressed, .long = "compressed", .help = "Ask for a gzip, deflate, or zstd body, and decode it. No br." },
    .{ .id = .write_out, .long = "write-out", .short = 'w', .takes_value = true, .arg = "<format>", .help = "Print this format after each transfer." },
    .{ .id = .method, .long = "request", .short = 'X', .takes_value = true, .arg = "<method>", .help = "The HTTP method." },
    .{ .id = .data_ascii, .long = "data", .short = 'd', .takes_value = true, .arg = "<data>", .help = "Send this as the body. @file reads a file." },
    .{ .id = .data_ascii, .long = "data-ascii", .takes_value = true, .arg = "<data>", .help = "The same as -d." },
    .{ .id = .data_raw, .long = "data-raw", .takes_value = true, .arg = "<data>", .help = "The same as -d, and @ names no file." },
    .{ .id = .data_binary, .long = "data-binary", .takes_value = true, .arg = "<data>", .help = "The same as -d, and @file keeps every byte." },
    .{ .id = .data_urlencode, .long = "data-urlencode", .takes_value = true, .arg = "<data>", .help = "Percent-encode this, then send it as the body." },
    .{ .id = .json, .long = "json", .takes_value = true, .arg = "<data>", .help = "Send this as a JSON body, with the two JSON headers." },
    .{ .id = .form, .long = "form", .short = 'F', .takes_value = true, .arg = "<part>", .help = "Send a multipart form part. @file uploads a file." },
    .{ .id = .form_string, .long = "form-string", .takes_value = true, .arg = "<part>", .help = "The same as -F, and the value is taken literally." },
    .{ .id = .form_escape, .long = "form-escape", .help = "Escape a form name with a backslash, not a percent." },
    .{ .id = .upload_file, .long = "upload-file", .short = 'T', .takes_value = true, .arg = "<path>", .help = "PUT this file. - reads standard input." },
    .{ .id = .get, .long = "get", .short = 'G', .help = "Put the -d data in the query instead of the body." },
    .{ .id = .head, .long = "head", .short = 'I', .help = "Ask for the response head alone." },
    .{ .id = .header, .long = "header", .short = 'H', .takes_value = true, .arg = "<line>", .help = "Add one request header. Repeatable." },
    .{ .id = .location, .long = "location", .short = 'L', .help = "Follow a redirect." },
    .{ .id = .location_trusted, .long = "location-trusted", .help = "Follow a redirect, and send the credential to every hop." },
    .{ .id = .max_redirects, .long = "max-redirs", .takes_value = true, .arg = "<n>", .help = "How many redirects -L may follow." },
    .{ .id = .fail_on_error, .long = "fail", .short = 'f', .help = "Treat a 4xx or 5xx status as a failure." },
    .{ .id = .fail_with_body, .long = "fail-with-body", .help = "The same as -f, and write the error body too." },
    .{ .id = .fail_early, .long = "fail-early", .help = "Stop at the first url that fails." },
    .{ .id = .user, .long = "user", .short = 'u', .takes_value = true, .arg = "<user:pass>", .help = "The credentials to send." },
    .{ .id = .netrc_file, .long = "netrc-file", .takes_value = true, .arg = "<path>", .help = "Read the credentials from this netrc file." },
    .{ .id = .netrc, .long = "netrc", .short = 'n', .help = "Read the credentials from the default netrc file." },
    .{ .id = .netrc_optional, .long = "netrc-optional", .help = "The same as -n, and a missing file is no fault." },
    .{ .id = .user_agent, .long = "user-agent", .short = 'A', .takes_value = true, .arg = "<text>", .help = "The User-Agent value." },
    .{ .id = .referer, .long = "referer", .short = 'e', .takes_value = true, .arg = "<url>", .help = "The Referer value. A ;auto suffix updates it on each redirect." },
    .{ .id = .cookie, .long = "cookie", .short = 'b', .takes_value = true, .arg = "<data|file>", .help = "Send these cookies. A value with no = names a jar file. Repeatable." },
    .{ .id = .cookie_jar, .long = "cookie-jar", .short = 'c', .takes_value = true, .arg = "<path>", .help = "Write the cookie jar to this path after the run. - is standard output." },
    .{ .id = .junk_session_cookies, .long = "junk-session-cookies", .short = 'j', .help = "Drop the session cookies a jar file holds." },
    .{ .id = .protocols, .long = "proto", .takes_value = true, .arg = "<list>", .help = "Which protocols a url may name." },
    .{ .id = .redirect_protocols, .long = "proto-redir", .takes_value = true, .arg = "<list>", .help = "Which protocols a redirect may name." },
    .{ .id = .default_protocol, .long = "proto-default", .takes_value = true, .arg = "<proto>", .help = "The scheme for a url that carries none." },
    .{ .id = .tls_v1_0, .long = "tlsv1.0", .help = "Speak TLSv1.0 or greater. See the floor below." },
    .{ .id = .tls_v1_1, .long = "tlsv1.1", .help = "Speak TLSv1.1 or greater. See the floor below." },
    .{ .id = .tls_v1_2, .long = "tlsv1.2", .help = "Speak TLSv1.2 or greater." },
    .{ .id = .tls_v1_3, .long = "tlsv1.3", .help = "Speak TLSv1.3 or greater." },
    .{ .id = .tls_v1_0, .long = "tlsv1", .short = '1', .help = "The same as --tlsv1.0." },
    .{ .id = .tls_max, .long = "tls-max", .takes_value = true, .arg = "<version>", .help = "The highest TLS version to keep." },
    .{ .id = .connect_timeout, .long = "connect-timeout", .takes_value = true, .arg = "<s>", .help = "How long the connect may take." },
    .{ .id = .resolve, .long = "resolve", .takes_value = true, .arg = "<h:p:addr>", .help = "Dial this address for that host and port. Repeatable." },
    .{ .id = .connect_to, .long = "connect-to", .takes_value = true, .arg = "<h:p:h:p>", .help = "Dial the second host and port for the first. Repeatable." },
    .{ .id = .retry, .long = "retry", .takes_value = true, .arg = "<n>", .help = "Try a failed transfer this many times more." },
    .{ .id = .retry_delay, .long = "retry-delay", .takes_value = true, .arg = "<s>", .help = "Wait this long between tries, instead of doubling." },
    .{ .id = .retry_max_time, .long = "retry-max-time", .takes_value = true, .arg = "<s>", .help = "Start no try after this many seconds. 0 is no bound." },
    .{ .id = .retry_connrefused, .long = "retry-connrefused", .help = "Also try again when the peer refused the connection." },
    .{ .id = .retry_all_errors, .long = "retry-all-errors", .help = "Try again after any failure. Read the note below first." },
    .{ .id = .max_time, .long = "max-time", .short = 'm', .takes_value = true, .arg = "<s>", .help = "How long the whole transfer may take." },
    .{ .id = .speed_limit, .long = "speed-limit", .short = 'Y', .takes_value = true, .arg = "<n>", .help = "The slowest rate to accept, in bytes each second." },
    .{ .id = .speed_time, .long = "speed-time", .short = 'y', .takes_value = true, .arg = "<s>", .help = "How long the rate may stay below --speed-limit." },
    .{ .id = .limit_rate, .long = "limit-rate", .takes_value = true, .arg = "<n>", .help = "Cap the rate. Takes a k, M, or G suffix." },
    .{ .id = .max_filesize, .long = "max-filesize", .takes_value = true, .arg = "<n>", .help = "Cap the response size. Takes the same suffixes." },
    .{ .id = .proxy, .long = "proxy", .short = 'x', .takes_value = true, .arg = "<url>", .help = "Send every request through this proxy. The scheme picks the kind." },
    .{ .id = .noproxy, .long = "noproxy", .takes_value = true, .arg = "<list>", .help = "Hosts that reach no proxy. * is every host." },
    .{ .id = .proxy_user, .long = "proxy-user", .short = 'U', .takes_value = true, .arg = "<user:pass>", .help = "The credentials to send to the proxy, and never to the origin." },
    .{ .id = .proxy_basic, .long = "proxy-basic", .help = "Answer the proxy with Basic. This is already the default." },
    .{ .id = .proxy_digest, .long = "proxy-digest", .help = "Answer the proxy with Digest. Not in this build. See the note below." },
    .{ .id = .proxy_anyauth, .long = "proxy-anyauth", .help = "Let the proxy pick the scheme. Not in this build. See the note below." },
    .{ .id = .socks4, .long = "socks4", .takes_value = true, .arg = "<host:port>", .help = "A SOCKS4 proxy. This machine resolves the host." },
    .{ .id = .socks4a, .long = "socks4a", .takes_value = true, .arg = "<host:port>", .help = "A SOCKS4a proxy. The proxy resolves the host." },
    .{ .id = .socks5, .long = "socks5", .takes_value = true, .arg = "<host:port>", .help = "A SOCKS5 proxy. This machine resolves the host." },
    .{ .id = .socks5_hostname, .long = "socks5-hostname", .takes_value = true, .arg = "<host:port>", .help = "A SOCKS5 proxy. The proxy resolves the host." },
    .{ .id = .proxy_insecure, .long = "proxy-insecure", .help = "Do not verify the proxy certificate. The origin is still verified." },
    .{ .id = .proxy_cacert, .long = "proxy-cacert", .takes_value = true, .arg = "<path>", .help = "A file of certificate authorities for an https proxy." },
    .{ .id = .proxy_capath, .long = "proxy-capath", .takes_value = true, .arg = "<dir>", .help = "A directory of certificate authorities for an https proxy." },
    .{ .id = .cacert, .long = "cacert", .takes_value = true, .arg = "<path>", .help = "A file of certificate authorities." },
    .{ .id = .capath, .long = "capath", .takes_value = true, .arg = "<dir>", .help = "A directory of certificate authorities." },
    .{ .id = .ca_native, .long = "ca-native", .help = "Also use the trust store of the platform." },
    .{ .id = .insecure, .long = "insecure", .short = 'k', .help = "Do not verify the peer certificate. See the note below." },
    .{ .id = .http_1_1, .long = "http1.1", .help = "Offer http/1.1 alone, so no hop speaks HTTP/2." },
    .{ .id = .http_2, .long = "http2", .help = "Ask for HTTP/2. Over TLS this is the default; over cleartext it asks to upgrade." },
    .{ .id = .http2_prior_knowledge, .long = "http2-prior-knowledge", .help = "Speak HTTP/2 and take no other answer, cleartext or TLS." },
    .{ .id = .http3, .long = "http3", .help = "Ask for HTTP/3 over QUIC, and fall back to the TCP hop when QUIC does not answer." },
    .{ .id = .http3_only, .long = "http3-only", .help = "Speak HTTP/3 and take no other answer. No fallback." },
    .{ .id = .no_tcp_nodelay, .long = "no-tcp-nodelay", .help = "Leave Nagle's algorithm on. zurl turns it off by default." },
    .{ .id = .no_keepalive, .long = "no-keepalive", .help = "Send no TCP keepalive probes. zurl sends none anyway." },
    .{ .id = .no_alpn, .long = "no-alpn", .help = "Send no ALPN extension, so no hop speaks HTTP/2." },
    .{ .id = .globoff, .long = "globoff", .short = 'g', .help = "Read no { } or [ ] in a url. zurl never reads them." },
    .{ .id = .list_only, .long = "list-only", .short = 'l', .help = "List names alone. An ftp directory sends NLST. HTTP ignores this." },
    .{ .id = .ssl_required, .long = "ssl-reqd", .help = "Put TLS on a mail or ftp connection before the login, and fail without it." },
    .{ .id = .mail_from, .long = "mail-from", .takes_value = true, .arg = "<address>", .help = "The envelope sender of an smtp message." },
    .{ .id = .mail_rcpt, .long = "mail-rcpt", .takes_value = true, .arg = "<address>", .help = "One envelope recipient of an smtp message. Repeatable." },
    .{ .id = .sasl_authzid, .long = "sasl-authzid", .takes_value = true, .arg = "<identity>", .help = "The SASL identity to act as. Only AUTH PLAIN carries one." },
    .{ .id = .sasl_ir, .long = "sasl-ir", .help = "Put the first SASL message on the command that opens the exchange." },
    .{ .id = .login_options, .long = "login-options", .takes_value = true, .arg = "AUTH=<mechanism>", .help = "Use this one SASL mechanism for a mail login, or fail." },
    .{ .id = .mqtt_client_id, .long = "mqtt-client-id", .takes_value = true, .arg = "<id>", .help = "The client id an mqtt connect names. One is drawn without this." },
    .{ .id = .mqtt_messages, .long = "mqtt-messages", .takes_value = true, .arg = "<n>", .help = "How many messages an mqtt subscribe reads. The default is 1. curl reads until you stop it." },
    .{ .id = .rtsp_request, .long = "rtsp-request", .takes_value = true, .arg = "<method>", .help = "The rtsp method. The same as -X on an rtsp url. The default is OPTIONS." },
    .{ .id = .rtsp_session_id, .long = "rtsp-session-id", .takes_value = true, .arg = "<id>", .help = "The Session header an rtsp request carries." },
    .{ .id = .rtsp_stream_uri, .long = "rtsp-stream-uri", .takes_value = true, .arg = "<uri>", .help = "The uri an rtsp request line names. The url is used without this." },
    .{ .id = .rtsp_transport, .long = "rtsp-transport", .takes_value = true, .arg = "<spec>", .help = "The Transport header an rtsp request carries. An rtsp SETUP needs one." },
    .{ .id = .parallel, .long = "parallel", .short = 'Z', .help = "Run the transfers at the same time." },
    .{ .id = .parallel_max, .long = "parallel-max", .takes_value = true, .arg = "<n>", .help = "How many transfers -Z may run at once. The default is 8." },
    .{ .id = .progress_bar, .long = "progress-bar", .short = '#', .help = "Draw a bar instead of the meter of columns." },
    .{ .id = .no_progress_meter, .long = "no-progress-meter", .help = "Draw no meter, and keep every message." },
    .{ .id = .no_buffer, .long = "no-buffer", .short = 'N', .help = "Do not hold the body back. zurl holds none back." },
    .{ .id = .silent, .long = "silent", .short = 's', .help = "Draw no meter, and print no message for a failed transfer." },
    .{ .id = .show_error, .long = "show-error", .short = 'S', .help = "Print the message even with -s." },
    .{ .id = .config_file, .long = "config", .short = 'K', .takes_value = true, .arg = "<path>", .help = "Read options from this file. Repeatable." },
    .{ .id = .disable_default_config, .long = "disable", .short = 'q', .help = "Do not read the default curlrc." },
    .{ .id = .url_arg, .long = "url", .takes_value = true, .arg = "<url>", .help = "One more url. The same as a bare url, and it keeps its place." },
    .{ .id = .verbose, .long = "verbose", .short = 'v', .help = "Say what the transfer did, on standard error. Prints no credential." },
    .{ .id = .show_headers, .long = "show-headers", .short = 'i', .help = "Write the response head before the body." },
    .{ .id = .show_headers, .long = "include", .help = "The same as -i." },
    .{ .id = .stderr_file, .long = "stderr", .takes_value = true, .arg = "<path>", .help = "Write every message to this file. - is standard output." },
    .{ .id = .suppress_connect_headers, .long = "suppress-connect-headers", .help = "Leave the CONNECT head out of -v. -v never prints one." },
    .{ .id = .output_dir, .long = "output-dir", .takes_value = true, .arg = "<dir>", .help = "Put every -o and -O file under this directory." },
    .{ .id = .create_file_mode, .long = "create-file-mode", .takes_value = true, .arg = "<mode>", .help = "The octal mode a created file gets. The default is 0644." },
    .{ .id = .remove_on_error, .long = "remove-on-error", .help = "Delete the output file when the transfer fails." },
    .{ .id = .remote_time, .long = "remote-time", .short = 'R', .help = "Give the file the Last-Modified time the server sent." },
    .{ .id = .remote_header_name, .long = "remote-header-name", .short = 'J', .help = "Take the -O name from Content-Disposition. Read the note below." },
    .{ .id = .clobber, .long = "clobber", .help = "Overwrite a file that is already there. This is the default." },
    .{ .id = .etag_compare, .long = "etag-compare", .takes_value = true, .arg = "<path>", .help = "Send this file's text as If-None-Match." },
    .{ .id = .etag_save, .long = "etag-save", .takes_value = true, .arg = "<path>", .help = "Write the response ETag to this file." },
    .{ .id = .time_cond, .long = "time-cond", .short = 'z', .takes_value = true, .arg = "<time>", .help = "Ask only if the body changed. A leading - turns it around." },
    .{ .id = .rate, .long = "rate", .takes_value = true, .arg = "<n/unit>", .help = "Start this many transfers each unit of time. Serial runs alone." },
    .{ .id = .parallel_immediate, .long = "parallel-immediate", .help = "Start each -Z transfer at once. zurl already does." },
    .{ .id = .parallel_max_host, .long = "parallel-max-host", .takes_value = true, .arg = "<n>", .help = "How many -Z transfers may reach one host. See the note below." },
    .{ .id = .auth_basic, .long = "basic", .help = "Answer with Basic. This is already the default." },
    .{ .id = .auth_digest, .long = "digest", .help = "Send no password until the server asks for Digest." },
    .{ .id = .auth_anyauth, .long = "anyauth", .help = "Send no password until the server names a scheme." },
    .{ .id = .expect100_timeout, .long = "expect100-timeout", .takes_value = true, .arg = "<s>", .help = "Accepted, and it changes nothing. See the note below." },
    .{ .id = .happy_eyeballs_timeout_ms, .long = "happy-eyeballs-timeout-ms", .takes_value = true, .arg = "<ms>", .help = "Accepted, and it changes nothing. See the note below." },
    .{ .id = .keepalive_time, .long = "keepalive-time", .takes_value = true, .arg = "<s>", .help = "Accepted, and it changes nothing. See the note below." },
    .{ .id = .keepalive_cnt, .long = "keepalive-cnt", .takes_value = true, .arg = "<n>", .help = "Accepted, and it changes nothing. See the note below." },
    .{ .id = .client_cert, .long = "cert", .short = 'E', .takes_value = true, .arg = "<path>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .client_cert_type, .long = "cert-type", .takes_value = true, .arg = "<type>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .client_key, .long = "key", .takes_value = true, .arg = "<path>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .client_key_type, .long = "key-type", .takes_value = true, .arg = "<type>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .client_key_pass, .long = "pass", .takes_value = true, .arg = "<phrase>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .known_hosts, .long = "knownhosts", .takes_value = true, .arg = "<path>", .help = "The known_hosts file for ssh. Default ~/.ssh/known_hosts." },
    .{ .id = .host_pub_sha256, .long = "hostpubsha256", .takes_value = true, .arg = "<base64>", .help = "Pin the ssh host key by its SHA-256, as ssh-keygen -l prints it." },
    .{ .id = .host_pub_md5, .long = "hostpubmd5", .takes_value = true, .arg = "<hex>", .help = "Pin the ssh host key by its MD5. Prefer --hostpubsha256." },
    .{ .id = .ciphers, .long = "ciphers", .takes_value = true, .arg = "<list>", .help = "Refused. This build carries one fixed suite list." },
    .{ .id = .curves, .long = "curves", .takes_value = true, .arg = "<list>", .help = "Refused. This build carries one fixed curve list." },
    .{ .id = .trace, .long = "trace", .takes_value = true, .arg = "<path>", .help = "Refused. This build has no tap on the wire. Use -v." },
    .{ .id = .trace_ascii, .long = "trace-ascii", .takes_value = true, .arg = "<path>", .help = "Refused. This build has no tap on the wire. Use -v." },
    .{ .id = .trace_time, .long = "trace-time", .help = "Refused. It marks a trace, and there is no trace." },
    .{ .id = .trace_ids, .long = "trace-ids", .help = "Refused. It marks a trace, and there is no trace." },
    .{ .id = .trace_config, .long = "trace-config", .takes_value = true, .arg = "<what>", .help = "Refused. It shapes a trace, and there is no trace." },

    // Flags with behaviour.
    .{ .id = .tcp_nodelay, .long = "tcp-nodelay", .help = "Turn Nagle off. This is already the default." },
    .{ .id = .use_ascii, .long = "use-ascii", .short = 'B', .help = "Ask ftp for TYPE A, and turn each CRLF into one LF." },
    .{ .id = .disable_epsv, .long = "disable-epsv", .help = "Send ftp PASV and never EPSV." },
    .{ .id = .tftp_blksize, .long = "tftp-blksize", .takes_value = true, .arg = "<n>", .help = "The tftp blksize to ask for. 8 to 8192. The default is 512." },
    .{ .id = .tftp_no_options, .long = "tftp-no-options", .help = "Send the tftp request with no option block." },
    .{ .id = .remote_name_all, .long = "remote-name-all", .help = "Give every url an -O, so no body reaches standard output." },
    .{ .id = .out_null, .long = "out-null", .help = "Throw every body away. It reaches no file and no screen." },
    .{ .id = .skip_existing, .long = "skip-existing", .help = "Skip a url whose output file is already there." },
    .{ .id = .url_query, .long = "url-query", .takes_value = true, .arg = "<data>", .help = "Percent-encode this and add it to the url query." },
    .{ .id = .disallow_username_in_url, .long = "disallow-username-in-url", .help = "Refuse a url that carries a user name." },
    .{ .id = .dump_ca_embed, .long = "dump-ca-embed", .help = "Write the built-in trust bundle to standard output and stop." },
    .{ .id = .oauth2_bearer, .long = "oauth2-bearer", .takes_value = true, .arg = "<token>", .help = "Send this token as Authorization: Bearer. It answers no challenge." },
    .{ .id = .proxy_ca_native, .long = "proxy-ca-native", .help = "Also use the trust store of the platform for the proxy." },
    .{ .id = .post301, .long = "post301", .help = "Keep the method and the body across a 301." },
    .{ .id = .post302, .long = "post302", .help = "Keep the method and the body across a 302." },
    .{ .id = .post303, .long = "post303", .help = "Keep the method and the body across a 303." },
    .{ .id = .follow, .long = "follow", .help = "Follow a redirect. The same as -L here. Read the note below." },

    // Flags accepted, and each one changes nothing. See the notes below.
    .{ .id = .path_as_is, .long = "path-as-is", .help = "Keep a .. in the url path. zurl already does. Read the note below." },
    .{ .id = .ftp_pasv, .long = "ftp-pasv", .help = "Ask ftp for a passive transfer. zurl has no other mode." },
    .{ .id = .ftp_skip_pasv_ip, .long = "ftp-skip-pasv-ip", .help = "Never dial the address a PASV answer names. zurl never does." },
    .{ .id = .disable_eprt, .long = "disable-eprt", .help = "Send no EPRT or LPRT. zurl sends neither." },
    .{ .id = .no_sessionid, .long = "no-sessionid", .help = "Reuse no TLS session. zurl caches none." },
    .{ .id = .ssl_allow_beast, .long = "ssl-allow-beast", .help = "Accepted. The floor here is TLS 1.2, which has no BEAST flaw." },
    .{ .id = .proxy_ssl_allow_beast, .long = "proxy-ssl-allow-beast", .help = "Accepted. The floor here is TLS 1.2, which has no BEAST flaw." },
    .{ .id = .ssl_auto_client_cert, .long = "ssl-auto-client-cert", .help = "Accepted. It is a Schannel option, and no certificate goes out." },
    .{ .id = .proxy_ssl_auto_client_cert, .long = "proxy-ssl-auto-client-cert", .help = "Accepted. It is a Schannel option, and no certificate goes out." },
    .{ .id = .ssl_no_revoke, .long = "ssl-no-revoke", .help = "Accepted. It is a Schannel option, and no revocation is checked." },
    .{ .id = .ssl_revoke_best_effort, .long = "ssl-revoke-best-effort", .help = "Accepted. It is a Schannel option, and no revocation is checked." },
    .{ .id = .false_start, .long = "false-start", .help = "Accepted. curl dropped this too. It changes nothing." },
    .{ .id = .no_npn, .long = "no-npn", .help = "Accepted. NPN is gone. zurl offers ALPN. See --no-alpn." },
    .{ .id = .egd_file, .long = "egd-file", .takes_value = true, .arg = "<path>", .help = "Accepted. curl dropped this too. It changes nothing." },
    .{ .id = .random_file, .long = "random-file", .takes_value = true, .arg = "<path>", .help = "Accepted. curl dropped this too. It changes nothing." },
    .{ .id = .metalink, .long = "metalink", .help = "Accepted. curl dropped this too. It changes nothing." },
    .{ .id = .ntlm_wb, .long = "ntlm-wb", .help = "Accepted. curl dropped this too. It changes nothing." },
    .{ .id = .socks5_basic, .long = "socks5-basic", .help = "Answer a SOCKS5 proxy with a user name. zurl offers no other." },
    .{ .id = .styled_output, .long = "styled-output", .help = "Accepted. zurl writes a response head with no styling either way." },
    .{ .id = .tcp_fastopen, .long = "tcp-fastopen", .help = "Accepted. zurl opens an ordinary TCP connection." },
    .{ .id = .mptcp, .long = "mptcp", .help = "Accepted. zurl opens an ordinary TCP connection." },

    // Flags refused by name. Names and addresses this build cannot choose.
    .{ .id = .interface_name, .long = "interface", .takes_value = true, .arg = "<name>", .help = "Refused. This build binds no local address before it dials." },
    .{ .id = .local_port, .long = "local-port", .takes_value = true, .arg = "<range>", .help = "Refused. This build binds no local port before it dials." },
    .{ .id = .dns_interface, .long = "dns-interface", .takes_value = true, .arg = "<name>", .help = "Refused. The resolver of the platform answers, and takes no such input." },
    .{ .id = .dns_ipv4_addr, .long = "dns-ipv4-addr", .takes_value = true, .arg = "<addr>", .help = "Refused. The resolver of the platform answers, and takes no such input." },
    .{ .id = .dns_ipv6_addr, .long = "dns-ipv6-addr", .takes_value = true, .arg = "<addr>", .help = "Refused. The resolver of the platform answers, and takes no such input." },
    .{ .id = .dns_servers, .long = "dns-servers", .takes_value = true, .arg = "<addrs>", .help = "Refused. The resolver of the platform answers, and takes no such input." },
    .{ .id = .doh_url, .long = "doh-url", .takes_value = true, .arg = "<url>", .help = "Refused. This build resolves a name no other way." },
    .{ .id = .doh_insecure, .long = "doh-insecure", .help = "Refused. This build sends no DoH query. See --doh-url." },
    .{ .id = .doh_cert_status, .long = "doh-cert-status", .help = "Refused. This build sends no DoH query. See --doh-url." },
    .{ .id = .unix_socket, .long = "unix-socket", .takes_value = true, .arg = "<path>", .help = "Refused. This build dials TCP alone." },
    .{ .id = .abstract_unix_socket, .long = "abstract-unix-socket", .takes_value = true, .arg = "<path>", .help = "Refused. This build dials TCP alone." },
    .{ .id = .ip_tos, .long = "ip-tos", .takes_value = true, .arg = "<tos>", .help = "Refused. This build writes no Type of Service on a packet." },
    .{ .id = .vlan_priority, .long = "vlan-priority", .takes_value = true, .arg = "<n>", .help = "Refused. This build writes no VLAN priority on a packet." },
    .{ .id = .ipfs_gateway, .long = "ipfs-gateway", .takes_value = true, .arg = "<url>", .help = "Refused. This build reads no ipfs:// or ipns:// url." },

    // Flags refused by name. TLS controls with nothing behind them.
    .{ .id = .cert_status, .long = "cert-status", .help = "Refused. This build asks for no OCSP staple and checks none." },
    .{ .id = .crlfile, .long = "crlfile", .takes_value = true, .arg = "<path>", .help = "Refused. This build checks no revocation list." },
    .{ .id = .proxy_crlfile, .long = "proxy-crlfile", .takes_value = true, .arg = "<path>", .help = "Refused. This build checks no revocation list." },
    .{ .id = .pinnedpubkey, .long = "pinnedpubkey", .takes_value = true, .arg = "<hashes>", .help = "Refused. This build reads back no peer public key to pin." },
    .{ .id = .proxy_pinnedpubkey, .long = "proxy-pinnedpubkey", .takes_value = true, .arg = "<hashes>", .help = "Refused. This build reads back no peer public key to pin." },
    .{ .id = .sigalgs, .long = "sigalgs", .takes_value = true, .arg = "<list>", .help = "Refused. This build offers one fixed signature algorithm list." },
    .{ .id = .tls13_ciphers, .long = "tls13-ciphers", .takes_value = true, .arg = "<list>", .help = "Refused. This build carries one fixed suite list." },
    .{ .id = .proxy_tls13_ciphers, .long = "proxy-tls13-ciphers", .takes_value = true, .arg = "<list>", .help = "Refused. This build carries one fixed suite list." },
    .{ .id = .proxy_ciphers, .long = "proxy-ciphers", .takes_value = true, .arg = "<list>", .help = "Refused. This build carries one fixed suite list." },
    .{ .id = .tls_earlydata, .long = "tls-earlydata", .help = "Refused. This build resumes no session, so it sends no early data." },
    .{ .id = .ssl_sessions, .long = "ssl-sessions", .takes_value = true, .arg = "<path>", .help = "Refused. This build keeps no session cache to load or save." },
    .{ .id = .ech, .long = "ech", .takes_value = true, .arg = "<config>", .help = "Refused. This build sends no Encrypted Client Hello." },
    .{ .id = .engine, .long = "engine", .takes_value = true, .arg = "<name>", .help = "Refused. The TLS here is in this binary. There is no engine to pick." },
    .{ .id = .tls_auth_type, .long = "tlsauthtype", .takes_value = true, .arg = "<type>", .help = "Refused. This build speaks no TLS-SRP." },
    .{ .id = .tls_user, .long = "tlsuser", .takes_value = true, .arg = "<name>", .help = "Refused. This build speaks no TLS-SRP." },
    .{ .id = .tls_password, .long = "tlspassword", .takes_value = true, .arg = "<phrase>", .help = "Refused. This build speaks no TLS-SRP." },
    .{ .id = .proxy_tls_auth_type, .long = "proxy-tlsauthtype", .takes_value = true, .arg = "<type>", .help = "Refused. This build speaks no TLS-SRP." },
    .{ .id = .proxy_tls_user, .long = "proxy-tlsuser", .takes_value = true, .arg = "<name>", .help = "Refused. This build speaks no TLS-SRP." },
    .{ .id = .proxy_tls_password, .long = "proxy-tlspassword", .takes_value = true, .arg = "<phrase>", .help = "Refused. This build speaks no TLS-SRP." },
    .{ .id = .opportunistic_ssl, .long = "ssl", .help = "Refused. It carries on in the clear after a refusal. Use --ssl-reqd." },
    .{ .id = .proxy_client_cert, .long = "proxy-cert", .takes_value = true, .arg = "<path>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .proxy_client_cert_type, .long = "proxy-cert-type", .takes_value = true, .arg = "<type>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .proxy_client_key, .long = "proxy-key", .takes_value = true, .arg = "<path>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .proxy_client_key_type, .long = "proxy-key-type", .takes_value = true, .arg = "<type>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .proxy_client_key_pass, .long = "proxy-pass", .takes_value = true, .arg = "<phrase>", .help = "Refused. This build sends no client certificate." },
    .{ .id = .proxy_tls_v1, .long = "proxy-tlsv1", .help = "Refused. The floor here is TLS 1.2, for the proxy as for the origin." },

    // Flags refused by name. Authentication schemes this build does not speak.
    .{ .id = .auth_negotiate, .long = "negotiate", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .auth_ntlm, .long = "ntlm", .help = "Refused. This build speaks no NTLM." },
    .{ .id = .proxy_negotiate, .long = "proxy-negotiate", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .proxy_ntlm, .long = "proxy-ntlm", .help = "Refused. This build speaks no NTLM." },
    .{ .id = .service_name, .long = "service-name", .takes_value = true, .arg = "<name>", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .proxy_service_name, .long = "proxy-service-name", .takes_value = true, .arg = "<name>", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .delegation, .long = "delegation", .takes_value = true, .arg = "<level>", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .krb, .long = "krb", .takes_value = true, .arg = "<level>", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .socks5_gssapi, .long = "socks5-gssapi", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .socks5_gssapi_nec, .long = "socks5-gssapi-nec", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .socks5_gssapi_service, .long = "socks5-gssapi-service", .takes_value = true, .arg = "<name>", .help = "Refused. This build speaks no SPNEGO and no Kerberos." },
    .{ .id = .aws_sigv4, .long = "aws-sigv4", .takes_value = true, .arg = "<provider>", .help = "Refused. This build signs no request with an AWS V4 signature." },

    // Flags refused by name. HTTP shapes this engine does not carry.
    .{ .id = .http_0_9, .long = "http0.9", .help = "Refused. A reply with no status line is a fault here." },
    .{ .id = .raw, .long = "raw", .help = "Refused. This build always decodes a body it asked to have coded." },
    .{ .id = .tr_encoding, .long = "tr-encoding", .help = "Refused. This build decodes no transfer coding but chunked." },
    .{ .id = .ignore_content_length, .long = "ignore-content-length", .help = "Refused. The length frames the body and finds a short one." },
    .{ .id = .request_target, .long = "request-target", .takes_value = true, .arg = "<path>", .help = "Refused. The request target here is the url path." },
    .{ .id = .alt_svc, .long = "alt-svc", .takes_value = true, .arg = "<path>", .help = "Refused. This build reads no Alt-Svc header and keeps no cache." },
    .{ .id = .hsts, .long = "hsts", .takes_value = true, .arg = "<path>", .help = "Refused. This build reads no HSTS header and keeps no cache." },

    // Flags refused by name. Proxy shapes this build does not carry.
    .{ .id = .proxy_header, .long = "proxy-header", .takes_value = true, .arg = "<header>", .help = "Refused. The CONNECT head here carries four fixed lines." },
    .{ .id = .proxy_tunnel, .long = "proxytunnel", .short = 'p', .help = "Refused. A cleartext url reaches a proxy as an absolute request." },
    .{ .id = .proxy_1_0, .long = "proxy1.0", .takes_value = true, .arg = "<host>", .help = "Refused. This build speaks HTTP/1.1 to a proxy." },
    .{ .id = .preproxy, .long = "preproxy", .takes_value = true, .arg = "<host>", .help = "Refused. This build dials one proxy and never two." },
    .{ .id = .proxy_http2, .long = "proxy-http2", .help = "Refused. This build speaks HTTP/1.1 to a proxy." },
    .{ .id = .proxy_http3, .long = "proxy-http3", .help = "Refused. This build speaks HTTP/1.1 to a proxy and offers no other version." },
    .{ .id = .haproxy_protocol, .long = "haproxy-protocol", .help = "Refused. This build writes no PROXY protocol header." },
    .{ .id = .haproxy_clientip, .long = "haproxy-clientip", .takes_value = true, .arg = "<ip>", .help = "Refused. This build writes no PROXY protocol header." },

    // Flags refused by name. FTP commands this build does not send.
    .{ .id = .ftp_account, .long = "ftp-account", .takes_value = true, .arg = "<data>", .help = "Refused. This build sends no ACCT." },
    .{ .id = .ftp_alternative_to_user, .long = "ftp-alternative-to-user", .takes_value = true, .arg = "<command>", .help = "Refused. This build sends USER and nothing in its place." },
    .{ .id = .ftp_create_dirs, .long = "ftp-create-dirs", .help = "Refused. This build sends no MKD, and it uploads nothing." },
    .{ .id = .ftp_method, .long = "ftp-method", .takes_value = true, .arg = "<method>", .help = "Refused. This build sends one CWD for each path element." },
    .{ .id = .ftp_port, .long = "ftp-port", .short = 'P', .takes_value = true, .arg = "<address>", .help = "Refused. This build is passive only. It listens for nothing." },
    .{ .id = .ftp_pret, .long = "ftp-pret", .help = "Refused. This build sends no PRET." },
    .{ .id = .ftp_ssl_ccc, .long = "ftp-ssl-ccc", .help = "Refused. This build sends no CCC, and never clears a control channel." },
    .{ .id = .ftp_ssl_ccc_mode, .long = "ftp-ssl-ccc-mode", .takes_value = true, .arg = "<mode>", .help = "Refused. This build sends no CCC, and never clears a control channel." },
    .{ .id = .ftp_ssl_control, .long = "ftp-ssl-control", .help = "Refused. This build sends PROT P, so the data channel is inside TLS." },
    .{ .id = .append, .long = "append", .short = 'a', .help = "Refused. This build uploads to no protocol that can append." },
    .{ .id = .quote, .long = "quote", .short = 'Q', .takes_value = true, .arg = "<command>", .help = "Refused. One file lists every command this build can send." },

    // Flags refused by name. Mail commands this build does not send.
    .{ .id = .mail_auth, .long = "mail-auth", .takes_value = true, .arg = "<address>", .help = "Refused. This build writes no AUTH parameter on MAIL FROM." },
    .{ .id = .mail_rcpt_allowfails, .long = "mail-rcpt-allowfails", .help = "Refused. One refused recipient ends the transfer here." },
    .{ .id = .upload_flags, .long = "upload-flags", .takes_value = true, .arg = "<flags>", .help = "Refused. This build sends no imap APPEND." },

    // Flags refused by name. The rest.
    .{ .id = .telnet_option, .long = "telnet-option", .short = 't', .takes_value = true, .arg = "<opt=val>", .help = "Refused. This build answers no telnet subnegotiation." },
    .{ .id = .compressed_ssh, .long = "compressed-ssh", .help = "Refused. This build asks for no ssh compression." },
    .{ .id = .ssh_pubkey, .long = "pubkey", .takes_value = true, .arg = "<path>", .help = "Refused. This build reads the public key out of the private key." },
    .{ .id = .crlf, .long = "crlf", .help = "Refused. This build sends an upload byte for byte." },
    .{ .id = .xattr, .long = "xattr", .help = "Refused. This build writes no extended file attribute." },
    .{ .id = .variable, .long = "variable", .takes_value = true, .arg = "<name=text>", .help = "Refused. This build expands no variable, so nothing would read it." },
    .{ .id = .libcurl, .long = "libcurl", .takes_value = true, .arg = "<path>", .help = "Refused. This build is not libcurl, so the code would not compile." },
    .{ .id = .manual, .long = "manual", .short = 'M', .help = "Refused. This build carries no manual page. --help lists every flag." },
};

fn longFlagSpec(name: []const u8) ?FlagSpec {
    for (flag_table) |entry| {
        const long = entry.long orelse continue;
        if (std.mem.eql(u8, long, name)) return entry.spec();
    }
    return null;
}

fn shortFlagSpec(c: u8) ?FlagSpec {
    for (flag_table) |entry| {
        const short = entry.short orelse continue;
        if (short == c) return entry.spec();
    }
    return null;
}

/// Handles one `--flag` or `--flag=value` token. `argv[i.*]` is `arg`;
/// `i.*` advances past a separate value argument when the flag takes one
/// and none was attached with `=`.
fn parseLong(
    b: *Builder,
    argv: []const []const u8,
    i: *usize,
    arg: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    const rest = arg[2..];
    var name = rest;
    var inline_value: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, rest, '=')) |eq| {
        name = rest[0..eq];
        inline_value = rest[eq + 1 ..];
    }

    // **The name alone, and never the value beside it.** `arg` is the whole
    // token, so `--use=alice:s3cret` echoed the password to standard error
    // and into whatever log holds it. `safe.Text` masks a url userinfo and
    // a bare `user:pass` is not one, so the mask could not help here. A
    // user who mistyped a flag needs the flag name and nothing else.
    const spec = longFlagSpec(name) orelse
        return fail(b.arena, fault, error.UnknownFlag, "zurl: unknown flag: '--{f}'", .{safe.text(name)});

    const value = if (!spec.takes_value)
        ""
    else if (inline_value) |v|
        v
    else blk: {
        if (i.* + 1 >= argv.len)
            return fail(b.arena, fault, error.MissingArgument, "zurl: option '{f}' needs an argument", .{safe.text(arg)});
        i.* += 1;
        break :blk argv[i.*];
    };

    try applyEffect(b, spec.id, value, arg, fault);
}

/// Handles one `-x`, `-xy`, or `-xVALUE` token: a cluster of bundled short
/// flags, ending in an optional attached value for the last one.
fn parseShortCluster(
    b: *Builder,
    argv: []const []const u8,
    i: *usize,
    arg: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    const cluster = arg[1..];
    var j: usize = 0;
    while (j < cluster.len) : (j += 1) {
        const c = cluster[j];
        const spec = shortFlagSpec(c) orelse
            return fail(b.arena, fault, error.UnknownFlag, "zurl: unknown flag: '-{c}'", .{c});

        if (!spec.takes_value) {
            try applyEffect(b, spec.id, "", arg, fault);
            continue;
        }

        const value = if (j + 1 < cluster.len)
            cluster[j + 1 ..]
        else blk: {
            if (i.* + 1 >= argv.len)
                return fail(b.arena, fault, error.MissingArgument, "zurl: option '-{c}' needs an argument", .{c});
            i.* += 1;
            break :blk argv[i.*];
        };

        // A value-taking flag consumes the rest of the cluster as its
        // value, the way curl reads `-XPOST`. Nothing follows it.
        try applyEffect(b, spec.id, value, arg, fault);
        return;
    }
}

fn applyEffect(
    b: *Builder,
    id: FlagId,
    value: []const u8,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    // Where this flag came from, so a fault raised after the walk can
    // still name the config file and line that set it. Recorded before
    // the effect runs, because a flag that fails still came from
    // somewhere.
    if (b.token) |at| b.flag_tokens.set(id, at);
    switch (id) {
        // **`-X` means two different things, and the url scheme decides
        // which.** HTTP reads it as a method, and a mail protocol reads it
        // as a whole command line, such as `TOP 1 0`. The value is kept
        // for both, and a value that names no HTTP method is refused after
        // the walk, when the urls are known. See `resolveCustomRequest`.
        .method => {
            b.options.custom_request = value;
            if (std.meta.stringToEnum(std.http.Method, value)) |named| {
                b.options.method = named;
                b.method_given = true;
                // The last `-X` wins, so a later one that names a method
                // clears a refusal an earlier one earned.
                b.unknown_method = null;
            } else {
                b.unknown_method = value;
            }
        },
        // The five `-d`-family flags and `--json` all append to one list,
        // in command-line order, because curl joins them into one body and
        // the separator depends on which flag comes next. `body.zig` holds
        // that rule and the measurements behind it. Nothing is opened
        // here: `parse` does no I/O.
        .data_ascii => try b.data_items.append(b.arena, .{ .kind = .ascii, .text = value }),
        .data_raw => try b.data_items.append(b.arena, .{ .kind = .raw, .text = value }),
        .data_binary => try b.data_items.append(b.arena, .{ .kind = .binary, .text = value }),
        .data_urlencode => try b.data_items.append(b.arena, .{ .kind = .urlencode, .text = value }),
        .json => try b.data_items.append(b.arena, .{ .kind = .json, .text = value }),
        // Every `-F` and `--form-string` appends to one list, in
        // command-line order, because each one is a part of the same body
        // and the order is the order on the wire. Measured:
        // `-F 'x=@a' -F 'y=@b'` sends the `x` part first.
        // `src/cli/form.zig` reads the syntax and opens the files.
        .form => try b.form_items.append(b.arena, .{ .kind = .form, .text = value }),
        .form_string => try b.form_items.append(b.arena, .{ .kind = .string, .text = value }),
        .form_escape => b.form_escape = true,
        // The last `-T` wins, which is what curl does with two of them on
        // one url.
        .upload_file => b.upload = value,
        .get => b.get = true,
        .head => b.head = true,
        .header => try b.headers.append(b.arena, parseHeader(value)),
        // **`-b` reads its own argument two ways, and the `=` decides.**
        // Measured against curl 8.21.0: `-b 'a=1; b=2'` put that exact
        // text on the wire as the `Cookie` header, and `-b jarfile` read
        // the file and sent what matched. curl's own manual states the
        // rule the same way. A file name holding an `=` is therefore read
        // as cookie text under both programs, which is why the rule is
        // written here where a reader meets it.
        //
        // Nothing is opened. `src/main.zig` reads each file into the jar.
        .cookie => {
            b.cookies_enabled = true;
            if (std.mem.indexOfScalar(u8, value, '=') != null) {
                try b.cookie_texts.append(b.arena, value);
            } else {
                try b.cookie_files.append(b.arena, value);
            }
        },
        // The last `-c` wins, which is what curl does with two of them.
        // `-c -` is standard output, the same shape `-D -` has.
        .cookie_jar => {
            b.cookies_enabled = true;
            b.cookie_jar = if (std.mem.eql(u8, value, "-"))
                .stdout
            else
                .{ .file = value };
        },
        // **`-j` does not turn the cookie engine on by itself.** Measured
        // against curl 8.21.0: `-j` alone, with two urls where the first
        // answered `Set-Cookie`, sent no `Cookie` header on the second, so
        // the flag needs a `-b` or a `-c` beside it. curl's own manual
        // says the same: the option requires the cookie engine. So this
        // sets the answer and never `cookies_enabled`.
        .junk_session_cookies => b.junk_session_cookies = true,
        .max_redirects => b.max_redirects_arg = try parseIntArg(u16, value, b.arena, flag_text, fault),
        .location => b.location = true,
        // **`--location-trusted` follows a redirect too.** Measured
        // against curl 8.21.0: the flag alone, with no `-L` beside it,
        // followed a `302` and carried the credential to the target. So it
        // sets both answers, and a `--max-redirs` still names the limit.
        //
        // The credential half is `options.location_trusted`. Nothing else
        // writes that field, and `Transfer.Options` defaults it to false,
        // so no command line without this flag can reach the trusting
        // path. See `zurl_http.engine.Request.trusted_secrets`.
        .location_trusted => {
            b.location = true;
            b.options.location_trusted = true;
        },
        // `--fail` and `--fail-with-body` each clear the other, so the
        // last one on the command line wins. Measured against curl 8.21.0
        // with a loopback server answering `404` with a body:
        //
        // ```
        // --fail --fail-with-body   exit 22, the body is written
        // --fail-with-body --fail   exit 22, no file is created
        // ```
        .fail_on_error => {
            b.options.fail_on_error = true;
            b.fail_with_body = false;
        },
        // The transfer must run to the end, so `options.fail_on_error`
        // stays off: that field stops the transfer before the body
        // reaches the caller. `src/cli/run.zig` reads `Plan.fail_with_body`
        // after the body is written and returns 22 there.
        .fail_with_body => {
            b.options.fail_on_error = false;
            b.fail_with_body = true;
        },
        .fail_early => b.fail_early = true,
        .connect_timeout => {
            const ms = try parseTimeoutMs(value, b.arena, flag_text, fault);
            b.options.connect_timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
        },
        // **A bound on the whole transfer, and zero means none.**
        // Measured against curl 8.21.0: `--max-time 0` waited for a
        // server that answered nothing until the server gave up, so zero
        // is not an instant deadline. A negative value is exit 2, which
        // `parseTimeoutMs` already answers with.
        .max_time => {
            const ms = try parseTimeoutMs(value, b.arena, flag_text, fault);
            b.max_time = if (ms == 0)
                .none
            else
                .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
        },
        // `-C -` reads the offset off the destination file, and any other
        // argument names the offset itself. `src/cli/run.zig` measures the
        // file, because `parse` opens nothing.
        .continue_at => b.resume_at = if (std.mem.eql(u8, value, "-"))
            .file_size
        else
            .{ .offset = try parseIntArg(u64, value, b.arena, flag_text, fault) },
        .speed_limit => b.options.low_speed_limit = try parseIntArg(u64, value, b.arena, flag_text, fault),
        .speed_time => b.options.low_speed_time_s = try parseIntArg(u32, value, b.arena, flag_text, fault),
        .limit_rate => b.options.max_bytes_per_second = try parseSize(value, b.arena, flag_text, fault),
        .max_filesize => b.options.max_size = try parseSize(value, b.arena, flag_text, fault),
        .user => b.options.credentials = parseUser(value),
        .netrc_file => b.netrc_path = value,
        // **The three that decide which ssh host key is trusted.** Each
        // one is written here and read in `zurl_sftp` and `zurl_scp`. None
        // of them turns
        // a check off: `--knownhosts` moves the file, and the two pins
        // name one key and refuse every other. The flag that skips the
        // check is `-k`, and it is the same `-k` that skips a TLS
        // certificate check.
        .known_hosts => b.options.ssh_known_hosts = value,
        .host_pub_md5 => b.options.ssh_host_pub_md5 = value,
        .host_pub_sha256 => b.options.ssh_host_pub_sha256 = value,
        // The last of the two wins, the way the last of any other pair
        // does. `--netrc-file` keeps its own field and is not touched
        // here: it names a file, and these two name a policy for the
        // default one.
        .netrc => b.netrc_mode = .required,
        .netrc_optional => b.netrc_mode = .optional,
        .user_agent => b.options.user_agent = value,
        .cacert => b.options.ca.cacert = value,
        .capath => b.options.ca.capath = value,
        .ca_native => b.options.ca.ca_native = true,
        // **The one flag that turns a security check off.**
        //
        // It is written here and nowhere else. `Transfer.Options.insecure`
        // defaults to false, `zurl.Client` copies this field through
        // unchanged, and `zurl_http.h1` reads it at the one place a TLS
        // hop is opened. No fault path anywhere sets it: a handshake that
        // could not verify the peer is reported, and never tried again
        // without the check.
        //
        // Both halves of the check go, which is what curl does. Measured
        // against curl 8.21.0: `-k https://expired.badssl.com/` answers
        // 200 and exits 0, and the same url with no flag exits 60.
        .insecure => b.options.insecure = true,
        // **The proxy flags.** Each one records its argument and nothing
        // more; `resolveProxy` reads them all after the walk, so the order
        // of `-x`, `--socks5`, and `--noproxy` on one command line does not
        // change the answer. curl reads its own the same way.
        //
        // `-x ""` turns proxying off, environment variables included.
        // Measured against curl 8.21.0: with `http_proxy` set, `-x ""` sent
        // the request straight to the origin.
        .proxy => {
            b.proxy_arg = value;
            b.proxy_kind = null;
        },
        // A `--socks` flag names the proxy and the protocol together, so it
        // records the kind beside the argument. The last proxy flag on the
        // command line wins, which is what curl does.
        .socks4 => {
            b.proxy_arg = value;
            b.proxy_kind = .socks4;
        },
        .socks4a => {
            b.proxy_arg = value;
            b.proxy_kind = .socks4a;
        },
        .socks5 => {
            b.proxy_arg = value;
            b.proxy_kind = .socks5;
        },
        .socks5_hostname => {
            b.proxy_arg = value;
            b.proxy_kind = .socks5h;
        },
        .noproxy => b.noproxy_arg = value,
        // **The proxy's credential, and never the origin's.** `-u` fills
        // `options.credentials` and this fills `options.proxy_credentials`.
        // The two are separate fields all the way to two separate builders,
        // `zurl/authorize.zig` and `zurl/proxy.zig`.
        //
        // The split is on the FIRST colon, exactly as `-u` splits: a
        // password may hold one and a user name may not.
        .proxy_user => b.options.proxy_credentials = parseUser(value),
        // The default already. curl has the flag so a config file can undo
        // a `--proxy-digest` on an earlier line.
        .proxy_basic => b.proxy_auth_refused = null,
        // **Neither is in this build, and neither may quietly become
        // Basic.** A user who asked for Digest asked for a scheme where the
        // password never travels. Answering with Basic would put that
        // password on the wire in reversible base64, to a proxy, in
        // cleartext. That is a downgrade the user did not ask for, so the
        // run stops instead. `src/main.zig` prints the sentence.
        .proxy_digest => b.proxy_auth_refused = "--proxy-digest",
        .proxy_anyauth => b.proxy_auth_refused = "--proxy-anyauth",
        // **The proxy's own verification, and never the origin's.**
        // `--insecure` answers for the origin and this answers for the
        // proxy. A `CONNECT` tunnel through a cleartext proxy still
        // verifies the origin against the origin's name and roots, whatever
        // this flag says.
        .proxy_insecure => b.options.proxy_insecure = true,
        // And the proxy's own roots, in their own `ca.Inputs`. A build that
        // wrote these into `options.ca` would verify the origin against the
        // proxy's roots.
        .proxy_cacert => b.options.proxy_ca.cacert = value,
        .proxy_capath => b.options.proxy_ca.capath = value,
        // `-o` and `-O` append to one list, so they pair with the urls in
        // the order the command line gave them. Neither refuses the
        // other: curl 8.21.0 accepts `-o a -O URL1 URL2` and writes both.
        //
        // **`-o -` means standard output, not a file named `-`.** Measured
        // against curl 8.21.0: `curl -o - URL` writes the body to standard
        // output and creates no file. curl keeps this reading wherever
        // `-` falls in the destination list, including twice
        // (`-o - -o -` sends both urls' bodies to standard output) and
        // beside `-O` in either order. The one escape hatch is a path
        // that names the same file without spelling exactly `-`: `-o ./-`
        // still writes a file called `-`, measured, and `checkBytes` in
        // `src/cli/output.zig` already accepts a leading `-` in an `-O`
        // name, so that path was never blocked from the other end either.
        .output_file => try b.output_targets.append(b.arena, targetForOutputPath(value)),
        .output_url_name => try b.output_targets.append(b.arena, .url_name),
        // `-D -` means standard output too, the same reading `-o -` gets
        // and the same measurement: curl 8.21.0 writes the head blocks to
        // standard output and creates no file named `-`.
        .headers_file => b.output.headers_file = if (std.mem.eql(u8, value, "-"))
            .stdout
        else
            .{ .file = value },
        .create_dirs => b.create_dirs = true,
        .no_clobber => b.no_clobber = true,
        .silent => b.silent = true,
        .show_error => b.show_error = true,
        .progress_bar => b.progress_bar = true,
        .no_progress_meter => b.no_progress_meter = true,
        .write_out => b.write_out = value,
        .parallel => b.parallel = true,
        // Recorded, not read: `parse` does no I/O. `scanConfigPaths` reads
        // `b.config_paths` back out; `parseWithConfigFiles` is what turns
        // a path into text.
        .config_file => try b.config_paths.append(b.arena, value),
        // Only a position in argv gives `-q`/`--disable` an effect
        // (`defaultConfigDisabled` checks that directly), so the flag
        // itself does nothing here. It is still a recognised flag, not
        // `error.UnknownFlag`, wherever it appears.
        .disable_default_config => {},
        // **This flag owns the `Accept-Encoding` header, and a run that
        // does not name it sends none.**
        //
        // `--compressed` asks curl to advertise the codings it decodes and
        // to decode the answer before the caller sees it. Measured on the
        // wire with a loopback listener that captured the request bytes:
        //
        // ```
        // curl:              (no Accept-Encoding header at all)
        // curl --compressed: Accept-Encoding: deflate, gzip, br, zstd
        // zurl:              (no Accept-Encoding header at all)
        // zurl --compressed: Accept-Encoding: deflate, gzip, zstd
        // ```
        //
        // The flag was a no-op here while zurl asked for `gzip, deflate`
        // on every request. That default was the defect: a server may
        // compress an answer to zurl where it would send curl the plain
        // body, so the two tools read different octets off the same url
        // and no flag chose between them.
        //
        // zurl's list is curl's with `br` struck out. Brotli is not in the
        // Zig standard library and its static dictionary alone is over
        // 100 KiB, and a client that advertises a coding it cannot decode
        // asks for octets it must then refuse. `zstd` needed no new
        // dependency: `std.compress.zstd` ships a decoder. See
        // `zurl_http.h1.accept_encoding_value`.
        //
        // **The flag decides decoding, and the offer it sends decides
        // nothing.** Measured against curl 8.21.0, `curl --compressed -H
        // 'Accept-Encoding: gzip'` answered in zstd decoded it, and a
        // plain `curl` answered in gzip wrote the compressed octets out.
        // So a run without this flag takes whatever arrives as the body,
        // and a run with it decodes or reports 61.
        // `zurl_http.engine.contentEncoding` is the one rule.
        //
        // `compressed` is an ordinary line of a real `~/.curlrc`. This
        // flag being unknown made every zurl run on such a machine exit 2
        // before any transfer.
        .compressed => b.options.accept_encoding = true,
        // Each list starts from the flag's **own** default, and never from
        // the set a previous `--proto` built. Measured against curl
        // 8.21.0: `--proto -all,https --proto +ftp` still runs an `http`
        // url, so the second flag started from every protocol again and
        // the first one's set was gone. See `zurl_core.redirect.Set.parse`
        // for the syntax and for every row that was measured.
        .protocols => b.options.protocols = try parseProtocols(
            value,
            zurl_core.redirect.transfer_default,
            b.arena,
            flag_text,
            fault,
        ),
        .redirect_protocols => b.options.redirect_protocols = try parseProtocols(
            value,
            zurl_core.redirect.redirect_default,
            b.arena,
            flag_text,
            fault,
        ),
        // **The scheme a url that carries none is read with.**
        //
        // zurl already read a schemeless url as `http`, or as `ftp` for a
        // host starting `ftp.`, so this flag changes which scheme that is
        // and nothing else. curl replaces its own guess the same way:
        // measured, `--proto-default http ftp.gnu.org/` reaches
        // `http://ftp.gnu.org/` where the bare url reaches `ftp://`.
        //
        // Both faults are curl's own, and each keeps curl's exit code. An
        // empty name is a usage fault and exits 2. A name no protocol
        // carries exits **1**, before any transfer, even when every url on
        // the command line already spells its scheme out; curl checks the
        // flag itself and not the urls, and this does too.
        .default_protocol => {
            if (value.len == 0) return fail(
                b.arena,
                fault,
                error.MissingProtocolName,
                "zurl: option '{f}': needs a protocol name",
                .{safe.text(flag_text)},
            );
            if (zurl_core.redirect.Protocol.fromName(value) == null) return fail(
                b.arena,
                fault,
                error.UnsupportedProtocolName,
                "zurl: option '{f}': '{f}' is not a protocol zurl knows",
                .{ safe.text(flag_text), safe.text(value) },
            );
            b.options.default_protocol = value;
        },
        // **Accepted, and they cannot lower the floor.** zurl speaks TLS
        // 1.2 and TLS 1.3, so a flag asking for 1.0 or 1.1 asks for
        // something below what this build offers.
        //
        // Refusing either flag would exit 2 on a command line curl runs,
        // and that is the opposite of a drop-in replacement. curl on this
        // machine accepts both and still cannot negotiate either version,
        // because OpenSSL 3.6.3 refuses them at its default security
        // level, so the run fails at the handshake with exit 35. zurl
        // fails the same connection with the same code.
        // `zurl_core.tls.MinVersion` carries the measurement.
        .tls_v1_0 => try namedFloor(b, .tls_1_0, flag_text, fault),
        .tls_v1_1 => try namedFloor(b, .tls_1_1, flag_text, fault),
        // These two do raise the floor, and `max` keeps the highest of
        // however many the command line named.
        .tls_v1_2 => {
            try namedFloor(b, .tls_1_2, flag_text, fault);
            b.options.tls_min_version = b.options.tls_min_version.max(.tls_1_2);
        },
        .tls_v1_3 => {
            try namedFloor(b, .tls_1_3, flag_text, fault);
            b.options.tls_min_version = b.options.tls_min_version.max(.tls_1_3);
        },
        // **The highest TLS version to keep.**
        //
        // `1.3` and `default` are a no-op: TLS 1.3 is already this
        // build's ceiling. `1.2` narrows the client hello to TLS 1.2, so a
        // server that speaks both answers with TLS 1.2 and the transfer
        // runs, which is what curl does. `1.0` and `1.1` are below the
        // TLS 1.2 floor of this build, so the flag is accepted here and
        // the transfer then fails with 35 and a sentence naming the
        // conflict. curl fails the same command line with the same code,
        // because its OpenSSL refuses both versions at its default
        // security level.
        //
        // The last `--tls-max` wins. Measured:
        // `--tls-max 1.2 --tls-max 1.3 --tlsv1.3` runs.
        .tls_max => {
            const named = zurl_core.tls.Version.fromMaxText(value) orelse return fail(
                b.arena,
                fault,
                error.InvalidTlsVersion,
                "zurl: option '{f}': '{f}' is not one of default, 1.0, 1.1, 1.2, or 1.3",
                .{ safe.text(flag_text), safe.text(value) },
            );
            // curl checks the pair as each flag arrives, and names the
            // flag that closed the range. This is the `--tls-max` side of
            // that check; `namedFloor` is the other side.
            if (b.tls_named_min) |floor| {
                if (@intFromEnum(named) < @intFromEnum(floor)) return fail(
                    b.arena,
                    fault,
                    error.TlsVersionRangeEmpty,
                    "zurl: option '{f}': {s} is below the {s} an earlier flag asked for",
                    .{ safe.text(flag_text), named.name(), floor.name() },
                );
            }
            b.tls_named_max = named;
            b.options.tls_max_version = named;
        },
        // **`--http1.1` narrows the ALPN offer to `http/1.1`.**
        //
        // zurl offers `h2` and `http/1.1` now, and a peer that speaks
        // HTTP/2 chooses `h2`. This flag takes that entry out of the
        // offer, so the peer cannot choose it and the transfer runs on
        // HTTP/1.1. That is the way back when a peer's HTTP/2 misbehaves,
        // and it is what the same flag does beside curl.
        .http_1_1 => b.options.http_version = .http_1_1,
        // **`--http2` asks for HTTP/2, and over TLS that is already the
        // default.**
        //
        // The flag is a *request*, not a demand: curl 8.21.0 with
        // `--http2` against an HTTP/1.1 server exits 0 and speaks
        // HTTP/1.1, measured on a loopback listener. zurl offers both
        // names with or without this flag, so a peer with no HTTP/2 still
        // answers `http/1.1` and the transfer runs.
        //
        // **Over cleartext it does change something.** There is no ALPN on
        // an `http` url, so curl asks with the RFC 7540 section 3.2
        // `Upgrade: h2c` fields instead. Measured on a loopback listener:
        // `curl --http2 http://host/path` wrote `Upgrade: h2c`,
        // `HTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA`, and
        // `Connection: Upgrade, HTTP2-Settings`, and the same command with
        // no flag wrote a plain request with none of them. zurl sends the
        // same three fields. See `engine.HttpVersion`.
        //
        // A later `--http1.1` still wins, because the last flag on the
        // command line is the one that sets the field. curl reads its own
        // version flags the same way.
        .http_2 => b.options.http_version = .http_2,
        // **`--http2-prior-knowledge` speaks HTTP/2 and takes no other
        // answer.**
        //
        // Over cleartext the connection preface goes out first and no
        // HTTP/1.1 octet is ever written, which is RFC 9113 section 3.3.
        // Over TLS the ALPN offer is `h2` alone, so a peer with no HTTP/2
        // ends the handshake rather than answer on HTTP/1.1: measured
        // against an `openssl s_server` offering `http/1.1`, curl 8.21.0
        // gave `tlsv1 alert no application protocol` and exit 35 for this
        // flag and exit 0 on HTTP/1.1 for `--http2`.
        //
        // This is the flag for a peer that is known to speak HTTP/2 and
        // has no way to say so, such as a gRPC service on a loopback port.
        .http2_prior_knowledge => b.options.http_version = .prior_knowledge,
        // **`--http3` asks for HTTP/3 and falls back to the TCP hop.**
        //
        // The flag is a request, not a demand, exactly as `--http2` is.
        // Measured against curl 8.21.0 and `https://example.com/`, a host
        // with no HTTP/3: `curl --http3` exited 0, reported
        // `%{http_version} 2`, and wrote nothing on standard error. The
        // same command against `https://ziglang.org/` reported `1.1`. zurl
        // does the same, and counts the fallback in `Engine.h3_fallbacks`
        // so the recovery is not silent inside the engine.
        //
        // **HTTP/3 is never the default, and this flag is the only way to
        // it.** QUIC needs UDP 443 reachable end to end, and many networks
        // pass TCP and drop UDP. curl takes the same view: measured,
        // `curl https://cloudflare.com/`, a host that does speak HTTP/3,
        // reported `%{http_version} 2`.
        //
        // A later `--http1.1` or `--http2` still wins, because the last
        // version flag on the command line is the one that sets the field.
        // curl reads its own version flags the same way.
        .http3 => b.options.http_version = .http_3,
        // **`--http3-only` speaks HTTP/3 and takes no other answer.**
        //
        // Measured against curl 8.21.0 and `https://example.com/`:
        // `curl --http3-only` exited 7 and wrote `Failed to connect to
        // example.com:443 after 119 ms`, where `--http3` on the same host
        // exited 0 over HTTP/2. On a cleartext url curl exited 3 with
        // `HTTP/3 requested for non-HTTPS URL`, and zurl refuses that hop
        // with the same code. See `h1.h3Choice`.
        .http3_only => b.options.http_version = .http_3_only,
        // **Real behaviour: it leaves Nagle's algorithm on.** zurl sets
        // `TCP_NODELAY` on every connection, the way curl does, so this
        // flag has something to turn off. See
        // `zurl_net.tcp.DialOptions.no_delay`.
        .no_tcp_nodelay => b.options.tcp_no_delay = false,
        // **Accepted, and it changes nothing, because zurl turns TCP
        // keepalive on for no connection.**
        //
        // The flag is about keepalive *probes*, the `SO_KEEPALIVE` socket
        // option, and not about reusing a connection for a second
        // request. Measured against curl 8.21.0 with a loopback listener
        // that counts connections: `--no-keepalive` with two urls on one
        // host still sent both requests down one connection. So zurl must
        // keep its pool under this flag, and turning the pool off here
        // would be the divergence, not the match.
        .no_keepalive => {},
        // **Accepted, and it changes nothing, because zurl holds no body
        // back.** `-N` asks curl to stop buffering the body it writes.
        // zurl streams the body straight through and flushes at the end
        // of each url, so there is no second behaviour to select.
        .no_buffer => {},
        // The last `-r` wins, the way the last `-C` does. Measured:
        // `-r 0-9 -r 5-6` sends `Range: bytes=5-6`. The text is checked
        // and given its prefix after the walk, in `resolveRange`.
        .range => b.range_arg = value,
        // **The `--retry` family. Each row was measured. See `Retry`.**
        //
        // The last of each wins, which is what curl does with two of the
        // same flag: a later value replaces an earlier one rather than
        // adding to it.
        .retry => b.retry.attempts = try parseIntArg(u32, value, b.arena, flag_text, fault),
        // **Zero reads as no delay named at all**, so the wait doubles.
        // Measured: `--retry 3 --retry-delay 0` tried at 0, 1, 3, and 7
        // seconds, which is the doubling wait and not a wait of nothing.
        .retry_delay => {
            const seconds = try parseIntArg(u32, value, b.arena, flag_text, fault);
            b.retry.delay_s = if (seconds == 0) null else seconds;
        },
        .retry_max_time => b.retry.max_time_s = try parseIntArg(u32, value, b.arena, flag_text, fault),
        .retry_connrefused => b.retry.connrefused = true,
        .retry_all_errors => b.retry.all_errors = true,
        // **The Referer, and the `;auto` suffix that keeps it current.**
        //
        // Measured against curl 8.21.0 on a loopback server:
        //
        // ```
        // -e http://a/          Referer: http://a/
        // -e ';auto'            no Referer on the first request
        // -e 'http://a/;auto'   Referer: http://a/ on the first request
        // -e ''                 no Referer at all
        // -e a -e b             Referer: b
        // -e x -H 'Referer: y'  Referer: y
        // ```
        //
        // And with `-L` through a `302`, the second hop carried
        // `Referer: <the first hop's url>` under `;auto`, and the fixed
        // text under a plain `-e`. `options.auto_referer` is that half,
        // and `zurl_http.h1` owns it, because only the engine walks the
        // chain.
        .referer => {
            if (std.mem.endsWith(u8, value, auto_referer_suffix)) {
                b.referer = value[0 .. value.len - auto_referer_suffix.len];
                b.options.auto_referer = true;
            } else {
                b.referer = value;
            }
        },
        // **`--resolve` and `--connect-to` move the dial and nothing
        // else.** The `Host` header, the TLS server name, and the name the
        // certificate is checked against all stay the ones the url wrote.
        // See `Transfer.Options.connect_to`, which holds the rule and the
        // measurement, and `zurl_http.h1.dialTarget`, which enforces it.
        .resolve => try appendOverride(b, try parseResolve(b, value, flag_text, fault), flag_text, fault),
        .connect_to => try appendOverride(b, try parseConnectTo(b, value, flag_text, fault), flag_text, fault),
        .parallel_max => b.parallel_max = try parseIntArg(usize, value, b.arena, flag_text, fault),
        // **`--no-alpn` leaves the ALPN extension out of the client
        // hello.** zurl offers `http/1.1` alone, so the flag changes no
        // protocol: the transfer runs on HTTP/1.1 with the extension and
        // without it. It changes the bytes of the handshake, which is why
        // curl has the flag at all, and a peer or a middlebox that answers
        // ALPN badly is what a user reaches for it with.
        .no_alpn => b.options.no_alpn = true,
        // **Accepted, and it changes nothing, because zurl reads no glob.**
        // curl reads `{a,b}` and `[1-9]` in a url as a list of urls unless
        // `-g` turns that off. zurl never read them, so every zurl run
        // already behaves the way `curl -g` does, and a url holding a
        // brace reaches the wire as written under both flags.
        .globoff => {},
        // **`-l` asks an FTP directory for names alone, and HTTP ignores
        // it, which is what curl does.** Measured against curl 8.21.0: an
        // `ftp://` url naming a directory sends `NLST` with the flag and
        // `LIST` without one, and an `http://` url answers byte for byte
        // the same either way.
        .list_only => b.options.list_only = true,
        // **`--ssl-reqd` puts TLS on an ftp control connection, and a
        // server that refuses fails the transfer.** See
        // `zurl.Transfer.Options.ftp_ssl_required`, which holds the
        // measurement and why `--ssl` is not here beside it.
        .ssl_required => b.options.ftp_ssl_required = true,
        // **The last `--mail-from` wins and every `--mail-rcpt` is
        // kept.** A message has one sender and any number of recipients,
        // and curl reads the two flags the same way.
        .mail_from => b.options.mail_from = value,
        .mail_rcpt => try appendRecipient(b, value, fault),
        // **The three SASL controls of a mail login.** Each is carried
        // and none is checked here: a NUL in an authzid or a mechanism
        // name that is not the `AUTH=` form both reach a message that
        // names the flag, at the protocol package that builds the SASL
        // exchange. See `zurl_net.sasl`.
        .sasl_authzid => b.options.sasl_authzid = value,
        .sasl_ir => b.options.sasl_ir = true,
        .login_options => b.options.login_options = value,

        // **The last spelling of each of the six below wins**, the way the
        // last `--mail-from` does. Each names one thing about one request,
        // and a run that named it twice meant the second.
        //
        // Nothing here checks the value for a forged line ending. The two
        // that reach an rtsp header line and the one that reaches an rtsp
        // request line all pass through `zurl_net.line.write` inside
        // `zurl-rtsp`, which is the one gate this repository keeps, and a
        // check here as well would be a second place to get it wrong. The
        // mqtt client id reaches a length-counted string, so no byte in it
        // can end a field at all; `zurl-mqtt` refuses the NUL that MQTT
        // itself forbids.
        .mqtt_client_id => b.options.mqtt_client_id = value,
        .mqtt_messages => b.options.mqtt_messages = try readMessageCount(b, value, flag_text, fault),
        .rtsp_request => b.options.rtsp_request = value,
        .rtsp_session_id => b.options.rtsp_session_id = value,
        .rtsp_stream_uri => b.options.rtsp_stream_uri = value,
        .rtsp_transport => b.options.rtsp_transport = value,

        // **`--url` is a url and not a setting.** It joins the list where
        // the user typed it, so `-o a --url URL1 URL2` still pairs `a`
        // with the first url. `OutputSpec.bodyTarget` reads that list by
        // position, so an appended url that jumped the queue would write
        // another url's file.
        .url_arg => try b.urls.append(b.arena, value),

        .verbose => b.verbose = true,
        .show_headers => b.show_headers = true,
        .stderr_file => b.stderr_path = value,
        // **Accepted, and it changes nothing, because `-v` prints no
        // CONNECT head.** The flag hides the head of a proxy `CONNECT`
        // from curl's verbose output. zurl's `-v` prints the head of the
        // response the transfer returned and nothing from inside the
        // tunnel setup, so the state the flag asks for is the state every
        // run is already in.
        .suppress_connect_headers => {},

        // **The three origin authentication flags.** See
        // `zurl.Transfer.AuthMode`, which holds where the password goes
        // and when for each of the three.
        .auth_basic => b.options.auth_mode = .basic,
        .auth_digest => b.options.auth_mode = .digest,
        .auth_anyauth => b.options.auth_mode = .any,

        .output_dir => b.output_dir = value,
        .create_file_mode => b.create_file_mode = try parseFileMode(value, b.arena, flag_text, fault),
        .remove_on_error => b.remove_on_error = true,
        .remote_time => b.remote_time = true,
        .remote_header_name => b.remote_header_name = true,
        // Neither file is opened here. `parse` does no I/O, so
        // `src/main.zig` reads the one and `src/cli/run.zig` writes the
        // other. The last of two flags wins, which is what curl does.
        .etag_compare => b.etag_compare = value,
        .etag_save => b.etag_save = value,
        // **Kept raw, prefix and all.** The argument may name a date or a
        // file, and telling the two apart needs a `stat`, which `parse`
        // never does. `src/main.zig` reads it through
        // `src/cli/timecond.zig`. The last `-z` wins.
        .time_cond => b.time_cond = value,
        .rate => b.rate_wait_ms = try parseRate(value, b.arena, flag_text, fault),
        // **Accepted, and it changes nothing, because every `-Z` transfer
        // here starts as soon as a worker is free.** The flag tells curl
        // not to hold a transfer back while it waits to learn whether an
        // existing connection can multiplex it. zurl gives each worker a
        // `Client` and a connection pool of its own, so no worker ever
        // waits on another worker's connection, and the state the flag
        // asks for is the state every run is already in.
        .parallel_immediate => {},
        // curl reads a value outside its own range as though the flag
        // were not there, and `src/cli/run.zig` does the same with a
        // note. The number itself is still checked here, so a user who
        // typed one wrong learns it before any socket opens.
        .parallel_max_host => b.parallel_max_host = try parseIntArg(usize, value, b.arena, flag_text, fault),
        // **The other half of `--no-clobber`, so the pair can be
        // written in either order.** curl reads the last of the two, and
        // so does this: a `--clobber` after a `--no-clobber` in a config
        // file puts the command line back in charge.
        .clobber => b.no_clobber = false,

        // **Four waits this build does not keep.** Each argument is still
        // read and still refused when it does not parse, because a user
        // who typed a number wrong learns it here rather than never. What
        // each one would have bounded does not happen in zurl:
        //
        // - `--expect100-timeout` waits for a `100 Continue`. zurl sends
        //   no `Expect: 100-continue` on any request, so no wait starts.
        // - `--happy-eyeballs-timeout-ms` bounds the head start one
        //   address family gets over the other. zurl dials one address at
        //   a time, so there is no second attempt to time.
        // - `--keepalive-time` and `--keepalive-cnt` shape the TCP
        //   keepalive probes. zurl turns `SO_KEEPALIVE` on for no
        //   connection, which is what `--no-keepalive` already says here.
        //
        // Accepted rather than refused because none of the three asks for
        // a guarantee the run then breaks: a transfer with no `Expect`
        // header and no keepalive probe is the transfer the flag was
        // trying to shape. A refusal would stop a script that names one
        // out of habit.
        .expect100_timeout,
        .keepalive_time,
        => _ = try parseTimeoutMs(value, b.arena, flag_text, fault),
        .happy_eyeballs_timeout_ms => _ = try parseIntArg(u32, value, b.arena, flag_text, fault),
        .keepalive_cnt => _ = try parseIntArg(u32, value, b.arena, flag_text, fault),

        // **Refused by name, and the run stops.** Each of these asks for
        // something this build cannot do, and each of them fails quietly
        // if it is accepted and dropped: a client certificate that never
        // goes out looks to the user like a server that refused them, and
        // a cipher list that changes nothing looks like a policy that was
        // applied. `src/main.zig` prints the sentence and exits 2 before
        // any socket opens. See `Plan.unsupported_flag`.
        //
        // **The name comes from this table and never from `flag_text`.**
        // `flag_text` is the argument as the user wrote it, and
        // `--pass=hunter2` writes the passphrase into it. Echoing that in
        // a message would put a secret on standard error, into a CI log,
        // and into a journal, over a flag whose whole purpose is to carry
        // one. `src/cli/safe.zig` masks a password inside a *url* and has
        // no rule that could find this one, so the fix is to name the
        // flag and never the argument.
        .client_cert => refuse(b, "--cert", client_certificate_reason),
        .client_cert_type => refuse(b, "--cert-type", client_certificate_reason),
        .client_key => refuse(b, "--key", client_certificate_reason),
        .client_key_type => refuse(b, "--key-type", client_certificate_reason),
        .client_key_pass => refuse(b, "--pass", client_certificate_reason),
        .ciphers => refuse(b, "--ciphers", ciphers_reason),
        .curves => refuse(b, "--curves", curves_reason),
        .trace => refuse(b, "--trace", trace_reason),
        .trace_ascii => refuse(b, "--trace-ascii", trace_reason),
        .trace_time => refuse(b, "--trace-time", trace_reason),
        .trace_ids => refuse(b, "--trace-ids", trace_reason),
        .trace_config => refuse(b, "--trace-config", trace_reason),

        // **The other half of `--no-tcp-nodelay`, so the pair can be
        // written in either order**, the way `--clobber` answers
        // `--no-clobber` above. True is the default, so this flag names
        // the state a run with no flag is already in, and it also puts a
        // `--no-tcp-nodelay` from a config file back.
        .tcp_nodelay => b.options.tcp_no_delay = true,
        // `-B` reaches FTP alone. `zurl.Transfer.Options.use_ascii` holds
        // the rule and the measurement behind it.
        .use_ascii => b.options.use_ascii = true,
        .disable_epsv => b.options.ftp_disable_epsv = true,
        // The number is checked here, before any datagram, and it is
        // never clamped. `zurl_tftp.packet` holds the two bounds.
        .tftp_blksize => b.options.tftp_block_size = try parseTftpBlockSize(
            value,
            b.arena,
            flag_text,
            fault,
        ),
        .tftp_no_options => b.options.tftp_send_options = false,
        // **Both flags answer for every url that no `-o` and no `-O`
        // covers.** `OutputSpec.body` pairs with the url list one for
        // one, and these two replace what the tail of that list reads as.
        // The last of the two wins, which is what curl does. See
        // `OutputSpec.tail`.
        .remote_name_all => b.output_tail = .url_name,
        .out_null => b.output_tail = .discard,
        .skip_existing => b.skip_existing = true,
        // `--url-query` is `--data-urlencode` that always lands in the
        // query, with no `-G` needed and with a request body still
        // permitted beside it. See `DataKind.url_query`.
        .url_query => try b.query_items.append(b.arena, .{ .kind = .urlencode, .text = value }),
        // Checked after the walk, when every url has been seen. See
        // `resolveUsernameInUrl`.
        .disallow_username_in_url => b.disallow_username_in_url = true,
        // Read by `src/main.zig`, which writes the bundle and stops. No
        // transfer runs, so no other flag of the run is honoured.
        .dump_ca_embed => b.dump_ca_embed = true,
        // **A bearer token is a secret in a command line argument.** It is
        // carried, never echoed: no message here writes `value`, and the
        // header line gate lives in `zurl.authorize`. See
        // `zurl.Transfer.Options.bearer_token` for the order it takes
        // against `-u` and against a `-H Authorization`.
        .oauth2_bearer => b.options.bearer_token = value,
        // The mirror of `--ca-native`, for the proxy trust store alone.
        // The two stores are separate and must stay separate. See
        // `zurl.Transfer.Options.proxy_ca`.
        .proxy_ca_native => b.options.proxy_ca.ca_native = true,
        // **These three keep a body across a redirect, so each one is a
        // deliberate choice by the user.** A kept body reaches whichever
        // host the first server named. That is why none of them is the
        // default and why `--location-trusted` is still the only flag that
        // lets a *secret* cross. A body is not a secret in that sense: the
        // user addressed it to a url, and the server they asked answered
        // with another url for the same request. curl reads it the same
        // way. See `zurl_http.engine.RedirectMethods`.
        .post301 => b.options.redirect_methods.post301 = true,
        .post302 => b.options.redirect_methods.post302 = true,
        .post303 => b.options.redirect_methods.post303 = true,
        // **`--follow` is `-L`, and it is not the three flags above.**
        // Measured against curl 8.21.0 on a loopback pair, with a 301, a
        // 302, and a 303:
        //
        // ```
        // -L       -d a=1        GET /moved, no body
        // --follow -d a=1        GET /moved, no body
        // -L       -T file       PUT /moved on 301 and 302, GET on 303
        // --follow -T file       PUT /moved on 301 and 302, GET on 303
        // -L       -X PUT -d a=1 PUT /moved
        // --follow -X PUT -d a=1 GET /moved
        // ```
        //
        // So the two flags answer the same for every command line that
        // does not name `-X`. The one row where they differ is the one
        // where `-X` pins the method text: curl's `-L` carries that text
        // to the redirect target and curl's `--follow` drops it, which is
        // what "per spec" means in the help line.
        //
        // **zurl cannot tell those two rows apart**, because
        // `zurl_http.engine.Request` carries no answer to "did the user
        // name this method". `h1.Exchange.rewriteHop` already records that
        // gap and the divergence it causes for `-L`, and `--follow`
        // inherits it. So this sets the following alone, and `--help`
        // names the corner. It is not made into the three flags above:
        // those keep a body across a redirect, and `--follow` never does.
        .follow => b.location = true,

        // **Accepted, and each one changes nothing.** Every flag below
        // names a state this build is already in, or names a curl feature
        // curl itself has dropped. curl's own observable answer is the
        // same answer zurl gives, so a refusal would stop a script over a
        // flag that was never going to change a byte.
        //
        // - `--path-as-is` asks that a `..` in the url path reach the
        //   server. zurl never squashes one: measured against a loopback
        //   listener, `zurl http://h/a/../b` sends `GET /a/../b` and curl
        //   with no flag sends `GET /b`. A `..` inside a `Location:`
        //   header is still resolved by RFC 3986, which is what curl does
        //   with the flag too.
        // - `--ftp-pasv` asks for the passive mode, and passive is the
        //   only mode here. `--disable-eprt` asks that no `EPRT` go out,
        //   and none can. `--ftp-skip-pasv-ip` asks that the address a
        //   `PASV` answer names never be dialled, and it never is: that
        //   address is written by the server. See
        //   `zurl_ftp.Fetcher.dataTarget`.
        // - `--no-sessionid` asks that no TLS session be reused. This
        //   build caches none, and it drops every session ticket a server
        //   sends.
        // - `--ssl-allow-beast` and its proxy twin ask that a TLS 1.0 CBC
        //   workaround be left off. The floor here is TLS 1.2, so no
        //   handshake this build completes carries the flaw.
        // - `--ssl-auto-client-cert`, `--ssl-no-revoke`, and
        //   `--ssl-revoke-best-effort`, with their proxy twins, are
        //   Schannel options. curl on this platform accepts each one and
        //   does nothing with it, and this build sends no client
        //   certificate and checks no revocation list either way.
        // - `--false-start`, `--no-npn`, `--egd-file`, `--random-file`,
        //   `--metalink`, and `--ntlm-wb` are flags curl has dropped.
        //   curl 8.21.0 accepts each one and prints a note for two of
        //   them, measured.
        // - `--socks5-basic` names the one SOCKS5 authentication this
        //   build offers, so it names the default.
        // - `--styled-output` asks for a bold header name on a terminal.
        //   zurl writes a response head with no styling, whichever way
        //   the flag is written, and every byte of the head is the same.
        // - `--tcp-fastopen` and `--mptcp` each ask for a kind of socket.
        //   This build opens an ordinary TCP connection, and the bytes on
        //   the wire and the file on disk are the same either way.
        .path_as_is,
        .ftp_pasv,
        .ftp_skip_pasv_ip,
        .disable_eprt,
        .no_sessionid,
        .ssl_allow_beast,
        .proxy_ssl_allow_beast,
        .ssl_auto_client_cert,
        .proxy_ssl_auto_client_cert,
        .ssl_no_revoke,
        .ssl_revoke_best_effort,
        .false_start,
        .no_npn,
        .metalink,
        .ntlm_wb,
        .socks5_basic,
        .styled_output,
        .tcp_fastopen,
        .mptcp,
        => {},
        // The same verdict, and each of these takes a path. The path is
        // not opened and not checked: curl dropped both flags, so a file
        // that is not there is not a fault the user has to hear about.
        .egd_file, .random_file => {},

        // **Refused by name, and the run stops.** The block above holds
        // the rule: a flag that is accepted and dropped leaves the user
        // believing something happened. Each sentence below says what
        // this build does instead, so a reader can decide whether that is
        // enough for them.
        //
        // **The name comes from this table and never from `flag_text`**,
        // for the reason the client certificate block gives: several of
        // these carry a secret in their own argument, and
        // `--tlspassword=hunter2` is one argument.
        .interface_name => refuse(b, "--interface", local_address_reason),
        .local_port => refuse(b, "--local-port", local_address_reason),
        .dns_interface => refuse(b, "--dns-interface", resolver_reason),
        .dns_ipv4_addr => refuse(b, "--dns-ipv4-addr", resolver_reason),
        .dns_ipv6_addr => refuse(b, "--dns-ipv6-addr", resolver_reason),
        .dns_servers => refuse(b, "--dns-servers", resolver_reason),
        .doh_url => refuse(b, "--doh-url", resolver_reason),
        .doh_insecure => refuse(b, "--doh-insecure", doh_reason),
        .doh_cert_status => refuse(b, "--doh-cert-status", doh_reason),
        .unix_socket => refuse(b, "--unix-socket", unix_socket_reason),
        .abstract_unix_socket => refuse(b, "--abstract-unix-socket", unix_socket_reason),
        .ip_tos => refuse(b, "--ip-tos", packet_marking_reason),
        .vlan_priority => refuse(b, "--vlan-priority", packet_marking_reason),
        .ipfs_gateway => refuse(b, "--ipfs-gateway", ipfs_reason),

        .cert_status => refuse(b, "--cert-status", revocation_reason),
        .crlfile => refuse(b, "--crlfile", revocation_reason),
        .proxy_crlfile => refuse(b, "--proxy-crlfile", revocation_reason),
        .pinnedpubkey => refuse(b, "--pinnedpubkey", pinning_reason),
        .proxy_pinnedpubkey => refuse(b, "--proxy-pinnedpubkey", pinning_reason),
        .sigalgs => refuse(b, "--sigalgs", sigalgs_reason),
        .tls13_ciphers => refuse(b, "--tls13-ciphers", ciphers_reason),
        .proxy_tls13_ciphers => refuse(b, "--proxy-tls13-ciphers", ciphers_reason),
        .proxy_ciphers => refuse(b, "--proxy-ciphers", ciphers_reason),
        .tls_earlydata => refuse(b, "--tls-earlydata", session_reason),
        .ssl_sessions => refuse(b, "--ssl-sessions", session_reason),
        .ech => refuse(b, "--ech", ech_reason),
        .engine => refuse(b, "--engine", engine_reason),
        .tls_auth_type => refuse(b, "--tlsauthtype", srp_reason),
        .tls_user => refuse(b, "--tlsuser", srp_reason),
        .tls_password => refuse(b, "--tlspassword", srp_reason),
        .proxy_tls_auth_type => refuse(b, "--proxy-tlsauthtype", srp_reason),
        .proxy_tls_user => refuse(b, "--proxy-tlsuser", srp_reason),
        .proxy_tls_password => refuse(b, "--proxy-tlspassword", srp_reason),
        .opportunistic_ssl => refuse(b, "--ssl", opportunistic_ssl_reason),
        .proxy_client_cert => refuse(b, "--proxy-cert", client_certificate_reason),
        .proxy_client_cert_type => refuse(b, "--proxy-cert-type", client_certificate_reason),
        .proxy_client_key => refuse(b, "--proxy-key", client_certificate_reason),
        .proxy_client_key_type => refuse(b, "--proxy-key-type", client_certificate_reason),
        .proxy_client_key_pass => refuse(b, "--proxy-pass", client_certificate_reason),
        .proxy_tls_v1 => refuse(b, "--proxy-tlsv1", proxy_tls_v1_reason),

        .auth_negotiate => refuse(b, "--negotiate", gssapi_reason),
        .proxy_negotiate => refuse(b, "--proxy-negotiate", gssapi_reason),
        .service_name => refuse(b, "--service-name", gssapi_reason),
        .proxy_service_name => refuse(b, "--proxy-service-name", gssapi_reason),
        .delegation => refuse(b, "--delegation", gssapi_reason),
        .krb => refuse(b, "--krb", gssapi_reason),
        .socks5_gssapi => refuse(b, "--socks5-gssapi", gssapi_reason),
        .socks5_gssapi_nec => refuse(b, "--socks5-gssapi-nec", gssapi_reason),
        .socks5_gssapi_service => refuse(b, "--socks5-gssapi-service", gssapi_reason),
        .auth_ntlm => refuse(b, "--ntlm", ntlm_reason),
        .proxy_ntlm => refuse(b, "--proxy-ntlm", ntlm_reason),
        .aws_sigv4 => refuse(b, "--aws-sigv4", aws_sigv4_reason),

        .http_0_9 => refuse(b, "--http0.9", http_0_9_reason),
        .proxy_http3 => refuse(b, "--proxy-http3", proxy_http3_reason),
        .raw => refuse(b, "--raw", raw_reason),
        .tr_encoding => refuse(b, "--tr-encoding", tr_encoding_reason),
        .ignore_content_length => refuse(b, "--ignore-content-length", content_length_reason),
        .request_target => refuse(b, "--request-target", request_target_reason),
        .alt_svc => refuse(b, "--alt-svc", alt_svc_reason),
        .hsts => refuse(b, "--hsts", hsts_reason),

        .proxy_header => refuse(b, "--proxy-header", proxy_header_reason),
        .proxy_tunnel => refuse(b, "--proxytunnel", proxy_tunnel_reason),
        .proxy_1_0 => refuse(b, "--proxy1.0", proxy_http_version_reason),
        .proxy_http2 => refuse(b, "--proxy-http2", proxy_http_version_reason),
        .preproxy => refuse(b, "--preproxy", preproxy_reason),
        .haproxy_protocol => refuse(b, "--haproxy-protocol", haproxy_reason),
        .haproxy_clientip => refuse(b, "--haproxy-clientip", haproxy_reason),

        .ftp_account => refuse(b, "--ftp-account", ftp_acct_reason),
        .ftp_alternative_to_user => refuse(b, "--ftp-alternative-to-user", ftp_acct_reason),
        .ftp_create_dirs => refuse(b, "--ftp-create-dirs", ftp_upload_reason),
        .ftp_method => refuse(b, "--ftp-method", ftp_method_reason),
        .ftp_port => refuse(b, "--ftp-port", ftp_active_reason),
        .ftp_pret => refuse(b, "--ftp-pret", ftp_pret_reason),
        .ftp_ssl_ccc => refuse(b, "--ftp-ssl-ccc", ftp_ccc_reason),
        .ftp_ssl_ccc_mode => refuse(b, "--ftp-ssl-ccc-mode", ftp_ccc_reason),
        .ftp_ssl_control => refuse(b, "--ftp-ssl-control", ftp_ssl_control_reason),
        .append => refuse(b, "--append", append_reason),
        .quote => refuse(b, "--quote", quote_reason),

        .mail_auth => refuse(b, "--mail-auth", mail_auth_reason),
        .mail_rcpt_allowfails => refuse(b, "--mail-rcpt-allowfails", mail_rcpt_reason),
        .upload_flags => refuse(b, "--upload-flags", upload_flags_reason),

        .telnet_option => refuse(b, "--telnet-option", telnet_option_reason),
        .compressed_ssh => refuse(b, "--compressed-ssh", ssh_compression_reason),
        .ssh_pubkey => refuse(b, "--pubkey", ssh_pubkey_reason),
        .crlf => refuse(b, "--crlf", crlf_reason),
        .xattr => refuse(b, "--xattr", xattr_reason),
        .variable => refuse(b, "--variable", variable_reason),
        .libcurl => refuse(b, "--libcurl", libcurl_reason),
        .manual => refuse(b, "--manual", manual_reason),
    }
}

/// Turns `--tftp-blksize`'s argument into a block size.
///
/// **The value is refused outside the range and never clamped.** A user
/// who asks for a block this build cannot read has to hear it here, before
/// a datagram goes out, because a clamped size is a transfer that ran with
/// a number the user did not choose. RFC 2348 sets the floor at 8, and
/// `zurl_tftp.packet.max_block_size` sets the ceiling, which is what the
/// read buffer of this build holds.
fn parseTftpBlockSize(
    text: []const u8,
    arena: Allocator,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!u16 {
    const size = try parseIntArg(u16, text, arena, flag_text, fault);
    if (size < zurl_tftp.packet.min_block_size or size > zurl_tftp.packet.max_block_size) return fail(
        arena,
        fault,
        error.InvalidNumber,
        "zurl: option '{f}': a tftp block size is {d} to {d}, and '{f}' is outside it",
        .{
            safe.text(flag_text),
            zurl_tftp.packet.min_block_size,
            zurl_tftp.packet.max_block_size,
            safe.text(text),
        },
    );
    return size;
}

/// Why the five client certificate flags are refused.
const client_certificate_reason =
    "this build sends no client certificate, so the transfer would go out with none";

/// Why `--ciphers` is refused.
const ciphers_reason =
    "this build offers one fixed suite list, so a named list would change nothing";

/// Why `--curves` is refused.
const curves_reason =
    "this build offers one fixed curve list, so a named list would change nothing";

/// Why the five trace flags are refused.
const trace_reason =
    "this build has no tap on the wire, so no trace could be written. -v says what it can";

// **One sentence for each flag this build refuses, and each says what the
// build does instead.** A sentence is written here and never built from
// user text, for the reason `refuse` gives: several of these flags carry a
// secret in their own argument.
//
// A reason names the behaviour and not the file that holds it. A user
// reads this on standard error and has to decide whether zurl still suits
// them, which is a question about the transfer and not about the source.

/// Why `--interface` and `--local-port` are refused.
const local_address_reason =
    "this build binds no local address and no local port, so the dial would leave from wherever the kernel chose";

/// Why the four DNS flags and `--doh-url` are refused.
const resolver_reason =
    "the resolver of the platform answers every name here, and it takes no server, no interface, and no source address from a flag";

/// Why `--doh-insecure` and `--doh-cert-status` are refused.
const doh_reason =
    "this build sends no DNS query over HTTPS, so there is no such connection to shape";

/// Why `--unix-socket` and `--abstract-unix-socket` are refused.
const unix_socket_reason =
    "this build dials TCP alone, so a socket path names nothing it can open";

/// Why `--ip-tos` and `--vlan-priority` are refused.
const packet_marking_reason =
    "this build writes no marking on an outgoing packet, so the traffic would carry the ordinary class";

/// Why `--ipfs-gateway` is refused.
const ipfs_reason =
    "this build reads no ipfs:// and no ipns:// url, so no transfer would reach the gateway";

/// Why `--cert-status`, `--crlfile`, and `--proxy-crlfile` are refused.
const revocation_reason =
    "this build checks no certificate revocation, so a revoked certificate would still verify";

/// Why `--pinnedpubkey` and `--proxy-pinnedpubkey` are refused.
const pinning_reason =
    "this build reads back no peer public key, so the pin could not be compared against anything";

/// Why `--sigalgs` is refused.
const sigalgs_reason =
    "this build offers one fixed signature algorithm list, so a named list would change nothing";

/// Why `--tls-earlydata` and `--ssl-sessions` are refused.
const session_reason =
    "this build resumes no TLS session and caches none, so there is nothing to save, load, or send early";

/// Why `--ech` is refused.
const ech_reason =
    "this build sends no Encrypted Client Hello, so the server name would go out in the clear anyway";

/// Why `--engine` is refused.
const engine_reason =
    "the TLS of this build is inside this binary, so there is no engine to choose between";

/// Why the six TLS-SRP flags are refused.
const srp_reason =
    "this build speaks no TLS-SRP, so the handshake would carry no such credential";

/// Why `--ssl` is refused.
const opportunistic_ssl_reason =
    "it carries on in the clear when a server refuses TLS, and the credential goes out anyway. --ssl-reqd stops instead";

/// Why `--proxy-tlsv1` is refused.
const proxy_tls_v1_reason =
    "the floor of this build is TLS 1.2, for a proxy as for an origin, so TLS 1.0 is never offered";

/// Why the nine SPNEGO and Kerberos flags are refused.
const gssapi_reason =
    "this build speaks no SPNEGO and no Kerberos, so it would answer the challenge with nothing";

/// Why `--ntlm` and `--proxy-ntlm` are refused.
const ntlm_reason =
    "this build speaks no NTLM, so it would answer the challenge with nothing";

/// Why `--aws-sigv4` is refused.
const aws_sigv4_reason =
    "this build signs no request, so the server would refuse every one of them";

/// Why `--http0.9` is refused.
const http_0_9_reason =
    "this build reads a status line on every reply, so a body with no head is a fault and not a body";

/// Why `--proxy-http3` is refused.
///
/// **`--http3` and `--http3-only` are real flags now, and this one is
/// not.** The two that are real name the protocol this build speaks to the
/// origin, and `h1.h3Choice` is the route to it. This one names the
/// protocol spoken to a *proxy*, and this build speaks HTTP/1.1 to a proxy
/// and offers no other version, which is what `--proxy1.0` and
/// `--proxy-http2` are refused for as well.
const proxy_http3_reason =
    "this build speaks HTTP/1.1 to a proxy and has no QUIC on that hop, so the proxy would answer in another protocol";

/// Why `--raw` is refused.
///
/// curl's `--raw` turns off both decodings at once: the content coding and
/// the chunked transfer coding. This build can drop the first and cannot
/// drop the second, so the flag would keep half its promise with no sign
/// of which half.
///
/// **Dropping the content coding is already what a plain run does.** With
/// no `--compressed` the request offers nothing, so nothing arrives coded
/// and the octets written out are the peer's own.
const raw_reason =
    "this build cannot write a chunked body out still chunked, and a run without --compressed " ++
    "already writes the peer's own octets";

/// Why `--tr-encoding` is refused.
///
/// **It is not `--compressed`, and the two ask different peers for
/// different things.** Measured against curl 8.21.0 on a loopback
/// listener, `curl --tr-encoding` sends `TE: gzip` and `Connection: TE`,
/// which RFC 9110 section 10.1.4 makes a hop-by-hop request for a
/// *transfer* coding: the next hop may apply it and the hop after that may
/// not. `curl --compressed` sends `Accept-Encoding`, which is end to end
/// and asks the origin about the representation itself. The two travel
/// together happily, and curl sends both when given both.
const tr_encoding_reason =
    "this build decodes no transfer coding but chunked, so a coded body would reach the output " ++
    "still coded; --compressed asks the origin for a compressed representation instead";

/// Why `--ignore-content-length` is refused.
const content_length_reason =
    "the length frames the body here and finds a short one, so dropping it would hide a truncated answer";

/// Why `--request-target` is refused.
const request_target_reason =
    "the request target here is the path of the url, so a second target would name a resource the url does not";

/// Why `--alt-svc` is refused.
const alt_svc_reason =
    "this build reads no Alt-Svc header and keeps no cache, so the file would stay empty and no hop would move";

/// Why `--hsts` is refused.
const hsts_reason =
    "this build reads no Strict-Transport-Security header and keeps no cache, so no http:// url would be upgraded";

/// Why `--proxy-header` is refused.
const proxy_header_reason =
    "the CONNECT head here carries four fixed lines, so a header of your own would not go out";

/// Why `--proxytunnel` is refused.
const proxy_tunnel_reason =
    "a cleartext url reaches a proxy here as an absolute request and never as a CONNECT tunnel";

/// Why `--proxy1.0` and `--proxy-http2` are refused.
const proxy_http_version_reason =
    "this build speaks HTTP/1.1 to a proxy and offers no other version";

/// Why `--preproxy` is refused.
const preproxy_reason =
    "this build dials one proxy and never two, so the first of the pair would be skipped";

/// Why `--haproxy-protocol` and `--haproxy-clientip` are refused.
const haproxy_reason =
    "this build writes no PROXY protocol header, so the server would read the address of this machine";

/// Why `--ftp-account` and `--ftp-alternative-to-user` are refused.
const ftp_acct_reason =
    "this build sends USER and PASS alone, and it has no ACCT, so a server that asks for one is refused by name";

/// Why `--ftp-create-dirs` is refused.
const ftp_upload_reason =
    "this build sends no MKD, and an ftp:// url uploads nothing, so there is no directory to make";

/// Why `--ftp-method` is refused.
const ftp_method_reason =
    "this build sends one CWD for each element of the path, which is curl's own default, and it offers no other way";

/// Why `--ftp-port` is refused.
const ftp_active_reason =
    "this build is passive only. Active mode asks zurl to listen for an inbound connection, and it opens no listener";

/// Why `--ftp-pret` is refused.
const ftp_pret_reason =
    "this build sends no PRET, so a server that needs one would refuse the data connection";

/// Why `--ftp-ssl-ccc` and `--ftp-ssl-ccc-mode` are refused.
const ftp_ccc_reason =
    "this build sends no CCC and never takes TLS back off a control connection";

/// Why `--ftp-ssl-control` is refused.
const ftp_ssl_control_reason =
    "this build sends PBSZ 0 and PROT P, so the data connection is inside TLS and never in the clear";

/// Why `-a`/`--append` is refused.
const append_reason =
    "this build uploads to no protocol that can append, so the flag would overwrite the target instead";

/// Why `-Q`/`--quote` is refused.
const quote_reason =
    "one file lists every command this build can send to a server, and a command from a command line is not on it";

/// Why `--mail-auth` is refused.
const mail_auth_reason =
    "this build writes no AUTH parameter on MAIL FROM, so the original sender would not travel";

/// Why `--mail-rcpt-allowfails` is refused.
const mail_rcpt_reason =
    "one refused recipient ends the transfer here, so the message reaches nobody rather than some of them";

/// Why `--upload-flags` is refused.
const upload_flags_reason =
    "this build sends no imap APPEND, so there is no message to mark seen or answered";

/// Why `-t`/`--telnet-option` is refused.
const telnet_option_reason =
    "this build answers no telnet subnegotiation, so it would agree to send a terminal type and then send none";

/// Why `--compressed-ssh` is refused.
const ssh_compression_reason =
    "this build asks for no ssh compression, so the transfer would go out uncompressed";

/// Why `--pubkey` is refused.
const ssh_pubkey_reason =
    "this build reads the public key out of the private key, so a separate file is never opened";

/// Why `--crlf` is refused.
const crlf_reason =
    "this build sends an upload byte for byte, and a rewrite would change the length it already announced";

/// Why `--xattr` is refused.
const xattr_reason =
    "this build writes no extended file attribute, so the url and the type would not be stored";

/// Why `--variable` is refused.
const variable_reason =
    "this build expands no variable, so nothing on the command line would read the value";

/// Why `--libcurl` is refused.
const libcurl_reason =
    "this build is not libcurl, so the C it wrote would not describe what zurl did";

/// Why `-M`/`--manual` is refused.
const manual_reason =
    "this build carries no manual page. --help lists every flag it accepts and what each one does";

/// Records that `flag` cannot run, with the sentence that says why.
///
/// **`flag` is the long spelling from `flag_table` and never the text the
/// user typed.** A refused flag may carry a secret in its own argument:
/// `--pass=hunter2` is one argument, and a message that echoed it would
/// write the passphrase to standard error. Every caller passes a literal.
///
/// **The first refusal wins.** A user who typed two flags this build
/// cannot honour reads about the first one they wrote, which is where they
/// start reading their own command line. The run stops either way, so the
/// second is never reached.
fn refuse(b: *Builder, flag: []const u8, reason: []const u8) void {
    if (b.unsupported_flag != null) return;
    b.unsupported_flag = .{ .flag = flag, .reason = reason };
}

/// Turns `--create-file-mode`'s argument into a file mode.
///
/// The text is octal, with or without a leading zero, which is how curl
/// reads it and how a person writes one. The value is bounded at 0o7777:
/// nothing above that is a permission bit, and a longer number is far more
/// likely a decimal a user meant as octal.
fn parseFileMode(
    text: []const u8,
    arena: Allocator,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!u32 {
    const mode = std.fmt.parseInt(u32, text, 8) catch return fail(
        arena,
        fault,
        error.InvalidNumber,
        "zurl: option '{f}': '{f}' is not an octal file mode",
        .{ safe.text(flag_text), safe.text(text) },
    );
    if (mode > 0o7777) return fail(
        arena,
        fault,
        error.InvalidNumber,
        "zurl: option '{f}': '{f}' is above the highest file mode, 7777",
        .{ safe.text(flag_text), safe.text(text) },
    );
    return mode;
}

/// How many `--mail-rcpt` entries one transfer may name.
///
/// Each one is its own `RCPT TO` command and its own round trip, so a list
/// of a thousand is a thousand round trips from one command line. curl
/// keeps no bound of its own; this one is far past any real message and it
/// stops an unbounded list arriving from a config file.
pub const max_recipients: usize = 128;

/// Adds one `--mail-rcpt` entry, and refuses a list past
/// `max_recipients`.
fn appendRecipient(
    b: *Builder,
    value: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    if (b.recipients.items.len == max_recipients) return fail(
        b.arena,
        fault,
        error.TooManyRecipients,
        "zurl: --mail-rcpt: more than {d} recipients",
        .{max_recipients},
    );
    try b.recipients.append(b.arena, value);
}

/// How many messages `--mqtt-messages` may ask a subscribe for.
///
/// **This is `zurl_mqtt.Fetcher.max_message_count` written again**, and it
/// is written again on purpose: `src/cli/run.zig` may leave the mqtt
/// package out of a build, and the refusal below must not change when it
/// does. The two numbers meeting is a test in `run.zig`.
pub const max_mqtt_messages: u32 = 100_000;

/// Reads a `--mqtt-messages` count.
///
/// **Zero is refused here and not left to the protocol package.** A
/// subscribe that reads no message is a transfer that connects, says
/// nothing, and exits, which is never what a user meant.
fn readMessageCount(
    b: *Builder,
    value: []const u8,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!u32 {
    const count = try parseIntArg(u32, value, b.arena, flag_text, fault);
    if (count == 0 or count > max_mqtt_messages) return fail(
        b.arena,
        fault,
        error.InvalidNumber,
        "zurl: --mqtt-messages reads at least 1 message and at most {d}",
        .{max_mqtt_messages},
    );
    return count;
}

/// The suffix `-e` reads as "keep the Referer current on each redirect".
const auto_referer_suffix = ";auto";

/// How many `--resolve` and `--connect-to` entries one run may name.
///
/// The list is walked once for each connection, so a long list costs every
/// dial. curl keeps no bound of its own; this one is far past any real
/// command line and it stops an unbounded list arriving from a config
/// file.
pub const max_host_overrides: usize = 64;

/// Adds one `--resolve` or `--connect-to` entry, and refuses a list past
/// `max_host_overrides`.
fn appendOverride(
    b: *Builder,
    entry: Transfer.HostOverride,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    if (b.overrides.items.len == max_host_overrides) return fail(
        b.arena,
        fault,
        error.TooManyHostOverrides,
        "zurl: option '{f}': no more than {d} of these are read",
        .{ safe.text(flag_text), max_host_overrides },
    );
    try b.overrides.append(b.arena, entry);
}

/// Reads one `--resolve` argument: `[+]host:port:address`.
///
/// **Measured against curl 8.21.0.** `--resolve example.invalid:PORT:127.0.0.1`
/// with `http://example.invalid:PORT/x` dialed 127.0.0.1 and sent
/// `Host: example.invalid:PORT`, so the flag moves the dial and leaves the
/// name alone. curl answers a malformed entry with exit 49 and
/// `Could not parse CURLOPT_RESOLVE entry`, and this keeps that code: see
/// `ParseError.InvalidHostOverride`.
///
/// The leading `+` curl allows is accepted and ignored. It asks curl to
/// let the entry time out of its DNS cache, and zurl keeps no cache: the
/// list is read again for every dial of the run.
///
/// A `-` in front removes an entry from curl's cache. There is no cache to
/// remove from here, so such an entry names nothing to dial and is
/// refused rather than read as a host called `-example.com`.
fn parseResolve(
    b: *Builder,
    value: []const u8,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!Transfer.HostOverride {
    var text = value;
    if (std.mem.startsWith(u8, text, "+")) text = text[1..];
    if (std.mem.startsWith(u8, text, "-")) return badOverride(b, value, flag_text, fault);

    // The host may be an IPv6 literal in brackets, which holds colons of
    // its own, so the host ends at the bracket and not at the first colon.
    const host_end = hostEnd(text) orelse return badOverride(b, value, flag_text, fault);
    const host = text[0..host_end];
    if (host.len == 0) return badOverride(b, value, flag_text, fault);
    const rest = text[host_end + 1 ..];

    const colon = std.mem.indexOfScalar(u8, rest, ':') orelse
        return badOverride(b, value, flag_text, fault);
    const port = std.fmt.parseInt(u16, rest[0..colon], 10) catch
        return badOverride(b, value, flag_text, fault);
    // curl takes a list of addresses here and tries each. zurl dials one,
    // so the first name is the one it uses and a second is refused rather
    // than dropped without a word.
    const address = rest[colon + 1 ..];
    if (address.len == 0 or std.mem.indexOfScalar(u8, address, ',') != null)
        return badOverride(b, value, flag_text, fault);

    return .{
        .from_host = unbracket(host),
        .from_port = port,
        // `--resolve` never moves the port. Measured: the dial went to
        // 127.0.0.1 on the very port the url named.
        .to_host = unbracket(address),
        .to_port = port,
    };
}

/// Reads one `--connect-to` argument: `host1:port1:host2:port2`.
///
/// **Measured against curl 8.21.0.** `--connect-to example.invalid:80:127.0.0.1:PORT`
/// with `http://example.invalid:80/y` dialed 127.0.0.1 on PORT and sent
/// `Host: example.invalid`, so this flag moves the dial and leaves the
/// name alone the same way `--resolve` does.
///
/// An empty field means "any" on the left and "keep" on the right, which
/// is curl's own reading: `::127.0.0.1:8080` moves every host and port to
/// that one address.
fn parseConnectTo(
    b: *Builder,
    value: []const u8,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!Transfer.HostOverride {
    var rest = value;
    var fields: [4][]const u8 = undefined;
    for (fields[0..3]) |*field| {
        const end = hostEnd(rest) orelse return badOverride(b, value, flag_text, fault);
        field.* = rest[0..end];
        rest = rest[end + 1 ..];
    }
    fields[3] = rest;
    if (std.mem.indexOfScalar(u8, fields[3], ':') != null)
        return badOverride(b, value, flag_text, fault);

    return .{
        .from_host = unbracket(fields[0]),
        .from_port = try overridePort(b, fields[1], value, flag_text, fault),
        .to_host = unbracket(fields[2]),
        .to_port = try overridePort(b, fields[3], value, flag_text, fault),
    };
}

/// Reads one port field of a `--connect-to` entry. An empty field is null,
/// which reads as "any" on the left and "keep the url's own" on the right.
fn overridePort(
    b: *Builder,
    text: []const u8,
    value: []const u8,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!?u16 {
    if (text.len == 0) return null;
    return std.fmt.parseInt(u16, text, 10) catch badOverride(b, value, flag_text, fault);
}

/// Where the host field of an override entry ends: the index of the colon
/// that closes it, or null when the text carries no colon at all.
///
/// A bracketed IPv6 literal holds colons of its own, so the search starts
/// after the closing bracket. `[::1]:443:...` therefore ends its host at
/// the colon after `]` and not at the first colon inside the address.
fn hostEnd(text: []const u8) ?usize {
    if (std.mem.startsWith(u8, text, "[")) {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return null;
        if (close + 1 >= text.len or text[close + 1] != ':') return null;
        return close + 1;
    }
    return std.mem.indexOfScalar(u8, text, ':');
}

/// Takes the brackets off an IPv6 literal, and leaves every other host as
/// it is.
///
/// `zurl_core.url.parse` hands the engine a bare IPv6 host with no
/// brackets, so an override has to be stored the same way or a url naming
/// `[::1]` would never match an entry naming `[::1]`.
fn unbracket(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']')
        return host[1 .. host.len - 1];
    return host;
}

/// Refuses one malformed `--resolve` or `--connect-to` entry.
fn badOverride(
    b: *Builder,
    value: []const u8,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error) {
    return fail(
        b.arena,
        fault,
        error.InvalidHostOverride,
        "zurl: option '{f}': could not read the entry '{f}'",
        .{ safe.text(flag_text), safe.text(value) },
    );
}

/// Records the version a `--tlsv1.x` flag named, and refuses the pair when
/// a `--tls-max` already on the command line put the ceiling below it.
///
/// **The named version, not the floor this build holds.** `--tlsv1.0`
/// leaves `options.tls_min_version` at TLS 1.2, and this still records TLS
/// 1.0, because the pair curl refuses is the pair the user *wrote*.
/// Measured against curl 8.21.0:
///
/// ```
/// curl --tls-max 1.0 --tlsv1.0 URL   exit 35, the handshake failed
/// curl --tls-max 1.0 --tlsv1.1 URL   exit 2, no socket opened
/// ```
///
/// The order of the two flags decides which sentence prints, and both
/// exit 2. curl writes `Minimum TLS version set higher than max` when the
/// `--tlsv1.x` flag comes last and `--tls-max set lower than minimum
/// accepted version` when `--tls-max` does. This keeps that split, because
/// each flag can only check what the command line has already said.
fn namedFloor(
    b: *Builder,
    named: zurl_core.tls.Version,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    if (b.tls_named_max) |ceiling| {
        if (@intFromEnum(named) > @intFromEnum(ceiling)) return fail(
            b.arena,
            fault,
            error.TlsVersionRangeEmpty,
            "zurl: option '{f}': {s} is above the {s} --tls-max asked for",
            .{ safe.text(flag_text), named.name(), ceiling.name() },
        );
    }
    // The highest named wins, the way the floor itself does, so a lower
    // flag after a higher one cannot walk the pair back into agreement.
    b.tls_named_min = if (b.tls_named_min) |current|
        if (@intFromEnum(named) >= @intFromEnum(current)) named else current
    else
        named;
}

/// Reads one `--proto` or `--proto-redir` list into a set, and turns every
/// fault into a message that names the flag and shows the list.
///
/// The list is untrusted input: it comes from the command line or from a
/// config file, so it reaches standard error through `safe.Text` and never
/// as a raw `{s}`. `zurl_core.redirect.Set.parse` bounds both its length
/// and its entry count, and each bound gets its own sentence, because a
/// user answers "too long" and "nothing enabled" differently.
fn parseProtocols(
    value: []const u8,
    base: zurl_core.redirect.Set,
    arena: Allocator,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!zurl_core.redirect.Set {
    return zurl_core.redirect.Set.parse(value, base) catch |err| switch (err) {
        error.ProtocolListEmpty => fail(
            arena,
            fault,
            error.InvalidProtocolList,
            "zurl: option '{f}': '{f}' leaves no protocol enabled",
            .{ safe.text(flag_text), safe.text(value) },
        ),
        error.ProtocolListTooLong => fail(
            arena,
            fault,
            error.InvalidProtocolList,
            "zurl: option '{f}': the list is longer than {d} bytes",
            .{ safe.text(flag_text), zurl_core.redirect.Set.max_list_bytes },
        ),
        error.ProtocolListTooManyEntries => fail(
            arena,
            fault,
            error.InvalidProtocolList,
            "zurl: option '{f}': the list names more than {d} protocols",
            .{ safe.text(flag_text), zurl_core.redirect.Set.max_entries },
        ),
    };
}

/// Writes `fault`'s message from `fmt`/`args`, then returns `err`. Mirrors
/// `zurl_core.Diagnostics.record`: `return fail(...)` lets every call site
/// report in one line, so no fault path can forget to fill the message.
fn fail(
    arena: Allocator,
    fault: ?*Fault,
    err: ParseError,
    comptime fmt: []const u8,
    args: anytype,
) (ParseError || Allocator.Error) {
    if (fault) |f| f.message = try std.fmt.allocPrint(arena, fmt, args);
    return err;
}

fn parseIntArg(
    comptime T: type,
    text: []const u8,
    arena: Allocator,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!T {
    return std.fmt.parseInt(T, text, 10) catch
        fail(arena, fault, error.InvalidNumber, "zurl: '{f}' is not a valid number for {f}", .{ safe.text(text), safe.text(flag_text) });
}

/// Parses a byte count, accepting the `k`, `M`, and `G` suffixes curl's
/// `--limit-rate` and `--max-filesize` accept. The multiplier is 1024-based,
/// matching curl's own `GetSizeParameter`.
fn parseSize(
    text: []const u8,
    arena: Allocator,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!u64 {
    if (text.len == 0)
        return fail(arena, fault, error.InvalidNumber, "zurl: {f} needs a size", .{safe.text(flag_text)});

    var digits = text;
    var multiplier: u64 = 1;
    const last = text[text.len - 1];
    if (!std.ascii.isDigit(last)) {
        digits = text[0 .. text.len - 1];
        multiplier = switch (last) {
            'k', 'K' => 1024,
            'm', 'M' => 1024 * 1024,
            'g', 'G' => 1024 * 1024 * 1024,
            else => return fail(
                arena,
                fault,
                error.InvalidSizeSuffix,
                "zurl: '{f}' is not a size suffix zurl knows, in {f} {f}",
                .{ safe.text(text[text.len - 1 ..]), safe.text(flag_text), safe.text(text) },
            ),
        };
    }

    const n = std.fmt.parseInt(u64, digits, 10) catch
        return fail(arena, fault, error.InvalidNumber, "zurl: '{f}' is not a valid size for {f}", .{ safe.text(text), safe.text(flag_text) });
    return std.math.mul(u64, n, multiplier) catch
        fail(arena, fault, error.InvalidNumber, "zurl: '{f}' overflows for {f}", .{ safe.text(text), safe.text(flag_text) });
}

/// The fastest rate `--rate` accepts, in transfers each second.
///
/// curl's own ceiling, measured against curl 8.21.0: `--rate 1000/s` runs
/// and `--rate 1001/s` prints `option --rate: too large number` and exits
/// 2. The same ceiling holds under every unit: `60000/m` runs and
/// `60001/m` does not.
const rate_max_per_second: u64 = 1000;

/// Parses `--rate`'s argument and returns the wait between the start of
/// one transfer and the start of the next, in milliseconds.
///
/// **The grammar is a count, then an optional unit.** Measured against
/// curl 8.21.0:
///
/// ```
/// --rate 2/s      two transfers each second
/// --rate 10/m     ten each minute
/// --rate 1/h      one each hour
/// --rate 1/d      one each day
/// --rate 3        three each hour: an argument with no unit is hours
/// --rate 0        exit 2, `option --rate: is badly used here`
/// --rate 2/x      exit 2, `unsupported --rate unit`
/// --rate 5/S      exit 2: the unit letter is lower case only
/// --rate abc      exit 2, `expected a proper numerical parameter`
/// --rate -1       exit 2, the same sentence
/// ```
///
/// A rate of zero is refused rather than read as "no bound", because a
/// user who wrote it asked for something that has no answer.
fn parseRate(
    text: []const u8,
    arena: Allocator,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!u64 {
    const cut = std.mem.indexOfScalar(u8, text, '/') orelse text.len;
    const digits = text[0..cut];
    // The default unit is the hour, which is what curl's own manual says
    // and what `--rate 3` measured as.
    const unit_seconds: u64 = if (cut == text.len) 3600 else switch (text.len - cut) {
        2 => switch (text[cut + 1]) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            else => return fail(
                arena,
                fault,
                error.InvalidNumber,
                "zurl: '{f}' is not a --rate unit zurl knows, in {f} {f}. Use s, m, h, or d.",
                .{ safe.text(text[cut + 1 ..]), safe.text(flag_text), safe.text(text) },
            ),
        },
        else => return fail(
            arena,
            fault,
            error.InvalidNumber,
            "zurl: '{f}' is not a --rate unit zurl knows, in {f} {f}. Use s, m, h, or d.",
            .{ safe.text(text[@min(cut + 1, text.len)..]), safe.text(flag_text), safe.text(text) },
        ),
    };

    const count = std.fmt.parseInt(u64, digits, 10) catch return fail(
        arena,
        fault,
        error.InvalidNumber,
        "zurl: '{f}' is not a valid number for {f}",
        .{ safe.text(text), safe.text(flag_text) },
    );
    if (count == 0) return fail(
        arena,
        fault,
        error.InvalidNumber,
        "zurl: {f} needs a count above zero",
        .{safe.text(flag_text)},
    );
    // Checked as a rate, so the ceiling reads the same under every unit,
    // the way curl's does. The multiply cannot overflow: `count` is at
    // most the whole 64 bit range and this compares before it scales.
    const ceiling = std.math.mul(u64, rate_max_per_second, unit_seconds) catch std.math.maxInt(u64);
    if (count > ceiling) return fail(
        arena,
        fault,
        error.InvalidNumber,
        "zurl: {f} {f} is faster than {d} transfers each second",
        .{ safe.text(flag_text), safe.text(text), rate_max_per_second },
    );

    // The wait is the unit divided by the count. `count` is at least one
    // and at most `ceiling`, so this never divides by zero and the result
    // is at least one millisecond for every rate the ceiling allows.
    return @max(1, (unit_seconds * std.time.ms_per_s) / count);
}

/// Parses `--connect-timeout`'s argument, a count of seconds that may carry
/// a fraction, and returns it in milliseconds: the unit
/// `Transfer.Options.connect_timeout` is built from.
fn parseTimeoutMs(
    text: []const u8,
    arena: Allocator,
    flag_text: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!i64 {
    const seconds = std.fmt.parseFloat(f64, text) catch
        return fail(arena, fault, error.InvalidNumber, "zurl: '{f}' is not a valid time for {f}", .{ safe.text(text), safe.text(flag_text) });
    if (!std.math.isFinite(seconds) or seconds < 0)
        return fail(arena, fault, error.InvalidNumber, "zurl: '{f}' is not a valid time for {f}", .{ safe.text(text), safe.text(flag_text) });

    const ms = seconds * std.time.ms_per_s;
    if (ms > @as(f64, @floatFromInt(std.math.maxInt(i64))))
        return fail(arena, fault, error.InvalidNumber, "zurl: '{f}' is too large for {f}", .{ safe.text(text), safe.text(flag_text) });
    return @intFromFloat(@round(ms));
}

/// Returns the `BodyTarget` an `-o` argument names.
///
/// `path` spelled exactly `-` names standard output, matching curl. Any
/// other spelling, including one that names the same file by a longer
/// path such as `./-`, is an explicit file, and this function never
/// rewrites it: `path` is returned unchanged, so a caller who genuinely
/// wants a file named `-` still gets one by typing `./-`.
fn targetForOutputPath(path: []const u8) BodyTarget {
    if (std.mem.eql(u8, path, "-")) return .stdout;
    return .{ .file = path };
}

/// Parses a `-H` argument. curl's own header syntax needs a colon; a
/// header with none reaches here as a bare name with an empty value rather
/// than a parse error, since a nonsense header is the engine's problem to
/// refuse, not this parser's.
fn parseHeader(text: []const u8) std.http.Header {
    if (std.mem.indexOfScalar(u8, text, ':')) |idx| {
        return .{
            .name = std.mem.trim(u8, text[0..idx], " \t"),
            .value = std.mem.trim(u8, text[idx + 1 ..], " \t"),
        };
    }
    return .{ .name = std.mem.trim(u8, text, " \t"), .value = "" };
}

/// Splits `-u`'s argument on the FIRST colon. A password may hold one; a
/// user name may not. With no colon, `text` is the user name and the
/// password is empty, matching curl.
fn parseUser(text: []const u8) zurl_core.auth.Credentials {
    if (std.mem.indexOfScalar(u8, text, ':')) |idx|
        return .{ .user = text[0..idx], .password = text[idx + 1 ..] };
    return .{ .user = text, .password = "" };
}

/// Reads `name` from `env`, treating an empty value as unset.
///
/// An environment variable set to the empty string names no file and no
/// directory. Reading it as a path of `""` would send an empty string all
/// the way to the trust loader instead of leaving the field `null` the way
/// an unset variable does, so `envPath` folds the empty case into `null`
/// here, once, rather than in every caller.
fn envPath(env: *std.process.Environ.Map, name: []const u8) ?[]const u8 {
    const value = env.get(name) orelse return null;
    return if (value.len == 0) null else value;
}

/// The first of `names` that `env` sets to a non-empty value, or null.
///
/// The lists in `zurl_core.proxy.Env` put the lower case spelling first,
/// because curl prefers it where both are set. Measured against curl
/// 8.21.0 with both cases pointing at two different ports.
fn envFirst(env: *std.process.Environ.Map, names: []const []const u8) ?[]const u8 {
    for (names) |name| {
        if (envPath(env, name)) |value| return value;
    }
    return null;
}

/// Fills `options.proxy`, `options.proxy_tls`, and `options.no_proxy` from
/// the flags and the environment.
///
/// **The flags outrank the environment, and each of the two proxy fields is
/// answered on its own.** curl reads `http_proxy` for a cleartext target and
/// `https_proxy` for a TLS one, with `all_proxy` behind both, so a shell
/// that sets one and not the other still reaches the origin directly for the
/// other scheme. `zurl_core.proxy.Env` names the variables and holds the
/// measurement, `HTTP_PROXY` being deliberately absent.
///
/// **`-x ""` turns proxying off, the environment included.** Measured
/// against curl 8.21.0: with `http_proxy` set, `-x ""` sent the request
/// straight to the origin. An empty argument is therefore not "no flag": it
/// is a flag that says no proxy.
///
/// `--noproxy` outranks `no_proxy` even when it is empty, for the same
/// reason. Measured: `--noproxy ""` beside a `no_proxy` that would have
/// matched still sent the request through the proxy.
///
/// A proxy url that does not read stops the run. curl answers a bad scheme
/// with exit 7 and a bad port with exit 5, and `src/main.zig` gives these
/// two members those codes.
fn resolveProxy(
    b: *Builder,
    env: *std.process.Environ.Map,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    b.options.no_proxy = b.noproxy_arg orelse
        envFirst(env, &zurl_core.proxy.Env.no) orelse "";

    if (b.proxy_arg) |text| {
        // `-x ""` says no proxy at all, and it says it louder than any
        // environment variable.
        if (text.len == 0) return;
        const spec = try parseProxyArg(text, b.proxy_kind, b.arena, fault);
        b.options.proxy = spec;
        b.options.proxy_tls = spec;
        // An explicit proxy covers every scheme, so a protocol that cannot
        // carry one refuses rather than dial direct. See
        // `Transfer.Options.proxy_every_protocol`.
        b.options.proxy_every_protocol = true;
        return;
    }

    // No flag, so the environment answers, one scheme at a time.
    const fallback = envFirst(env, &zurl_core.proxy.Env.all);
    // `all_proxy` covers every scheme the way `-x` does, and
    // `http_proxy` and `https_proxy` each answer for one HTTP target.
    if (fallback != null) b.options.proxy_every_protocol = true;
    if (envFirst(env, &zurl_core.proxy.Env.http) orelse fallback) |text| {
        b.options.proxy = try parseProxyArg(text, null, b.arena, fault);
    }
    if (envFirst(env, &zurl_core.proxy.Env.https) orelse fallback) |text| {
        b.options.proxy_tls = try parseProxyArg(text, null, b.arena, fault);
    }
}

/// Reads one proxy url, and names the flag in `fault` when it does not
/// read.
fn parseProxyArg(
    text: []const u8,
    kind: ?zurl_core.proxy.Kind,
    arena: Allocator,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!zurl_core.proxy.Spec {
    const parsed = if (kind) |k|
        zurl_core.proxy.parseAs(text, k)
    else
        zurl_core.proxy.parse(text);
    return parsed catch |err| switch (err) {
        // **The sentence quotes nothing.** A proxy url can carry a
        // credential, and a message is printed, logged, and pasted into a
        // bug report. So it names the fault and the flag family, and never
        // the text.
        error.UnsupportedProxyScheme => fail(
            arena,
            fault,
            error.UnsupportedProxyScheme,
            "zurl: the proxy names a scheme zurl does not speak",
            .{},
        ),
        error.InvalidProxy => fail(
            arena,
            fault,
            error.InvalidProxy,
            "zurl: the proxy is not a usable host and port",
            .{},
        ),
    };
}

// --- Config files: -K/--config and the default .curlrc ---
//
// `zurl_core.config.Iterator` parses one config file's text into a stream
// of `Option{ name, value }` pairs; this section owns nothing about that
// format. Its own job is smaller: turn those pairs into the argv-shaped
// tokens `parse`'s tokeniser already knows how to read (`expandConfig`),
// and, in `parseWithConfigFiles`, read the files themselves. That function
// is the only place in this file that touches a filesystem.

/// The bound on one config file's total size. Config files are short,
/// hand-written option lists; 1 MiB holds many thousands of lines, far
/// more than any real one, while still bounding the worst case for a file
/// this package does not trust.
pub const max_config_file_bytes: usize = 1 * 1024 * 1024;

/// The bound on how many options one config file may name.
/// `max_config_file_bytes` already bounds the read, but a file packed with
/// short, near-blank lines could still name an unreasonable number of
/// options within that size; this bounds the token list `expandConfig`
/// builds directly, so the loop that builds it is bounded on its own terms
/// too.
const max_config_options: usize = 4096;

/// The bound on one option's decoded quoted value. Generous for any
/// header or url a config file plausibly carries; a value longer than this
/// is malformed or hostile input, not a real use, and is refused rather
/// than silently truncated.
const max_config_value_bytes: usize = 8192;

/// True when `argv`'s first element is `-q` or `--disable`.
///
/// `man curl`, under `-q, --disable`: "If used as the first parameter on
/// the command line, the curlrc config file is not read or used." Later
/// than first, or absent, the default config file is read as usual; this
/// function only ever inspects `argv[0]`, matching that rule literally
/// rather than treating `-q` as an ordinary flag that can appear anywhere
/// and still have this effect.
pub fn defaultConfigDisabled(argv: []const []const u8) bool {
    return argv.len > 0 and
        (std.mem.eql(u8, argv[0], "-q") or std.mem.eql(u8, argv[0], "--disable"));
}

/// What a raw, unexpanded command line says about config files, gathered
/// before any file is read.
const ConfigScan = struct {
    /// Every `-K`/`--config` path, in the order `argv` names them. `man
    /// curl`, under `-K, --config`: "--config can be used several times in
    /// a command line", so this is a list, not a single optional path.
    paths: []const []const u8,
    /// True when `argv` disables the default `.curlrc` read.
    disable_default: bool,
};

/// Walks `argv` with `parse`'s own tokeniser, so a value belonging to some
/// other flag is never mistaken for `-K`/`--config`'s own argument, and
/// returns the config files it names.
///
/// Any usage fault `walk` raises here fires again, byte-for-byte, when
/// `parse` walks the final, expanded token list built from this scan's
/// findings, so a fault raised in this pass is still reported to the
/// caller: there is no reason to read a config file for a command line
/// that is already known to be invalid.
fn scanConfigPaths(
    arena: Allocator,
    argv: []const []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!ConfigScan {
    var b: Builder = .{ .arena = arena };
    try walk(&b, argv, fault);
    return .{
        .paths = try b.config_paths.toOwnedSlice(arena),
        .disable_default = defaultConfigDisabled(argv),
    };
}

/// True for the option names `-K`/`--config` parse to: `"config"` for the
/// long form, `"K"` for the short form. `zurl_core.config.Iterator`
/// already strips any leading dashes, so both `-K` and `--config` and even
/// undashed `config` in a config file reach here as one of these two bare
/// names.
fn isConfigOptionName(name: []const u8) bool {
    return std.mem.eql(u8, name, "config") or std.mem.eql(u8, name, "K");
}

/// Turns a config file's option name into the flag token `parse`'s own
/// tokeniser expects: a single letter becomes a short flag (`-s`), the way
/// curl accepts a bare short-option letter in a config file, and anything
/// longer becomes a long flag (`--silent`).
fn optionFlagToken(arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
    return if (name.len == 1)
        std.fmt.allocPrint(arena, "-{s}", .{name})
    else
        std.fmt.allocPrint(arena, "--{s}", .{name});
}

/// The token list `parseWithConfigFiles` builds, with one source for each
/// token.
///
/// The two lists move together and are never appended to apart, so a
/// caller cannot leave a token with the wrong file and line beside it.
const TokenList = struct {
    tokens: std.ArrayList([]const u8) = .empty,
    sources: std.ArrayList(?Source) = .empty,

    fn append(l: *TokenList, arena: Allocator, token: []const u8, source: ?Source) Allocator.Error!void {
        try l.tokens.append(arena, token);
        try l.sources.append(arena, source);
    }

    fn appendArgv(l: *TokenList, arena: Allocator, argv: []const []const u8) Allocator.Error!void {
        for (argv) |token| try l.append(arena, token, null);
    }
};

/// How a config file's own faults are treated.
///
/// **This is curl's rule, measured.** A `-K`/`--config` file the user
/// named is a command line: `curl -K bad.conf URL` exits 2 for an unknown
/// option in it. The default `~/.curlrc` is advice: `curl URL` with the
/// same line in `~/.curlrc` printed a warning, fetched the url, and
/// exited 0. The same held for a missing parameter, a bad numeric
/// parameter, and a `--cacert` naming a file that does not exist.
///
/// zurl treating the default file as fatal made every zurl run fail on any
/// account whose `~/.curlrc` held one line zurl does not implement, such
/// as `compressed`.
const ConfigKind = enum {
    /// `-K`/`--config`. A fault is a usage fault and the run stops.
    named,
    /// The default `~/.curlrc`. A fault is a warning, the option is
    /// dropped, and the rest of the file still applies.
    default,
};

/// Turns one config file's already-read text into the argv-shaped tokens
/// `parse` would see for the same options typed on the command line, in
/// order, and appends them to `out` with `file` and each option's own line
/// beside them.
///
/// This function does no I/O: `parseWithConfigFiles` reads the file and
/// hands this function the bytes. It also refuses to expand a nested
/// `-K`/`--config`: honouring one would let a file pull in an unbounded
/// chain of further files, an untrusted-input hazard that
/// `max_config_file_bytes` and `max_config_options` close for one file but
/// cannot close across an open-ended chain of them.
///
/// `kind` decides what a fault in the file costs. See `ConfigKind`. A
/// `default` file's faults land in `warnings`, one arena-owned sentence
/// each, and the run goes on. A `named` file's faults fill `fault` and
/// stop the parse.
///
/// `env` is only for `optionIsUsable`, which parses one option of a
/// `default` file on its own to learn whether this build can act on it.
fn expandConfig(
    arena: Allocator,
    file: []const u8,
    text: []const u8,
    kind: ConfigKind,
    env: *std.process.Environ.Map,
    out: *TokenList,
    warnings: *std.ArrayList([]const u8),
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    var it: zurl_core.config.Iterator = .init(text);
    var value_buf: [max_config_value_bytes]u8 = undefined;

    var seen: usize = 0;
    while (true) {
        const opt = it.next(&value_buf) catch |err| {
            // The iterator has already stepped past the line it refused,
            // so a `default` file reads on from the next line.
            const at: Source = .{ .file = file, .line = it.line -| 1, .advisory = kind == .default };
            const message = switch (err) {
                error.UnterminatedQuote => "zurl: a config file has a quoted value with no closing quote",
                error.NoSpaceLeft => std.fmt.comptimePrint(
                    "zurl: a config file has a quoted value longer than {d} bytes",
                    .{max_config_value_bytes},
                ),
                error.OptionNameTooLong => std.fmt.comptimePrint(
                    "zurl: a config file has an option name longer than {d} bytes",
                    .{zurl_core.config.max_option_name_bytes},
                ),
            };
            if (kind == .default) {
                try warnings.append(arena, try prefixSource(arena, at, message));
                seen += 1;
                continue;
            }
            if (fault) |f| {
                f.source = at;
                f.message = try prefixSource(arena, at, message);
            }
            return error.ConfigFileMalformed;
        } orelse break;

        const at: Source = .{ .file = file, .line = opt.line, .advisory = kind == .default };

        // Counted after the read, so a file that names exactly
        // `max_config_options` options is accepted and one that names one
        // more is refused. Counting before the read refused both.
        if (seen >= max_config_options) {
            // A file-level bound, not an option-level one. There is no one
            // option to drop, so this stops reading the file whichever
            // kind it is, and says so.
            const message = try std.fmt.allocPrint(
                arena,
                "zurl: a config file names more than {d} options",
                .{max_config_options},
            );
            if (kind == .default) {
                try warnings.append(arena, try prefixSource(arena, at, message));
                return;
            }
            if (fault) |f| {
                f.source = at;
                f.message = try prefixSource(arena, at, message);
            }
            return error.ConfigFileTooManyOptions;
        }
        seen += 1;

        if (isConfigOptionName(opt.name)) {
            const message = try std.fmt.allocPrint(
                arena,
                "zurl: a config file cannot itself use '{f}' to name another config file",
                .{safe.text(opt.name)},
            );
            if (kind == .default) {
                try warnings.append(arena, try prefixSource(arena, at, message));
                continue;
            }
            if (fault) |f| {
                f.source = at;
                f.message = try prefixSource(arena, at, message);
            }
            return error.ConfigFileNested;
        }

        const flag = try optionFlagToken(arena, opt.name);
        // `opt.value` may borrow `value_buf`, which the next `it.next`
        // call overwrites: copy into the arena before continuing.
        const value: ?[]const u8 = if (opt.value) |v| try arena.dupe(u8, v) else null;

        if (kind == .default and !try optionIsUsable(arena, env, flag, value, at, warnings)) continue;

        try out.append(arena, flag, at);
        if (value) |v| try out.append(arena, v, at);
    }
}

/// Whether this build can act on one option of the default config file,
/// and, when it cannot, records the reason as a warning.
///
/// The check is a real parse of that one option, so it agrees with the
/// parse that runs later by construction: an unknown flag, a missing
/// argument, a number that does not parse, and a method this build cannot
/// send all answer false, and each one keeps the sentence the real parser
/// wrote for it. A second table of "options zurl accepts" would drift.
fn optionIsUsable(
    arena: Allocator,
    env: *std.process.Environ.Map,
    flag: []const u8,
    value: ?[]const u8,
    at: Source,
    warnings: *std.ArrayList([]const u8),
) Allocator.Error!bool {
    var probe: Fault = .{};
    const tokens: []const []const u8 = if (value) |v| &.{ flag, v } else &.{flag};
    _ = parse(arena, tokens, env, &probe) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        else => {
            const message = if (probe.message.len > 0)
                probe.message
            else
                "zurl: a config file names an option this build cannot use";
            try warnings.append(arena, try prefixSource(arena, at, message));
            return false;
        },
    };
    return true;
}

/// Reads the file `-K`/`--config` names. Any failure, including a missing
/// file, is a usage error naming `path`: unlike the default config file,
/// the user asked for this one specifically.
fn readNamedConfig(
    arena: Allocator,
    io: Io,
    path: []const u8,
    fault: ?*Fault,
) (ParseError || Allocator.Error)![]const u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_config_file_bytes)) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.StreamTooLong => return fail(
            arena,
            fault,
            error.ConfigFileTooLarge,
            "zurl: --config: '{f}' is larger than the {d} byte limit",
            .{ safe.text(path), max_config_file_bytes },
        ),
        else => return fail(
            arena,
            fault,
            error.ConfigFileUnreadable,
            "zurl: --config: cannot read '{f}'",
            .{safe.text(path)},
        ),
    };
}

/// Finds and reads curl's own default config file, or returns `null` when
/// none of the candidate paths can be read: a missing default config file
/// is normal, not a fault, so this function reports it the same way it
/// reports every other reason a candidate did not pan out.
///
/// `man curl`, under `-K, --config`: "curl ... checks for a default config
/// file and uses it if found, even when --config is used. The default
/// config file is checked for in the following places in this order: 1)
/// "$CURL_HOME/.curlrc" 2) "$XDG_CONFIG_HOME/curlrc" ... 3)
/// "$HOME/.curlrc" ...". This function implements those three candidates,
/// in that order, stopping at the first one it can read. curl's remaining
/// candidates are Windows-only paths, or a `getpwuid` lookup for a user
/// with no `HOME` set; the task report explains why zurl does not add
/// either yet.
fn readDefaultConfig(
    arena: Allocator,
    io: Io,
    env: *std.process.Environ.Map,
) Allocator.Error!?DefaultConfig {
    var candidates: std.ArrayList([]const u8) = .empty;
    if (env.get("CURL_HOME")) |home|
        try candidates.append(arena, try std.fmt.allocPrint(arena, "{s}/.curlrc", .{home}));
    if (env.get("XDG_CONFIG_HOME")) |xdg|
        try candidates.append(arena, try std.fmt.allocPrint(arena, "{s}/curlrc", .{xdg}));
    if (env.get("HOME")) |home|
        try candidates.append(arena, try std.fmt.allocPrint(arena, "{s}/.curlrc", .{home}));

    for (candidates.items) |path| {
        const text = Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_config_file_bytes)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
        return .{ .path = path, .text = text };
    }
    return null;
}

/// The default config file that `readDefaultConfig` found. The path comes
/// back beside the bytes, because a warning about a line in that file
/// must name which of the three candidate files it was.
const DefaultConfig = struct {
    path: []const u8,
    text: []const u8,
};

/// Reads `argv`'s `-K`/`--config` files and curl's own default config
/// file, then parses the result as if every option those files name had
/// been typed before `argv` on the command line. `argv` itself can still
/// override anything a file set, because a later flag wins over an
/// earlier one in `parse`'s single pass over the concatenated tokens.
///
/// This is the only function in this file that touches a filesystem.
/// `parse` stays pure: every path this function reads is turned into
/// argv-shaped tokens, through `expandConfig`, before `parse` ever sees
/// them. The one exception is `--cacert`, which this function checks for
/// existence, through `checkCacert`, after `parse` has already built the
/// `Plan`.
pub fn parseWithConfigFiles(
    arena: Allocator,
    io: Io,
    argv: []const []const u8,
    env: *std.process.Environ.Map,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!Plan {
    const scan = try scanConfigPaths(arena, argv, fault);

    var list: TokenList = .{};
    var warnings: std.ArrayList([]const u8) = .empty;

    if (!scan.disable_default) {
        if (try readDefaultConfig(arena, io, env)) |found|
            try expandConfig(arena, found.path, found.text, .default, env, &list, &warnings, fault);
    }

    for (scan.paths) |path| {
        const text = try readNamedConfig(arena, io, path, fault);
        try expandConfig(arena, path, text, .named, env, &list, &warnings, fault);
    }

    try list.appendArgv(arena, argv);
    var parsed = try parseAttributed(
        arena,
        try list.tokens.toOwnedSlice(arena),
        try list.sources.toOwnedSlice(arena),
        env,
        fault,
    );

    if (parsed.plan.options.ca.cacert) |path| {
        checkCacert(io, path, arena, fault) catch |err| {
            // Raised after the parse, so it names its own source rather
            // than take one from the token the parse stopped on.
            const source = parsed.cacert_source orelse return err;
            if (!source.advisory) {
                try attributeFault(arena, fault, source);
                return err;
            }
            // The default config file is advice. Measured: a `~/.curlrc`
            // naming a `cacert` that does not exist made curl 8.21.0 warn
            // and run the transfer anyway. The flag is dropped, so the
            // trust roots fall back to the ones this build would have used
            // with no flag at all, rather than fail the handshake later
            // over a file the user never typed.
            const sentence = if (fault) |f| f.message else "";
            try warnings.append(arena, try prefixSource(arena, source, if (sentence.len > 0)
                sentence
            else
                "zurl: --cacert names a file that does not exist"));
            if (fault) |f| f.* = .{};
            parsed.plan.options.ca.cacert = null;
        };
    }

    // The parse earns sentences of its own, such as the one `-r` writes
    // for a range holding a character that is not a digit. They join the
    // config file's, after them, so the list reads in the order the run
    // learned each one.
    try warnings.appendSlice(arena, parsed.plan.warnings);
    parsed.plan.warnings = try warnings.toOwnedSlice(arena);
    return parsed.plan;
}

/// Confirms `--cacert`'s path exists, matching curl's own eager check.
///
/// A real curl 8.21.0 refuses a missing `--cacert` before any transfer:
///
/// ```
/// $ curl --cacert /nonexistent/ca.pem https://example.com/
/// curl: The file '/nonexistent/ca.pem' provided to --cacert does not exist
/// curl: option --cacert: is badly used here
/// ```
///
/// The check is existence only, the same as curl's own: a path that
/// exists but cannot be read, or names a directory instead of a file,
/// passes here. curl exits 77 for either of those, not 2, which a real
/// run confirms: `--cacert` pointed at a directory, and `--cacert` pointed
/// at a file with every permission bit cleared, both reach the TLS setup
/// and fail there. `Client.ensureCaBundle` reports that failure as
/// `error.CaCertBadFile`, curl's 77.
///
/// `--capath` gets no matching check. A real curl run of `--capath
/// /nonexistent` reaches the TLS handshake and fails there, as curl's 60,
/// rather than being refused at parse time the way `--cacert` is. curl
/// checks the file `--cacert` names because loading one certificate file
/// is cheap enough to do eagerly. `--capath` names a directory whose
/// contents curl does not enumerate until the handshake actually needs
/// them.
fn checkCacert(
    io: Io,
    path: []const u8,
    arena: Allocator,
    fault: ?*Fault,
) (ParseError || Allocator.Error)!void {
    Io.Dir.cwd().access(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return fail(
            arena,
            fault,
            error.CacertMissing,
            "zurl: The file '{f}' provided to --cacert does not exist",
            .{safe.text(path)},
        ),
        // Every other access fault, a permission denied included, is not
        // curl's eager check: it reaches the real load instead, which
        // reports it as curl's 77.
        else => {},
    };
}

const testing = std.testing;

fn testArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

fn testEnv() std.process.Environ.Map {
    return .init(testing.allocator);
}

test "a bare url is the only url, and every option keeps its default except redirects, which the CLI does not follow" {
    // `Transfer.Options{}` follows by default: `fix` depends on that
    // library default. curl's own command-line default is the opposite,
    // no `-L` means no redirect is followed, so a bare CLI invocation must
    // differ from `Transfer.Options{}` in exactly this one field. Before
    // this fix, `-L` was a documented no-op and this test asserted full
    // equality with `Transfer.Options{}`, which was true by coincidence:
    // the CLI followed by default too. That assertion is genuinely false
    // now, on purpose.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{"http://example.com"}, &env, null);

    try testing.expectEqual(@as(usize, 1), plan.urls.len);
    try testing.expectEqualStrings("http://example.com", plan.urls[0]);

    var want = Transfer.Options{};
    want.redirects = .unfollowed;
    try testing.expectEqualDeep(want, plan.options);
    try testing.expectEqual(false, plan.silent);
    try testing.expectEqual(false, plan.show_error);
    try testing.expectEqual(false, plan.parallel);
    try testing.expectEqual(@as(?[]const u8, null), plan.write_out);
}

test "-X names the method" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-X", "DELETE", "http://x" }, &env, null);
    try testing.expectEqual(std.http.Method.DELETE, plan.options.method);

    const plan2 = try parse(arena.allocator(), &.{ "--request", "HEAD", "http://x" }, &env, null);
    try testing.expectEqual(std.http.Method.HEAD, plan2.options.method);
}

test "a body-bearing method is accepted, and carries no body of its own" {
    // **This test replaces a refusal that is now false.** `-X POST` used
    // to exit 2 with "needs a request body, and this build cannot send one
    // yet". The build sends one now, and `-X POST` on its own still asks
    // for no body at all.
    //
    // Measured against curl 8.21.0: `curl -X POST URL` sends `POST /x
    // HTTP/1.1` with no `Content-Length` and no body, and the peer answers
    // it.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-X", "POST", "http://x" }, &env, null);
    try testing.expectEqual(std.http.Method.POST, plan.options.method);
    try testing.expectEqual(@as(usize, 0), plan.request_body.data.len);
    try testing.expectEqual(@as(?[]const u8, null), plan.request_body.upload);
    // No `-d`, so no content type is implied either.
    try testing.expectEqual(@as(usize, 0), plan.options.headers.len);
}

test "the method each body flag chooses, and the ones -X and -I outrank" {
    // Every row measured against curl 8.21.0 on a loopback listener. See
    // `resolveRequestBody` for the captured request lines.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const Case = struct { argv: []const []const u8, method: std.http.Method };
    const cases = [_]Case{
        .{ .argv = &.{ "-d", "a=1", "http://x" }, .method = .POST },
        .{ .argv = &.{ "--json", "{}", "http://x" }, .method = .POST },
        .{ .argv = &.{ "--data-urlencode", "a=1", "http://x" }, .method = .POST },
        .{ .argv = &.{ "-T", "f", "http://x" }, .method = .PUT },
        .{ .argv = &.{ "-I", "http://x" }, .method = .HEAD },
        .{ .argv = &.{ "-G", "-d", "a=1", "http://x" }, .method = .GET },
        .{ .argv = &.{ "-X", "GET", "-d", "a=1", "http://x" }, .method = .GET },
        .{ .argv = &.{ "-X", "DELETE", "-d", "a=1", "http://x" }, .method = .DELETE },
        .{ .argv = &.{ "-X", "POST", "-I", "http://x" }, .method = .POST },
        .{ .argv = &.{ "-I", "-G", "http://x" }, .method = .HEAD },
        .{ .argv = &.{"http://x"}, .method = .GET },
        // A form is a `POST`, `-X` outranks it, and `-G` does not move it.
        // All three measured against curl 8.21.0.
        .{ .argv = &.{ "-F", "a=1", "http://x" }, .method = .POST },
        .{ .argv = &.{ "--form-string", "a=1", "http://x" }, .method = .POST },
        .{ .argv = &.{ "-X", "PUT", "-F", "a=1", "http://x" }, .method = .PUT },
        .{ .argv = &.{ "-F", "a=1", "-G", "http://x" }, .method = .POST },
    };

    for (cases) |case| {
        const plan = try parse(a, case.argv, &env, null);
        try testing.expectEqual(case.method, plan.options.method);
    }
}

test "two flags that each name a method are refused, the way curl refuses them" {
    // curl 8.21.0 answers each of these with exit 2 and `You can only
    // select one HTTP request method!`, before any socket. `-X` and `-G`
    // are not in the list: measured, both run.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const refused = [_][]const []const u8{
        &.{ "-I", "-d", "a=1", "http://x" },
        &.{ "-I", "--json", "{}", "http://x" },
        &.{ "-I", "-T", "f", "http://x" },
        &.{ "-T", "f", "-d", "a=1", "http://x" },
        &.{ "-d", "a=1", "-T", "f", "http://x" },
        // `-F` joins the same list. The last two are two bodies rather
        // than two methods, and curl refuses them with the same message
        // and the same exit 2, measured.
        &.{ "-F", "a=1", "-I", "http://x" },
        &.{ "-F", "a=1", "-T", "f", "http://x" },
        &.{ "-F", "a=1", "-d", "b=2", "http://x" },
        &.{ "-d", "b=2", "-F", "a=1", "http://x" },
        &.{ "-F", "a=1", "--json", "{}", "http://x" },
        &.{ "--form-string", "a=1", "-d", "b=2", "http://x" },
    };
    for (refused) |argv| {
        var fault: Fault = .{};
        try testing.expectError(error.ConflictingMethods, parse(a, argv, &env, &fault));
        try testing.expect(std.mem.indexOf(u8, fault.message, "one HTTP request method") != null);
    }

    _ = try parse(a, &.{ "-I", "-X", "POST", "http://x" }, &env, null);
    _ = try parse(a, &.{ "-I", "-G", "http://x" }, &env, null);
    _ = try parse(a, &.{ "-G", "-T", "f", "http://x" }, &env, null);
    // Measured: `-F 'a=1' -G` runs and sends the form as a `POST` body.
    _ = try parse(a, &.{ "-F", "a=1", "-G", "http://x" }, &env, null);
    // Two `-F` arguments are two parts of one body, never a conflict.
    _ = try parse(a, &.{ "-F", "a=1", "-F", "b=2", "http://x" }, &env, null);
    _ = try parse(a, &.{ "-F", "a=1", "--form-string", "b=2", "http://x" }, &env, null);
}

test "-F and --form-string fill one ordered list, and --form-escape is its own flag" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const plan = try parse(a, &.{
        "-F", "x=@a.txt", "--form-string", "y=@b.txt", "-F", "z=1", "http://x",
    }, &env, null);

    const items = plan.request_body.form;
    try testing.expectEqual(@as(usize, 3), items.len);
    try testing.expectEqual(FormKind.form, items[0].kind);
    try testing.expectEqualStrings("x=@a.txt", items[0].text);
    try testing.expectEqual(FormKind.string, items[1].kind);
    try testing.expectEqualStrings("y=@b.txt", items[1].text);
    try testing.expectEqual(FormKind.form, items[2].kind);
    try testing.expectEqualStrings("z=1", items[2].text);

    // Nothing is opened and nothing is parsed here. `parse` does no I/O,
    // so `a.txt` need not be there for this to succeed.
    try testing.expect(!plan.request_body.form_escape);

    const escaped = try parse(a, &.{ "--form-escape", "-F", "n=v", "http://x" }, &env, null);
    try testing.expect(escaped.request_body.form_escape);

    // The form implies no content type of its own here. The boundary is
    // not known until `src/cli/form.zig` draws it, so
    // `zurl.multipart.Body` carries the header instead.
    try testing.expectEqual(@as(?[]const u8, null), plan.request_body.content_type);
    try testing.expectEqual(@as(usize, 0), plan.options.headers.len);
}

test "-d implies a content type, and -H replaces it instead of adding a second" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    // The form content type rides on the body, so a redirect that drops
    // the body drops it too. It is not among the headers.
    const form = try parse(a, &.{ "-d", "a=1", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 0), form.options.headers.len);
    try testing.expectEqualStrings("application/x-www-form-urlencoded", form.request_body.content_type.?);

    // `--json` asks for two headers, and curl sends them in this order.
    const json = try parse(a, &.{ "--json", "{}", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 2), json.options.headers.len);
    try testing.expectEqualStrings("application/json", json.options.headers[0].value);
    try testing.expectEqualStrings("accept", json.options.headers[1].name);

    // Measured: `--json X -H 'Content-Type: text/plain'` sends text/plain
    // and keeps `Accept: application/json`, with no second content type.
    const overridden = try parse(a, &.{
        "--json", "{}", "-H", "Content-Type: text/plain", "http://x",
    }, &env, null);
    try testing.expectEqual(@as(usize, 2), overridden.options.headers.len);
    try testing.expectEqualStrings("text/plain", overridden.options.headers[0].value);
    try testing.expectEqualStrings("accept", overridden.options.headers[1].name);

    // A `-H` of the same name wins outright, and nothing is implied.
    const user_type = try parse(a, &.{
        "-d", "a=1", "-H", "Content-Type: text/plain", "http://x",
    }, &env, null);
    try testing.expectEqual(@as(usize, 1), user_type.options.headers.len);
    try testing.expectEqualStrings("text/plain", user_type.options.headers[0].value);
    try testing.expectEqual(@as(?[]const u8, null), user_type.request_body.content_type);

    // A `-G` has no body, so it implies no content type. Measured.
    const get = try parse(a, &.{ "-G", "-d", "a=1", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 0), get.options.headers.len);
    try testing.expectEqual(@as(?[]const u8, null), get.request_body.content_type);

    // `-T` implies no content type at all. Measured: `curl -T file URL`
    // sends `Content-Length` and no `Content-Type`.
    const upload = try parse(a, &.{ "-T", "f", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 0), upload.options.headers.len);
    try testing.expectEqual(@as(?[]const u8, null), upload.request_body.content_type);
}

test "every -d spelling lands in one list, in command-line order" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{
        "-d",               "a=1",
        "--data-ascii",     "b=2",
        "--data-raw",       "c=3",
        "--data-binary",    "d=4",
        "--data-urlencode", "e=5",
        "--json",           "{}",
        "http://x",
    }, &env, null);

    const items = plan.request_body.data;
    try testing.expectEqual(@as(usize, 6), items.len);
    try testing.expectEqual(DataKind.ascii, items[0].kind);
    try testing.expectEqual(DataKind.ascii, items[1].kind);
    try testing.expectEqual(DataKind.raw, items[2].kind);
    try testing.expectEqual(DataKind.binary, items[3].kind);
    try testing.expectEqual(DataKind.urlencode, items[4].kind);
    try testing.expectEqual(DataKind.json, items[5].kind);
    try testing.expectEqualStrings("a=1", items[0].text);
    try testing.expectEqualStrings("{}", items[5].text);
}

test "-H can be given more than once and keeps its order" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{
        "-H",       "X-A: 1",
        "-H",       "X-B: 2",
        "http://x",
    }, &env, null);

    try testing.expectEqual(@as(usize, 2), plan.options.headers.len);
    try testing.expectEqualStrings("X-A", plan.options.headers[0].name);
    try testing.expectEqualStrings("1", plan.options.headers[0].value);
    try testing.expectEqualStrings("X-B", plan.options.headers[1].name);
    try testing.expectEqualStrings("2", plan.options.headers[1].value);
}

test "-u splits on the first colon so a password may contain one" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-u", "alice:pa:ss", "http://x" }, &env, null);
    try testing.expectEqualStrings("alice", plan.options.credentials.?.user);
    try testing.expectEqualStrings("pa:ss", plan.options.credentials.?.password);
}

test "-u with no colon is a user with an empty password" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-u", "alice", "http://x" }, &env, null);
    try testing.expectEqualStrings("alice", plan.options.credentials.?.user);
    try testing.expectEqualStrings("", plan.options.credentials.?.password);
}

test "--limit-rate accepts a k, M and G suffix" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan_k = try parse(arena.allocator(), &.{ "--limit-rate", "2k", "http://x" }, &env, null);
    try testing.expectEqual(@as(u64, 2 * 1024), plan_k.options.max_bytes_per_second);

    const plan_m = try parse(arena.allocator(), &.{ "--limit-rate", "3M", "http://x" }, &env, null);
    try testing.expectEqual(@as(u64, 3 * 1024 * 1024), plan_m.options.max_bytes_per_second);

    const plan_g = try parse(arena.allocator(), &.{ "--limit-rate", "1G", "http://x" }, &env, null);
    try testing.expectEqual(@as(u64, 1024 * 1024 * 1024), plan_g.options.max_bytes_per_second);
}

test "--limit-rate rejects a suffix it does not know" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    const result = parse(arena.allocator(), &.{ "--limit-rate", "5X", "http://x" }, &env, &fault);
    try testing.expectError(error.InvalidSizeSuffix, result);
    try testing.expect(std.mem.indexOf(u8, fault.message, "X") != null);
}

test "--connect-timeout accepts a fractional second" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "--connect-timeout", "2.5", "http://x" }, &env, null);
    try testing.expectEqual(@as(i64, 2500), plan.options.connect_timeout.duration.raw.toMilliseconds());
    try testing.expectEqual(std.Io.Clock.awake, plan.options.connect_timeout.duration.clock);
}

test "a flag that needs an argument and has none is a usage error naming the flag" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    const short_result = parse(arena.allocator(), &.{ "http://x", "-H" }, &env, &fault);
    try testing.expectError(error.MissingArgument, short_result);
    try testing.expect(std.mem.indexOf(u8, fault.message, "-H") != null);

    var fault2: Fault = .{};
    const long_result = parse(arena.allocator(), &.{ "http://x", "--header" }, &env, &fault2);
    try testing.expectError(error.MissingArgument, long_result);
    try testing.expect(std.mem.indexOf(u8, fault2.message, "--header") != null);
}

test "an unknown flag is a usage error naming the flag" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    const result = parse(arena.allocator(), &.{ "--bogus-flag", "http://x" }, &env, &fault);
    try testing.expectError(error.UnknownFlag, result);
    try testing.expect(std.mem.indexOf(u8, fault.message, "--bogus-flag") != null);
}

test "a mistyped flag names the flag and never the value written beside it" {
    // **The one place an inline value reached standard error whole.**
    // `--use=alice:s3cret` is a typo for `--user`, and the message used to
    // carry the password with it. `safe.Text` masks a url userinfo, and a
    // bare `user:pass` is not one, so nothing masked it. In CI that lands
    // in a build log.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    try testing.expectError(error.UnknownFlag, parse(
        arena.allocator(),
        &.{ "--use=alice:s3cret", "http://x" },
        &env,
        &fault,
    ));
    try testing.expectEqualStrings("zurl: unknown flag: '--use'", fault.message);
    try testing.expect(std.mem.indexOf(u8, fault.message, "s3cret") == null);
}

test "a long flag may be written --flag=value as well as --flag value" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const equals_form = try parse(arena.allocator(), &.{ "--user-agent=custom/9", "http://x" }, &env, null);
    try testing.expectEqualStrings("custom/9", equals_form.options.user_agent);

    const space_form = try parse(arena.allocator(), &.{ "--user-agent", "custom/9", "http://x" }, &env, null);
    try testing.expectEqualStrings("custom/9", space_form.options.user_agent);
}

test "several short flags may be bundled as -sS" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-sS", "http://x" }, &env, null);
    try testing.expectEqual(true, plan.silent);
    try testing.expectEqual(true, plan.show_error);
}

test "-- stops flag parsing so a url may begin with a dash" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "--", "-not-a-flag" }, &env, null);
    try testing.expectEqual(@as(usize, 1), plan.urls.len);
    try testing.expectEqualStrings("-not-a-flag", plan.urls[0]);
}

test "more than one url is kept, in order" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "http://a", "http://b" }, &env, null);
    try testing.expectEqual(@as(usize, 2), plan.urls.len);
    try testing.expectEqualStrings("http://a", plan.urls[0]);
    try testing.expectEqualStrings("http://b", plan.urls[1]);
}

test "with no -L, a default plan does not follow a redirect" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(Transfer.Redirects.unfollowed, plan.options.redirects);
}

test "-L makes the plan follow, up to curl's own default of 50" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-L", "http://x" }, &env, null);
    try testing.expectEqual(Transfer.Redirects{ .follow = 50 }, plan.options.redirects);
}

test "--max-redirs with no -L changes nothing, matching curl: the manual ties it to --location" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "--max-redirs", "3", "http://x" }, &env, null);
    try testing.expectEqual(Transfer.Redirects.unfollowed, plan.options.redirects);
}

test "--max-redirs together with -L sets the follow limit" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const with_flag_after = try parse(arena.allocator(), &.{ "-L", "--max-redirs", "3", "http://x" }, &env, null);
    try testing.expectEqual(Transfer.Redirects{ .follow = 3 }, with_flag_after.options.redirects);

    // Flag order does not matter to curl, so it must not matter here.
    const with_flag_before = try parse(arena.allocator(), &.{ "--max-redirs", "3", "-L", "http://x" }, &env, null);
    try testing.expectEqual(Transfer.Redirects{ .follow = 3 }, with_flag_before.options.redirects);
}

test "-f sets fail_on_error" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "--fail", "http://x" }, &env, null);
    try testing.expectEqual(true, plan.options.fail_on_error);
}

test "--speed-limit and --speed-time set the stall bounds" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{
        "--speed-limit", "500",
        "--speed-time",  "20",
        "http://x",
    }, &env, null);
    try testing.expectEqual(@as(u64, 500), plan.options.low_speed_limit);
    try testing.expectEqual(@as(u32, 20), plan.options.low_speed_time_s);
}

test "--max-filesize accepts a suffix the same way --limit-rate does" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "--max-filesize", "4M", "http://x" }, &env, null);
    try testing.expectEqual(@as(u64, 4 * 1024 * 1024), plan.options.max_size);
}

test "--netrc-file captures the path without reading it" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "--netrc-file", "/tmp/does-not-exist.netrc", "http://x" }, &env, null);
    try testing.expectEqualStrings("/tmp/does-not-exist.netrc", plan.netrc_path.?);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.netrc_text);
}

test "--cacert, --capath and --ca-native fill the ca inputs" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{
        "--cacert",    "/etc/ca.pem",
        "--capath",    "/etc/ca-dir",
        "--ca-native", "http://x",
    }, &env, null);
    try testing.expectEqualStrings("/etc/ca.pem", plan.options.ca.cacert.?);
    try testing.expectEqualStrings("/etc/ca-dir", plan.options.ca.capath.?);
    try testing.expectEqual(true, plan.options.ca.ca_native);
}

test "--proxy-ca-native fills the proxy trust store and never the origin's" {
    // **The two stores are separate and must stay separate.** A build
    // with one would verify one peer against the other's roots at
    // whichever hop loaded last, and a transfer through a proxy puts both
    // peers in play. So this asserts on both fields and not on one.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const proxied = try parse(
        arena.allocator(),
        &.{ "--proxy-ca-native", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(true, proxied.options.proxy_ca.ca_native);
    try testing.expectEqual(false, proxied.options.ca.ca_native);

    // And the mirror, so neither flag can be wired into the other's
    // field without one of the two halves failing.
    const origin = try parse(arena.allocator(), &.{ "--ca-native", "http://x" }, &env, null);
    try testing.expectEqual(true, origin.options.ca.ca_native);
    try testing.expectEqual(false, origin.options.proxy_ca.ca_native);
}

test "--tcp-nodelay is the other half of --no-tcp-nodelay, and the last one wins" {
    // The pair has to read in either order, the way `--clobber` and
    // `--no-clobber` do, because a config file may hold one and a command
    // line the other.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    // True is the default, so the flag alone names the state a plain run
    // is already in.
    try testing.expectEqual(true, (try parse(a, &.{"http://x"}, &env, null)).options.tcp_no_delay);
    try testing.expectEqual(
        true,
        (try parse(a, &.{ "--tcp-nodelay", "http://x" }, &env, null)).options.tcp_no_delay,
    );
    try testing.expectEqual(
        false,
        (try parse(a, &.{ "--no-tcp-nodelay", "http://x" }, &env, null)).options.tcp_no_delay,
    );
    try testing.expectEqual(true, (try parse(
        a,
        &.{ "--no-tcp-nodelay", "--tcp-nodelay", "http://x" },
        &env,
        null,
    )).options.tcp_no_delay);
    try testing.expectEqual(false, (try parse(
        a,
        &.{ "--tcp-nodelay", "--no-tcp-nodelay", "http://x" },
        &env,
        null,
    )).options.tcp_no_delay);
}

test "-B and --disable-epsv reach the ftp options and nothing else" {
    // Both flags travel to `zurl-ftp` through `Transfer.Options`, and
    // neither has any other reader. A run with no flag must leave both
    // false, so a default-built transfer keeps the shape it had before
    // the two fields existed.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const plain = try parse(a, &.{"ftp://h/f"}, &env, null);
    try testing.expectEqual(false, plain.options.use_ascii);
    try testing.expectEqual(false, plain.options.ftp_disable_epsv);

    const short = try parse(a, &.{ "-B", "ftp://h/f" }, &env, null);
    try testing.expectEqual(true, short.options.use_ascii);

    const long = try parse(a, &.{ "--use-ascii", "ftp://h/f" }, &env, null);
    try testing.expectEqual(true, long.options.use_ascii);

    const epsv = try parse(a, &.{ "--disable-epsv", "ftp://h/f" }, &env, null);
    try testing.expectEqual(true, epsv.options.ftp_disable_epsv);
    // `--disable-eprt` is the accepted-and-inert twin, and it must not
    // reach this field: the two flags name two different commands.
    const eprt = try parse(a, &.{ "--disable-eprt", "ftp://h/f" }, &env, null);
    try testing.expectEqual(false, eprt.options.ftp_disable_epsv);
}

test "--tftp-blksize is refused outside its range and never clamped" {
    // **A clamped size is a transfer that ran with a number the user did
    // not choose.** The bounds come from `zurl_tftp.packet`, so this
    // cannot drift from the package that writes the request.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const floor = zurl_tftp.packet.min_block_size;
    const ceiling = zurl_tftp.packet.max_block_size;

    var at_floor: [8]u8 = undefined;
    const floor_text = try std.fmt.bufPrint(&at_floor, "{d}", .{floor});
    try testing.expectEqual(floor, (try parse(
        a,
        &.{ "--tftp-blksize", floor_text, "tftp://h/f" },
        &env,
        null,
    )).options.tftp_block_size.?);

    var at_ceiling: [8]u8 = undefined;
    const ceiling_text = try std.fmt.bufPrint(&at_ceiling, "{d}", .{ceiling});
    try testing.expectEqual(ceiling, (try parse(
        a,
        &.{ "--tftp-blksize", ceiling_text, "tftp://h/f" },
        &env,
        null,
    )).options.tftp_block_size.?);

    var under: [8]u8 = undefined;
    const under_text = try std.fmt.bufPrint(&under, "{d}", .{floor - 1});
    var fault: Fault = undefined;
    try testing.expectError(error.InvalidNumber, parse(
        a,
        &.{ "--tftp-blksize", under_text, "tftp://h/f" },
        &env,
        &fault,
    ));
    // The message names both bounds, so the user learns the range and not
    // just that they were outside it.
    try testing.expect(std.mem.indexOf(u8, fault.message, "tftp block size") != null);

    var over: [8]u8 = undefined;
    const over_text = try std.fmt.bufPrint(&over, "{d}", .{@as(u32, ceiling) + 1});
    try testing.expectError(error.InvalidNumber, parse(
        a,
        &.{ "--tftp-blksize", over_text, "tftp://h/f" },
        &env,
        &fault,
    ));

    // No flag leaves the field null, which the package reads as its own
    // default. `--tftp-no-options` is the other half of the pair.
    const plain = try parse(a, &.{"tftp://h/f"}, &env, null);
    try testing.expectEqual(@as(?u16, null), plain.options.tftp_block_size);
    try testing.expectEqual(true, plain.options.tftp_send_options);
    try testing.expectEqual(false, (try parse(
        a,
        &.{ "--tftp-no-options", "tftp://h/f" },
        &env,
        null,
    )).options.tftp_send_options);
}

test "--remote-name-all and --out-null answer for every url no -o covers" {
    // **An explicit destination still wins for its own url**, which is
    // curl's rule: the list of `-o` and `-O` pairs with the url list one
    // for one, and the tail answers for what is left. So a run with one
    // `-o` and two urls writes the file for url one and takes the tail
    // for url two.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const plain = try parse(a, &.{ "http://x/a", "http://x/b" }, &env, null);
    try testing.expectEqual(Args_BodyTargetTag.stdout, plain.output.bodyTarget(1));
    try testing.expectEqual(true, plain.output.anyToStdout(2));

    const all = try parse(
        a,
        &.{ "-o", "one", "--remote-name-all", "http://x/a", "http://x/b" },
        &env,
        null,
    );
    try testing.expectEqualStrings("one", all.output.bodyTarget(0).file);
    try testing.expectEqual(Args_BodyTargetTag.url_name, all.output.bodyTarget(1));
    // Nothing reaches standard output now, so a `-Z` run is free to
    // overlap the transfers.
    try testing.expectEqual(false, all.output.anyToStdout(2));

    const null_out = try parse(a, &.{ "--out-null", "http://x/a" }, &env, null);
    try testing.expectEqual(Args_BodyTargetTag.discard, null_out.output.bodyTarget(0));
    try testing.expectEqual(false, null_out.output.anyToStdout(1));

    // The last of the two wins, in both orders, so neither flag can
    // quietly outrank the other.
    try testing.expectEqual(Args_BodyTargetTag.discard, (try parse(
        a,
        &.{ "--remote-name-all", "--out-null", "http://x/a" },
        &env,
        null,
    )).output.bodyTarget(0));
    try testing.expectEqual(Args_BodyTargetTag.url_name, (try parse(
        a,
        &.{ "--out-null", "--remote-name-all", "http://x/a" },
        &env,
        null,
    )).output.bodyTarget(0));
}

/// The tag of `BodyTarget`, so a test can compare a target that carries no
/// payload without writing the union out.
const Args_BodyTargetTag = std.meta.Tag(BodyTarget);

test "--url-query fills its own list and never the request body" {
    // **`--url-query` is not `-G`.** `-G` moves the `-d` data into the
    // query and leaves no body, and this adds to the query and leaves the
    // body alone. A build that put these items in `data` would send them
    // as a body whenever `-G` was absent.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const plan = try parse(
        a,
        &.{ "--url-query", "a b=c", "-d", "body=1", "http://x/p" },
        &env,
        null,
    );
    try testing.expectEqual(@as(usize, 1), plan.request_body.query.len);
    try testing.expectEqualStrings("a b=c", plan.request_body.query[0].text);
    try testing.expectEqual(DataKind.urlencode, plan.request_body.query[0].kind);
    try testing.expectEqual(@as(usize, 1), plan.request_body.data.len);
    try testing.expectEqualStrings("body=1", plan.request_body.data[0].text);
    // The flag does not turn `-G` on. A run with both is a run the user
    // asked for both of.
    try testing.expectEqual(false, plan.request_body.get);

    // Repeated, in order, the way every other repeatable list is kept.
    const twice = try parse(
        a,
        &.{ "--url-query", "a=1", "--url-query", "b=2", "http://x/p" },
        &env,
        null,
    );
    try testing.expectEqual(@as(usize, 2), twice.request_body.query.len);
    try testing.expectEqualStrings("a=1", twice.request_body.query[0].text);
    try testing.expectEqualStrings("b=2", twice.request_body.query[1].text);
}

test "--disallow-username-in-url refuses a credential in any url of the run" {
    // **Every url is checked, and not the first one alone.** A run that
    // refused only url one would still have sent the credential in url
    // two. The message names the url and never the password: `safe.text`
    // masks a userinfo password, and this asserts on the mask.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    // A clean run still parses.
    _ = try parse(a, &.{ "--disallow-username-in-url", "http://x/a" }, &env, null);

    var fault: Fault = undefined;
    try testing.expectError(error.UsernameInUrl, parse(
        a,
        &.{ "--disallow-username-in-url", "http://alice:s3cret@x/a" },
        &env,
        &fault,
    ));
    try testing.expect(std.mem.indexOf(u8, fault.message, "s3cret") == null);

    // The second url carries it, so the first must not let the run
    // through.
    try testing.expectError(error.UsernameInUrl, parse(
        a,
        &.{ "--disallow-username-in-url", "http://x/a", "http://bob@x/b" },
        &env,
        &fault,
    ));

    // A password with no user name is a credential too, and curl refuses
    // it as well.
    try testing.expectError(error.UsernameInUrl, parse(
        a,
        &.{ "--disallow-username-in-url", "http://:pw@x/a" },
        &env,
        &fault,
    ));

    // With no flag, the same urls parse. The flag is the opt-in, and the
    // default has to stay what it was.
    _ = try parse(a, &.{"http://alice:s3cret@x/a"}, &env, null);
}

test "a userinfo is read out of the url text and never guessed" {
    // `hasUserinfo` runs before any url is parsed, so it reads the text.
    // The `@` has to be inside the authority: a `@` in a path, in a
    // query, or in a fragment is an ordinary character.
    try testing.expectEqual(true, hasUserinfo("http://alice@h/p"));
    try testing.expectEqual(true, hasUserinfo("http://alice:pw@h:8080/p"));
    try testing.expectEqual(true, hasUserinfo("http://:pw@h/p"));
    try testing.expectEqual(false, hasUserinfo("http://h/p@q"));
    try testing.expectEqual(false, hasUserinfo("http://h/p?a=b@c"));
    try testing.expectEqual(false, hasUserinfo("http://h/p#a@b"));
    try testing.expectEqual(false, hasUserinfo("http://h/"));
    // No authority at all, so no userinfo.
    try testing.expectEqual(false, hasUserinfo("mailto:alice@h"));
    try testing.expectEqual(false, hasUserinfo("h/p"));
    // A `//` that is inside the path and not the start of an authority.
    try testing.expectEqual(false, hasUserinfo("http:/a//b@c"));
}

test "the three SASL flags reach the plan rather than being refused by name" {
    // **These three used to be refused**, because no mail protocol here
    // spoke SASL. All three now carry a value to `zurl_net.sasl`, so the
    // refusal is gone and the plan holds what the user wrote.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const plan = try parse(a, &.{
        "--sasl-authzid", "admin",
        "--sasl-ir",      "--login-options",
        "AUTH=PLAIN",     "-u",
        "alice:s3cret",   "smtp://h/",
    }, &env, null);
    try testing.expectEqual(@as(?UnsupportedFlag, null), plan.unsupported_flag);
    try testing.expectEqualStrings("admin", plan.options.sasl_authzid.?);
    try testing.expect(plan.options.sasl_ir);
    try testing.expectEqualStrings("AUTH=PLAIN", plan.options.login_options.?);

    // A run that names none of them leaves all three at their defaults,
    // which is the automatic choice and no initial response.
    const bare = try parse(a, &.{ "-u", "alice:s3cret", "smtp://h/" }, &env, null);
    try testing.expectEqual(@as(?[]const u8, null), bare.options.sasl_authzid);
    try testing.expect(!bare.options.sasl_ir);
    try testing.expectEqual(@as(?[]const u8, null), bare.options.login_options);

    // **The value is carried and never checked here.** A mechanism name
    // this build does not speak reaches the protocol package, which is
    // the one place that knows what it offers, and the message names the
    // mechanism.
    const odd = try parse(a, &.{ "--login-options", "AUTH=GSSAPI", "smtp://h/" }, &env, null);
    try testing.expectEqual(@as(?UnsupportedFlag, null), odd.unsupported_flag);
    try testing.expectEqualStrings("AUTH=GSSAPI", odd.options.login_options.?);
}

test "--oauth2-bearer and --dump-ca-embed reach the plan" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const bearer = try parse(a, &.{ "--oauth2-bearer", "tok-1", "http://x" }, &env, null);
    try testing.expectEqualStrings("tok-1", bearer.options.bearer_token.?);
    // `-u` beside it is still carried, because `zurl.authorize` is the
    // one place that decides which credential wins. A parse that dropped
    // `-u` here would move that decision into two files.
    const both = try parse(
        a,
        &.{ "--oauth2-bearer", "tok-1", "-u", "alice:pw", "http://x" },
        &env,
        null,
    );
    try testing.expectEqualStrings("tok-1", both.options.bearer_token.?);
    try testing.expectEqualStrings("alice", both.options.credentials.?.user);

    try testing.expectEqual(false, (try parse(a, &.{"http://x"}, &env, null)).dump_ca_embed);
    try testing.expectEqual(
        true,
        (try parse(a, &.{ "--dump-ca-embed", "http://x" }, &env, null)).dump_ca_embed,
    );
    try testing.expectEqual(
        false,
        (try parse(a, &.{"http://x"}, &env, null)).skip_existing,
    );
    try testing.expectEqual(
        true,
        (try parse(a, &.{ "--skip-existing", "http://x" }, &env, null)).skip_existing,
    );
}

test "the four redirect flags each name one status, and --follow names three" {
    // **The narrowness is the point.** `--post301` alone must not keep a
    // body across a `302`. A build that set all three from one flag would
    // send a body to a target the user never told it to.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const plain = try parse(a, &.{"http://x"}, &env, null);
    try testing.expectEqual(false, plain.options.redirect_methods.post301);
    try testing.expectEqual(false, plain.options.redirect_methods.post302);
    try testing.expectEqual(false, plain.options.redirect_methods.post303);

    const one = try parse(a, &.{ "--post301", "http://x" }, &env, null);
    try testing.expectEqual(true, one.options.redirect_methods.post301);
    try testing.expectEqual(false, one.options.redirect_methods.post302);
    try testing.expectEqual(false, one.options.redirect_methods.post303);

    const two = try parse(a, &.{ "--post302", "http://x" }, &env, null);
    try testing.expectEqual(false, two.options.redirect_methods.post301);
    try testing.expectEqual(true, two.options.redirect_methods.post302);

    const three = try parse(a, &.{ "--post303", "http://x" }, &env, null);
    try testing.expectEqual(true, three.options.redirect_methods.post303);

    // **`--follow` follows, and it keeps nothing.** Measured against curl
    // 8.21.0: `--follow -d a=1` through a 302 sends `GET /moved` with no
    // body, exactly as `-L` does. An earlier reading made this flag set
    // the three above, and that sent a `POST` with the body to the
    // redirect target, which curl never does. This pins the correction.
    const follow = try parse(a, &.{ "--follow", "http://x" }, &env, null);
    try testing.expectEqual(false, follow.options.redirect_methods.post301);
    try testing.expectEqual(false, follow.options.redirect_methods.post302);
    try testing.expectEqual(false, follow.options.redirect_methods.post303);
    try testing.expectEqual(
        @as(u16, curl_default_max_redirects),
        follow.options.redirects.follow,
    );
    // And it reads exactly as `-L` reads, including `--max-redirs` in
    // either order.
    const dashl = try parse(a, &.{ "--max-redirs", "3", "-L", "http://x" }, &env, null);
    const followed = try parse(a, &.{ "--follow", "--max-redirs", "3", "http://x" }, &env, null);
    try testing.expectEqual(dashl.options.redirects, followed.options.redirects);
    // And a plain run still follows nothing, which is curl's own default
    // and not the library's. `parse` sets it, so a new flag that turned
    // following on by accident fails here.
    const bare = try parse(a, &.{"http://x"}, &env, null);
    try testing.expect(bare.options.redirects == .unfollowed);
}

test "every refused flag names itself and never its own argument" {
    // **The rule that keeps a secret out of standard error.** Several of
    // these flags carry a password in the argument, and
    // `--tlspassword=hunter2` is one argument. The refusal has to name
    // the flag from `flag_table` and never the text the user wrote.
    //
    // The walk is over the whole table rather than a hand-written list,
    // so a flag added later cannot skip the check.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    for (flag_table) |flag| {
        const long = flag.long orelse continue;
        var spelling: [64]u8 = undefined;
        var attached: [128]u8 = undefined;

        var argv: [3][]const u8 = undefined;
        var argv_len: usize = 0;
        if (flag.takes_value) {
            // The `--flag=value` form, which is the one that puts the
            // argument inside the token the user typed.
            argv[argv_len] = try std.fmt.bufPrint(
                &attached,
                "--{s}=hunter2secret",
                .{long},
            );
        } else {
            argv[argv_len] = try std.fmt.bufPrint(&spelling, "--{s}", .{long});
        }
        argv_len += 1;
        argv[argv_len] = "http://x";
        argv_len += 1;

        const plan = parse(a, argv[0..argv_len], &env, null) catch continue;
        const refused = plan.unsupported_flag orelse continue;

        // The name is the long spelling from the table, with two dashes
        // and no argument behind it.
        var expected: [64]u8 = undefined;
        try testing.expectEqualStrings(
            try std.fmt.bufPrint(&expected, "--{s}", .{long}),
            refused.flag,
        );
        try testing.expect(std.mem.indexOf(u8, refused.flag, "hunter2secret") == null);
        try testing.expect(std.mem.indexOf(u8, refused.reason, "hunter2secret") == null);
        // A reason that says nothing is a refusal a user cannot act on.
        try testing.expect(refused.reason.len > 20);
    }
}

test "a flag accepted and inert changes no field of the options" {
    // **The other half of the contract.** A flag in the accepted-and-inert
    // list must leave the transfer exactly as a run with no flag at all
    // leaves it. A field that moved here would be a flag doing something
    // its help line says it does not.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const inert = [_][]const u8{
        "--path-as-is",
        "--ftp-pasv",
        "--ftp-skip-pasv-ip",
        "--disable-eprt",
        "--no-sessionid",
        "--ssl-allow-beast",
        "--proxy-ssl-allow-beast",
        "--ssl-auto-client-cert",
        "--proxy-ssl-auto-client-cert",
        "--ssl-no-revoke",
        "--ssl-revoke-best-effort",
        "--false-start",
        "--no-npn",
        "--metalink",
        "--ntlm-wb",
        "--socks5-basic",
        "--styled-output",
        "--tcp-fastopen",
        "--mptcp",
    };

    const bare = try parse(a, &.{"http://x"}, &env, null);
    for (inert) |flag| {
        const plan = try parse(a, &.{ flag, "http://x" }, &env, null);
        // Nothing was refused, so the run would go on.
        try testing.expectEqual(@as(?UnsupportedFlag, null), plan.unsupported_flag);
        // And every answer a transfer reads is the answer a bare run
        // gives. The fields named here are the ones each flag would have
        // moved if it were wired by mistake.
        try testing.expectEqual(bare.options.insecure, plan.options.insecure);
        try testing.expectEqual(bare.options.tcp_no_delay, plan.options.tcp_no_delay);
        try testing.expectEqual(bare.options.tls_min_version, plan.options.tls_min_version);
        try testing.expectEqual(bare.options.tls_max_version, plan.options.tls_max_version);
        try testing.expectEqual(bare.options.no_alpn, plan.options.no_alpn);
        try testing.expectEqual(bare.options.ftp_disable_epsv, plan.options.ftp_disable_epsv);
        try testing.expectEqual(bare.options.use_ascii, plan.options.use_ascii);
        try testing.expectEqual(bare.options.location_trusted, plan.options.location_trusted);
        try testing.expectEqual(bare.options.redirect_methods, plan.options.redirect_methods);
        try testing.expectEqual(bare.output.tail, plan.output.tail);
    }
}

/// Parses `argv` with an empty environment, for a proxy test about the
/// flags alone.
fn proxyPlan(arena: Allocator, argv: []const []const u8) !Plan {
    var env = testEnv();
    defer env.deinit();
    return parse(arena, argv, &env, null);
}

test "-x sets the proxy of both schemes, and the scheme picks the kind" {
    // An explicit `-x` covers every scheme, which is what curl does: one
    // flag, and no second one for https.
    var arena = testArena();
    defer arena.deinit();

    const plan = try proxyPlan(arena.allocator(), &.{ "-x", "http://127.0.0.1:3128", "http://x" });
    try testing.expectEqual(zurl_core.proxy.Kind.http, plan.options.proxy.?.kind);
    try testing.expectEqualStrings("127.0.0.1", plan.options.proxy.?.host);
    try testing.expectEqual(@as(u16, 3128), plan.options.proxy.?.port);
    try testing.expectEqual(zurl_core.proxy.Kind.http, plan.options.proxy_tls.?.kind);
    try testing.expectEqual(@as(u16, 3128), plan.options.proxy_tls.?.port);

    // The long spelling reads the same, and so does a socks scheme.
    const socks = try proxyPlan(arena.allocator(), &.{ "--proxy", "socks5h://127.0.0.1:9050", "http://x" });
    try testing.expectEqual(zurl_core.proxy.Kind.socks5h, socks.options.proxy.?.kind);
    try testing.expectEqual(@as(u16, 9050), socks.options.proxy.?.port);
}

test "-x with an empty argument turns proxying off, environment included" {
    // Measured against curl 8.21.0: with `http_proxy` set, `-x ""` sent the
    // request straight to the origin. An empty argument is a flag that says
    // no proxy, and not the absence of a flag.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("http_proxy", "http://127.0.0.1:1");

    const plan = try parse(arena.allocator(), &.{ "-x", "", "http://x" }, &env, null);
    try testing.expectEqual(@as(?Transfer.ProxySpec, null), plan.options.proxy);
    try testing.expectEqual(@as(?Transfer.ProxySpec, null), plan.options.proxy_tls);
}

test "each socks flag names the proxy and the protocol together" {
    var arena = testArena();
    defer arena.deinit();

    const rows = [_]struct { flag: []const u8, kind: zurl_core.proxy.Kind }{
        .{ .flag = "--socks4", .kind = .socks4 },
        .{ .flag = "--socks4a", .kind = .socks4a },
        .{ .flag = "--socks5", .kind = .socks5 },
        .{ .flag = "--socks5-hostname", .kind = .socks5h },
    };
    for (rows) |row| {
        const plan = try proxyPlan(arena.allocator(), &.{ row.flag, "127.0.0.1", "http://x" });
        try testing.expectEqual(row.kind, plan.options.proxy.?.kind);
        // The default port of the kind the flag named, and not of a scheme
        // in the text. Measured: `--socks5 127.0.0.1` dialed 1080.
        try testing.expectEqual(@as(u16, 1080), plan.options.proxy.?.port);
    }

    // The last proxy flag wins, the way the last of any pair does.
    const last = try proxyPlan(arena.allocator(), &.{
        "-x",       "http://127.0.0.1:3128",
        "--socks5", "127.0.0.1:9050",
        "http://x",
    });
    try testing.expectEqual(zurl_core.proxy.Kind.socks5, last.options.proxy.?.kind);
    try testing.expectEqual(@as(u16, 9050), last.options.proxy.?.port);
}

test "-U names the proxy credential and -u names the origin's" {
    // **The two credentials are two fields, all the way from the command
    // line.** A build that shared one would send the proxy's password to
    // the origin, or the origin's to the proxy.
    var arena = testArena();
    defer arena.deinit();

    const plan = try proxyPlan(arena.allocator(), &.{
        "-u",       "alice:originpw",
        "-U",       "bob:proxypw",
        "http://x",
    });
    try testing.expectEqualStrings("alice", plan.options.credentials.?.user);
    try testing.expectEqualStrings("originpw", plan.options.credentials.?.password);
    try testing.expectEqualStrings("bob", plan.options.proxy_credentials.?.user);
    try testing.expectEqualStrings("proxypw", plan.options.proxy_credentials.?.password);

    // The long spelling, and the split on the FIRST colon: a password may
    // hold one and a user name may not.
    const colons = try proxyPlan(arena.allocator(), &.{ "--proxy-user", "bob:pw:with:colons", "http://x" });
    try testing.expectEqualStrings("bob", colons.options.proxy_credentials.?.user);
    try testing.expectEqualStrings("pw:with:colons", colons.options.proxy_credentials.?.password);

    // And neither flag fills the other's field.
    const proxy_only = try proxyPlan(arena.allocator(), &.{ "-U", "bob:proxypw", "http://x" });
    try testing.expectEqual(@as(?zurl_core.auth.Credentials, null), proxy_only.options.credentials);
    const origin_only = try proxyPlan(arena.allocator(), &.{ "-u", "alice:originpw", "http://x" });
    try testing.expectEqual(@as(?zurl_core.auth.Credentials, null), origin_only.options.proxy_credentials);
}

test "--proxy-digest and --proxy-anyauth are refused and never downgraded" {
    // Only `Basic` is built. Answering a `Digest` challenge with `Basic`
    // would put the password on the wire in reversible base64, in
    // cleartext, to a proxy that had offered a scheme where the password
    // never travels. `src/main.zig` stops the run on this field.
    var arena = testArena();
    defer arena.deinit();

    const digest = try proxyPlan(arena.allocator(), &.{ "--proxy-digest", "http://x" });
    try testing.expectEqualStrings("--proxy-digest", digest.proxy_auth_refused.?);

    const anyauth = try proxyPlan(arena.allocator(), &.{ "--proxy-anyauth", "http://x" });
    try testing.expectEqualStrings("--proxy-anyauth", anyauth.proxy_auth_refused.?);

    // `--proxy-basic` is the default, and it undoes an earlier flag, which
    // is what the flag is for in a config file.
    const basic = try proxyPlan(arena.allocator(), &.{ "--proxy-digest", "--proxy-basic", "http://x" });
    try testing.expectEqual(@as(?[]const u8, null), basic.proxy_auth_refused);
    const bare = try proxyPlan(arena.allocator(), &.{"http://x"});
    try testing.expectEqual(@as(?[]const u8, null), bare.proxy_auth_refused);
}

test "the proxy certificate flags fill their own inputs and never the origin's" {
    // **Two trust stores, from two pairs of flags.** A build that wrote
    // `--proxy-cacert` into `options.ca` would verify the origin against
    // the proxy's roots.
    var arena = testArena();
    defer arena.deinit();

    const plan = try proxyPlan(arena.allocator(), &.{
        "--cacert",         "/etc/origin.pem",
        "--capath",         "/etc/origin-dir",
        "--proxy-cacert",   "/etc/proxy.pem",
        "--proxy-capath",   "/etc/proxy-dir",
        "--proxy-insecure", "http://x",
    });
    try testing.expectEqualStrings("/etc/origin.pem", plan.options.ca.cacert.?);
    try testing.expectEqualStrings("/etc/origin-dir", plan.options.ca.capath.?);
    try testing.expectEqualStrings("/etc/proxy.pem", plan.options.proxy_ca.cacert.?);
    try testing.expectEqualStrings("/etc/proxy-dir", plan.options.proxy_ca.capath.?);

    // **And `--proxy-insecure` does not touch the origin's own answer.**
    // An origin behind a `CONNECT` tunnel is still verified.
    try testing.expect(plan.options.proxy_insecure);
    try testing.expect(!plan.options.insecure);

    // The mirror: `-k` does not turn the proxy check off either.
    const origin = try proxyPlan(arena.allocator(), &.{ "-k", "http://x" });
    try testing.expect(origin.options.insecure);
    try testing.expect(!origin.options.proxy_insecure);
}

test "the proxy environment variables fill each scheme on its own" {
    // curl reads `http_proxy` for a cleartext target and `https_proxy` for
    // a TLS one, so a shell that sets one and not the other still reaches
    // the origin directly for the other scheme.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("http_proxy", "http://127.0.0.1:3128");
    try env.put("https_proxy", "http://127.0.0.2:3129");

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqualStrings("127.0.0.1", plan.options.proxy.?.host);
    try testing.expectEqualStrings("127.0.0.2", plan.options.proxy_tls.?.host);
}

test "HTTP_PROXY is not read, and every other upper case name is" {
    // **Measured against curl 8.21.0, and it is the documented
    // exception.** A CGI program takes a client's `Proxy:` request header
    // as `HTTP_PROXY` in its own environment, so reading it would let
    // whoever sent the request choose the proxy of every cleartext
    // transfer. curl leaves the transfer direct under it, and so does this.
    var arena = testArena();
    defer arena.deinit();
    {
        var env = testEnv();
        defer env.deinit();
        try env.put("HTTP_PROXY", "http://127.0.0.1:3128");
        const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
        try testing.expectEqual(@as(?Transfer.ProxySpec, null), plan.options.proxy);
    }
    {
        var env = testEnv();
        defer env.deinit();
        try env.put("HTTPS_PROXY", "http://127.0.0.1:3128");
        const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
        try testing.expectEqualStrings("127.0.0.1", plan.options.proxy_tls.?.host);
    }
    {
        var env = testEnv();
        defer env.deinit();
        try env.put("ALL_PROXY", "http://127.0.0.1:3128");
        const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
        try testing.expectEqualStrings("127.0.0.1", plan.options.proxy.?.host);
        try testing.expectEqualStrings("127.0.0.1", plan.options.proxy_tls.?.host);
    }
}

test "a scheme's own variable outranks all_proxy, and a flag outranks both" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("all_proxy", "http://127.0.0.3:3130");
    try env.put("http_proxy", "http://127.0.0.1:3128");

    const from_env = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    // Measured against curl 8.21.0 with both set: the scheme's own
    // variable won.
    try testing.expectEqualStrings("127.0.0.1", from_env.options.proxy.?.host);
    // And the scheme with no variable of its own falls back to `all_proxy`.
    try testing.expectEqualStrings("127.0.0.3", from_env.options.proxy_tls.?.host);

    const from_flag = try parse(arena.allocator(), &.{ "-x", "http://127.0.0.9:1", "http://x" }, &env, null);
    try testing.expectEqualStrings("127.0.0.9", from_flag.options.proxy.?.host);
    try testing.expectEqualStrings("127.0.0.9", from_flag.options.proxy_tls.?.host);
}

test "the lower case spelling wins where both cases are set" {
    // Measured against curl 8.21.0 with both cases pointing at two
    // different ports: the lower case one decided.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("https_proxy", "http://127.0.0.1:3128");
    try env.put("HTTPS_PROXY", "http://127.0.0.2:3129");

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqualStrings("127.0.0.1", plan.options.proxy_tls.?.host);
}

test "--noproxy outranks no_proxy, even when it is empty" {
    // Measured against curl 8.21.0: `--noproxy ""` beside a `no_proxy` that
    // would have matched still sent the request through the proxy. An
    // empty flag is a list that excludes nothing, and not the absence of a
    // flag.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("no_proxy", "example.com");

    const from_env = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqualStrings("example.com", from_env.options.no_proxy);

    const from_flag = try parse(arena.allocator(), &.{ "--noproxy", "other.test", "http://x" }, &env, null);
    try testing.expectEqualStrings("other.test", from_flag.options.no_proxy);

    const emptied = try parse(arena.allocator(), &.{ "--noproxy", "", "http://x" }, &env, null);
    try testing.expectEqualStrings("", emptied.options.no_proxy);
}

test "NO_PROXY answers when no_proxy does not" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("NO_PROXY", "example.com");

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqualStrings("example.com", plan.options.no_proxy);
}

test "a proxy url that does not read stops the parse by name" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var fault: Fault = .{};
    try testing.expectError(error.UnsupportedProxyScheme, parse(
        arena.allocator(),
        &.{ "-x", "ftp://127.0.0.1", "http://x" },
        &env,
        &fault,
    ));
    // The sentence names the fault and quotes nothing: a proxy url can
    // carry a credential, and a message is printed and logged.
    try testing.expect(std.mem.indexOf(u8, fault.message, "scheme") != null);
    try testing.expect(std.mem.indexOf(u8, fault.message, "127.0.0.1") == null);

    fault = .{};
    try testing.expectError(error.InvalidProxy, parse(
        arena.allocator(),
        &.{ "-x", "http://127.0.0.1:notaport", "http://x" },
        &env,
        &fault,
    ));
    try testing.expect(fault.message.len != 0);

    // And a bad value in the environment is refused the same way. A stale
    // shell profile must not become a silent direct connection.
    try env.put("http_proxy", "ftp://127.0.0.1");
    try testing.expectError(error.UnsupportedProxyScheme, parse(
        arena.allocator(),
        &.{"http://x"},
        &env,
        null,
    ));
}

test "a run that named no proxy keeps every proxy field at its default" {
    // The whole of the old behaviour. A command line with no proxy flag and
    // an empty environment reaches the engine with an empty proxy set.
    var arena = testArena();
    defer arena.deinit();

    const plan = try proxyPlan(arena.allocator(), &.{"http://x"});
    try testing.expectEqual(@as(?Transfer.ProxySpec, null), plan.options.proxy);
    try testing.expectEqual(@as(?Transfer.ProxySpec, null), plan.options.proxy_tls);
    try testing.expectEqualStrings("", plan.options.no_proxy);
    try testing.expectEqual(@as(?zurl_core.auth.Credentials, null), plan.options.proxy_credentials);
    try testing.expect(!plan.options.proxy_insecure);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.proxy_ca.cacert);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.proxy_ca.capath);
}

test "CURL_CA_BUNDLE fills the ca inputs" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("CURL_CA_BUNDLE", "/etc/curl-bundle.pem");

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqualStrings("/etc/curl-bundle.pem", plan.options.ca.curl_ca_bundle.?);
}

test "SSL_CERT_FILE and SSL_CERT_DIR fill their own fields" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("SSL_CERT_FILE", "/etc/ssl/cert.pem");
    try env.put("SSL_CERT_DIR", "/etc/ssl/certs");

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqualStrings("/etc/ssl/cert.pem", plan.options.ca.ssl_cert_file.?);
    try testing.expectEqualStrings("/etc/ssl/certs", plan.options.ca.ssl_cert_dir.?);
}

test "--cacert beats CURL_CA_BUNDLE" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("CURL_CA_BUNDLE", "/etc/curl-bundle.pem");

    const plan = try parse(arena.allocator(), &.{ "--cacert", "/etc/ca.pem", "http://x" }, &env, null);

    var out: [zurl_core.ca.max_sources]zurl_core.ca.Source = undefined;
    const sources = zurl_core.ca.resolve(plan.options.ca, &out);
    try testing.expectEqualStrings("/etc/ca.pem", sources[0].file);
}

test "an empty environment leaves the ca inputs untouched" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("CURL_CA_BUNDLE", "");
    try env.put("SSL_CERT_FILE", "");
    try env.put("SSL_CERT_DIR", "");

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.ca.curl_ca_bundle);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.ca.ssl_cert_file);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.ca.ssl_cert_dir);
}

test "a variable that is not set at all leaves its ca field null" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.ca.curl_ca_bundle);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.ca.ssl_cert_file);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.ca.ssl_cert_dir);
}

test "-o writes to a named file and -O derives the name from the url" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const file_plan = try parse(arena.allocator(), &.{ "-o", "out.bin", "http://x" }, &env, null);
    try testing.expectEqualStrings("out.bin", file_plan.output.bodyTarget(0).file);

    const url_plan = try parse(arena.allocator(), &.{ "-O", "http://x/a.bin" }, &env, null);
    try testing.expectEqual(BodyTarget.url_name, url_plan.output.bodyTarget(0));
}

test "-o and -O together fill one ordered list, the way curl pairs them" {
    // This used to be `error.ConflictingOutput`. curl 8.21.0 accepts the
    // pair and keeps both files: measured with two loopback servers,
    // `-o a -O URL1 URL2` wrote URL1 to `a` and URL2 to the name in
    // URL2, and standard output stayed empty.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(
        arena.allocator(),
        &.{ "-o", "out.bin", "-O", "http://x/one", "http://x/two.bin" },
        &env,
        null,
    );
    try testing.expectEqual(@as(usize, 2), plan.output.body.len);
    try testing.expectEqualStrings("out.bin", plan.output.bodyTarget(0).file);
    try testing.expectEqual(BodyTarget.url_name, plan.output.bodyTarget(1));
}

test "a url past the last -o goes to standard output" {
    // Measured: `curl -o a URL1 URL2` writes URL1 to `a` and URL2 to
    // standard output. zurl used to point both urls at `a`, so the second
    // truncated the first and the run still exited 0.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(
        arena.allocator(),
        &.{ "-o", "a", "http://x/one", "http://x/two" },
        &env,
        null,
    );
    try testing.expectEqualStrings("a", plan.output.bodyTarget(0).file);
    try testing.expectEqual(BodyTarget.stdout, plan.output.bodyTarget(1));
    try testing.expect(plan.output.anyToStdout(2));
    try testing.expect(!plan.output.anyToStdout(1));
}

test "an -o past the last url names no file and is not a fault" {
    // Measured: `curl -o a -o b -o c URL1 URL2` exits 0 and creates `a`
    // and `b` only. The third destination is simply unused.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(
        arena.allocator(),
        &.{ "-o", "a", "-o", "b", "-o", "c", "http://x/one", "http://x/two" },
        &env,
        null,
    );
    try testing.expectEqual(@as(usize, 3), plan.output.body.len);
    try testing.expectEqual(@as(usize, 2), plan.urls.len);
    try testing.expect(!plan.output.anyToStdout(2));
}

test "with no -o and no -O every url goes to standard output" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "http://x/one", "http://x/two" }, &env, null);
    try testing.expectEqual(BodyTarget.stdout, plan.output.bodyTarget(0));
    try testing.expectEqual(BodyTarget.stdout, plan.output.bodyTarget(1));
    try testing.expect(plan.output.anyToStdout(2));
}

test "-D captures a headers-dump path" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-D", "headers.txt", "http://x" }, &env, null);
    try testing.expectEqualStrings("headers.txt", plan.output.headers_file.?.file);
}

test "-o - names standard output, not a file called -" {
    // Measured: `curl -o - URL` writes the body to standard output and
    // creates no file. zurl used to read `-` as an ordinary file name and
    // create one called `-` in the working directory, which a script
    // written against curl never sees written and a user rarely means to
    // create.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-o", "-", "http://x" }, &env, null);
    try testing.expectEqual(BodyTarget.stdout, plan.output.bodyTarget(0));
}

test "-o - given twice sends both urls' bodies to standard output" {
    // Measured: `curl -o - -o - URL1 URL2` writes both bodies to standard
    // output, one after the other, and creates no file called `-`.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(
        arena.allocator(),
        &.{ "-o", "-", "-o", "-", "http://x/one", "http://x/two" },
        &env,
        null,
    );
    try testing.expectEqual(BodyTarget.stdout, plan.output.bodyTarget(0));
    try testing.expectEqual(BodyTarget.stdout, plan.output.bodyTarget(1));
}

test "-o - pairs with a url by position, the same as any other -o" {
    // Measured: `curl -o - -o b URL1 URL2` sends URL1's body to standard
    // output and URL2's body to `b`; `curl -o a -o - URL1 URL2` writes the
    // opposite way round. `-` only ever means standard output for the
    // slot it fills.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const first = try parse(
        arena.allocator(),
        &.{ "-o", "-", "-o", "b", "http://x/one", "http://x/two" },
        &env,
        null,
    );
    try testing.expectEqual(BodyTarget.stdout, first.output.bodyTarget(0));
    try testing.expectEqualStrings("b", first.output.bodyTarget(1).file);

    const second = try parse(
        arena.allocator(),
        &.{ "-o", "a", "-o", "-", "http://x/one", "http://x/two" },
        &env,
        null,
    );
    try testing.expectEqualStrings("a", second.output.bodyTarget(0).file);
    try testing.expectEqual(BodyTarget.stdout, second.output.bodyTarget(1));
}

test "-o - beside -O keeps each url's own destination" {
    // Measured both orders: `curl -o - -O URL1 URL2` and `curl -O -o -
    // URL1 URL2` each pair `-` with one url and `-O` with the other, by
    // position, the same as `-o` beside `-o` does.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const dash_first = try parse(
        arena.allocator(),
        &.{ "-o", "-", "-O", "http://x/one", "http://x/two" },
        &env,
        null,
    );
    try testing.expectEqual(BodyTarget.stdout, dash_first.output.bodyTarget(0));
    try testing.expectEqual(BodyTarget.url_name, dash_first.output.bodyTarget(1));

    const dash_second = try parse(
        arena.allocator(),
        &.{ "-O", "-o", "-", "http://x/one", "http://x/two" },
        &env,
        null,
    );
    try testing.expectEqual(BodyTarget.url_name, dash_second.output.bodyTarget(0));
    try testing.expectEqual(BodyTarget.stdout, dash_second.output.bodyTarget(1));
}

test "-o ./- still writes a file literally called -" {
    // The escape hatch. Measured: `curl -o ./- URL` writes a file named
    // `-` in the working directory, because the argument is not spelled
    // exactly `-`. `targetForOutputPath` only rewrites the exact one-byte
    // spelling, so this path reaches `output.toFile` unchanged.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-o", "./-", "http://x" }, &env, null);
    try testing.expectEqualStrings("./-", plan.output.bodyTarget(0).file);
}

test "-D - names standard output, not a file called -" {
    // Measured: `curl -D - -o /dev/null URL` writes the head block to
    // standard output and creates no file called `-`. This is the same
    // mistake `-o -` had, in the second place zurl reads a `-` argument as
    // a destination.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-D", "-", "http://x" }, &env, null);
    try testing.expectEqual(HeadersTarget.stdout, plan.output.headers_file.?);
}

test "-w captures the write-out format unparsed" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-w", "%{http_code}\\n", "http://x" }, &env, null);
    try testing.expectEqualStrings("%{http_code}\\n", plan.write_out.?);
}

test "-Z and --progress-bar set their own booleans" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-Z", "--progress-bar", "http://x" }, &env, null);
    try testing.expectEqual(true, plan.parallel);
    try testing.expectEqual(true, plan.progress_bar);
}

test "--connect-timeout rejects a non-numeric argument" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    const result = parse(arena.allocator(), &.{ "--connect-timeout", "soon", "http://x" }, &env, &fault);
    try testing.expectError(error.InvalidNumber, result);
    try testing.expect(std.mem.indexOf(u8, fault.message, "soon") != null);
}

test "-X rejects a method zurl does not know" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    const result = parse(arena.allocator(), &.{ "-X", "FROBNICATE", "http://x" }, &env, &fault);
    try testing.expectError(error.InvalidMethod, result);
    try testing.expect(std.mem.indexOf(u8, fault.message, "FROBNICATE") != null);
}

test "-X on a mail url is a whole command line and not an HTTP method" {
    // **A mail protocol reads `-X` as a command.** `TOP 1 0` and
    // `FETCH 1 BODY[HEADER]` are values a user may write, and neither is
    // an HTTP method, so the refusal above cannot happen at the flag: it
    // has to wait until every url has been seen.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const rows = [_]struct { url: []const u8, value: []const u8 }{
        .{ .url = "pop3://h/", .value = "TOP 1 0" },
        .{ .url = "pop3s://h/", .value = "STAT" },
        .{ .url = "imap://h/INBOX", .value = "FETCH 1 BODY[HEADER]" },
        .{ .url = "imaps://h/INBOX", .value = "SEARCH ALL" },
        .{ .url = "smtp://h/", .value = "VRFY bob" },
        .{ .url = "smtps://h/", .value = "NOOP" },
        // The scheme is read without regard to case, the way every other
        // scheme comparison in this program is.
        .{ .url = "IMAP://h/INBOX", .value = "NOOP" },
    };
    for (rows) |row| {
        const plan = try parse(arena.allocator(), &.{ "-X", row.value, row.url }, &env, null);
        try testing.expectEqualStrings(row.value, plan.options.custom_request.?);
        // Nothing named a method, so the HTTP one stays the default.
        try testing.expectEqual(std.http.Method.GET, plan.options.method);
    }
}

test "-X names a method for every url, and the mail urls do not change that" {
    // A value that is an HTTP method fills both fields whatever the url
    // is, so `-X POST http://x` is unchanged and `-X POST smtp://h/` sends
    // `POST` as an smtp command.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-X", "POST", "http://x" }, &env, null);
    try testing.expectEqual(std.http.Method.POST, plan.options.method);
    try testing.expectEqualStrings("POST", plan.options.custom_request.?);
}

test "one http url among mail urls brings the -X refusal back" {
    // **The refusal is about the run and not about one url.** A run that
    // sends `FETCH` to an http server is a run that was typed wrongly, so
    // it stops before any socket.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    try testing.expectError(error.InvalidMethod, parse(
        arena.allocator(),
        &.{ "-X", "FETCH", "imap://h/INBOX", "http://x" },
        &env,
        &fault,
    ));
    try testing.expect(std.mem.indexOf(u8, fault.message, "FETCH") != null);

    // And a run with no url at all keeps it too: a method zurl does not
    // know is a mistake whichever url follows.
    var second: Fault = .{};
    try testing.expectError(error.InvalidMethod, parse(
        arena.allocator(),
        &.{ "-X", "FETCH" },
        &env,
        &second,
    ));
}

test "the last -X wins, and a later method clears an earlier refusal" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(
        arena.allocator(),
        &.{ "-X", "FROBNICATE", "-X", "PUT", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(std.http.Method.PUT, plan.options.method);
    try testing.expectEqualStrings("PUT", plan.options.custom_request.?);
}

test "--mail-from names one sender and --mail-rcpt names each recipient in order" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{
        "--mail-from", "a@b.example",
        "--mail-rcpt", "c@d.example",
        "--mail-rcpt", "e@f.example",
        "smtp://h/",
    }, &env, null);

    try testing.expectEqualStrings("a@b.example", plan.options.mail_from.?);
    try testing.expectEqual(@as(usize, 2), plan.options.mail_rcpt.len);
    try testing.expectEqualStrings("c@d.example", plan.options.mail_rcpt[0]);
    try testing.expectEqualStrings("e@f.example", plan.options.mail_rcpt[1]);
}

test "the last --mail-from wins, because a message has one sender" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{
        "--mail-from", "first@example",
        "--mail-from", "second@example",
        "smtp://h/",
    }, &env, null);
    try testing.expectEqualStrings("second@example", plan.options.mail_from.?);
}

test "a run with no mail flag names no sender and no recipient" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(?[]const u8, null), plan.options.mail_from);
    try testing.expectEqual(@as(usize, 0), plan.options.mail_rcpt.len);
}

test "a recipient list past the bound is refused" {
    // Each recipient is its own `RCPT TO` and its own round trip, so an
    // unbounded list from a config file would be an unbounded session.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    var i: usize = 0;
    while (i <= max_recipients) : (i += 1) {
        try argv.append(testing.allocator, "--mail-rcpt");
        try argv.append(testing.allocator, "c@d.example");
    }
    try argv.append(testing.allocator, "smtp://h/");

    var fault: Fault = .{};
    try testing.expectError(
        error.TooManyRecipients,
        parse(arena.allocator(), argv.items, &env, &fault),
    );
    try testing.expect(std.mem.indexOf(u8, fault.message, "--mail-rcpt") != null);

    // One list at the bound is taken. The slice ends on a whole flag and
    // value pair, so nothing is left half given.
    const ok = try parse(
        arena.allocator(),
        argv.items[0 .. max_recipients * 2],
        &env,
        null,
    );
    try testing.expectEqual(max_recipients, ok.options.mail_rcpt.len);
}

// --- Config files ---

/// Builds `a` followed by `b` into one token slice, the shape
/// `parseWithConfigFiles` hands `parse`: config-file tokens first, the
/// real command line after.
fn concatTokens(
    arena: Allocator,
    a: []const []const u8,
    b: []const []const u8,
) Allocator.Error![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    try list.appendSlice(arena, a);
    try list.appendSlice(arena, b);
    return list.toOwnedSlice(arena);
}

/// Expands one config file's text for a test and returns its tokens.
///
/// `expandConfig` takes the pieces `parseWithConfigFiles` has to hand: a
/// file name for the attribution, a `TokenList` that keeps a source beside
/// each token, and a place to put the warnings a default file earns. A
/// test that only wants the tokens says so here, once.
fn testExpand(
    arena: Allocator,
    env: *std.process.Environ.Map,
    text: []const u8,
    kind: ConfigKind,
    warnings: *std.ArrayList([]const u8),
    fault: ?*Fault,
) (ParseError || Allocator.Error)![]const []const u8 {
    var list: TokenList = .{};
    try expandConfig(arena, "test.conf", text, kind, env, &list, warnings, fault);
    return list.tokens.toOwnedSlice(arena);
}

test "a config file supplies options" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var warnings: std.ArrayList([]const u8) = .empty;
    const config_tokens = try testExpand(
        arena.allocator(),
        &env,
        "user-agent \"zurl-config/1\"\nsilent\n",
        .named,
        &warnings,
        null,
    );
    const argv = try concatTokens(arena.allocator(), config_tokens, &.{"http://x"});

    const plan = try parse(arena.allocator(), argv, &env, null);
    try testing.expectEqualStrings("zurl-config/1", plan.options.user_agent);
    try testing.expectEqual(true, plan.silent);
}

test "a command-line flag overrides the same option from a config file" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var warnings: std.ArrayList([]const u8) = .empty;
    const config_tokens = try testExpand(
        arena.allocator(),
        &env,
        "user-agent config-agent/1\n",
        .named,
        &warnings,
        null,
    );
    const argv = try concatTokens(arena.allocator(), config_tokens, &.{
        "--user-agent", "cli-agent/1",
        "http://x",
    });

    const plan = try parse(arena.allocator(), argv, &env, null);
    try testing.expectEqualStrings("cli-agent/1", plan.options.user_agent);
}

test "-H from a config file and -H on the command line both keep their order, config first" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var warnings: std.ArrayList([]const u8) = .empty;
    const config_tokens = try testExpand(
        arena.allocator(),
        &env,
        "header \"X-From: config\"\n",
        .named,
        &warnings,
        null,
    );
    const argv = try concatTokens(arena.allocator(), config_tokens, &.{
        "-H",       "X-From: cli",
        "http://x",
    });

    const plan = try parse(arena.allocator(), argv, &env, null);
    try testing.expectEqual(@as(usize, 2), plan.options.headers.len);
    try testing.expectEqualStrings("config", plan.options.headers[0].value);
    try testing.expectEqualStrings("cli", plan.options.headers[1].value);
}

test "-q stops the default curlrc being read" {
    try testing.expect(defaultConfigDisabled(&.{ "-q", "http://x" }));
    try testing.expect(defaultConfigDisabled(&.{ "--disable", "http://x" }));
    // Not the first argument: curl's own manual ties the effect to
    // position, so this must not disable the default read.
    try testing.expect(!defaultConfigDisabled(&.{ "http://x", "-q" }));
    try testing.expect(!defaultConfigDisabled(&.{"http://x"}));
    try testing.expect(!defaultConfigDisabled(&.{}));
}

test "a missing --config file is a usage error naming the path" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    const result = parseWithConfigFiles(arena.allocator(), testing.io, &.{
        "-K",       "/nonexistent-zurl-test-config-file.conf",
        "http://x",
    }, &env, &fault);
    try testing.expectError(error.ConfigFileUnreadable, result);
    try testing.expect(std.mem.indexOf(u8, fault.message, "/nonexistent-zurl-test-config-file.conf") != null);
}

test "a config file may itself not name another config file" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;
    var fault: Fault = .{};

    const long_form = testExpand(arena.allocator(), &env, "config other.txt\n", .named, &warnings, &fault);
    try testing.expectError(error.ConfigFileNested, long_form);
    try testing.expect(std.mem.indexOf(u8, fault.message, "config") != null);
    // The sentence names the file and the line, so a user with three
    // candidate config files knows which one to open.
    try testing.expect(std.mem.indexOf(u8, fault.message, "test.conf:1:") != null);

    var fault2: Fault = .{};
    const short_form = testExpand(arena.allocator(), &env, "-K other.txt\n", .named, &warnings, &fault2);
    try testing.expectError(error.ConfigFileNested, short_form);
}

test "a config file cannot name more options than the bound allows" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;
    var fault: Fault = .{};

    var text: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i <= max_config_options) : (i += 1) {
        try text.appendSlice(arena.allocator(), "silent\n");
    }

    const result = testExpand(arena.allocator(), &env, text.items, .named, &warnings, &fault);
    try testing.expectError(error.ConfigFileTooManyOptions, result);
}

test "a config file at the option bound is accepted" {
    // The other side of the bound. A parser that refused every config
    // file, or one that refused at one option fewer, passes the test
    // above and fails this one.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;

    var text: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < max_config_options) : (i += 1) {
        try text.appendSlice(arena.allocator(), "silent\n");
    }

    const tokens = try testExpand(arena.allocator(), &env, text.items, .named, &warnings, null);
    try testing.expectEqual(max_config_options, tokens.len);
}

test "a config file's quoted value must fit the decode buffer" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;
    var fault: Fault = .{};

    const huge = "x" ** (max_config_value_bytes + 1);
    const text = try std.fmt.allocPrint(arena.allocator(), "header \"{s}\"\n", .{huge});

    const result = testExpand(arena.allocator(), &env, text, .named, &warnings, &fault);
    try testing.expectError(error.ConfigFileMalformed, result);
    // The message says `quoted`, because only a quoted value goes through
    // the decode buffer. The same value with no quotes parses.
    try testing.expect(std.mem.indexOf(u8, fault.message, "quoted") != null);

    const unquoted = try std.fmt.allocPrint(arena.allocator(), "header {s}\n", .{huge});
    const tokens = try testExpand(arena.allocator(), &env, unquoted, .named, &warnings, null);
    try testing.expectEqual(@as(usize, 2), tokens.len);
}

test "a quoted value at the decode bound is accepted" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;

    const at_bound = "x" ** max_config_value_bytes;
    const text = try std.fmt.allocPrint(arena.allocator(), "header \"{s}\"\n", .{at_bound});

    const tokens = try testExpand(arena.allocator(), &env, text, .named, &warnings, null);
    try testing.expectEqual(@as(usize, 2), tokens.len);
    try testing.expectEqual(max_config_value_bytes, tokens[1].len);
}

test "a -K file's unknown option is a usage fault naming the file and the line" {
    // Measured against curl 8.21.0: an unknown option in a `-K` file
    // exits 2, and curl names the file and the line in its own message,
    // `curl: rc.conf:1 config file option 'evIL' is unknown`.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;
    var fault: Fault = .{};

    const tokens = try testExpand(
        arena.allocator(),
        &env,
        "silent\n# a comment\nevIL\n",
        .named,
        &warnings,
        &fault,
    );
    const argv = try concatTokens(arena.allocator(), tokens, &.{"http://x"});

    try testing.expectError(error.UnknownFlag, parseAttributed(
        arena.allocator(),
        argv,
        &.{},
        &env,
        &fault,
    ));
    // With no sources the message names no file, which is what a fault
    // from the command line must read like.
    try testing.expect(std.mem.indexOf(u8, fault.message, "test.conf") == null);
}

test "a config file option's fault names the file and the line it came from" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;

    var list: TokenList = .{};
    try expandConfig(
        arena.allocator(),
        "rc.conf",
        "silent\n# a comment\nevIL\n",
        .named,
        &env,
        &list,
        &warnings,
        null,
    );
    try list.appendArgv(arena.allocator(), &.{"http://x"});

    var fault: Fault = .{};
    try testing.expectError(error.UnknownFlag, parseAttributed(
        arena.allocator(),
        try list.tokens.toOwnedSlice(arena.allocator()),
        try list.sources.toOwnedSlice(arena.allocator()),
        &env,
        &fault,
    ));
    try testing.expectEqualStrings("zurl: rc.conf:3: unknown flag: '--evIL'", fault.message);
    try testing.expectEqualStrings("rc.conf", fault.source.?.file);
    try testing.expectEqual(@as(u32, 3), fault.source.?.line);
}

test "a fault the command line caused names no file" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    try testing.expectError(
        error.UnknownFlag,
        parse(arena.allocator(), &.{ "--evIL", "http://x" }, &env, &fault),
    );
    try testing.expectEqualStrings("zurl: unknown flag: '--evIL'", fault.message);
    try testing.expectEqual(@as(?Source, null), fault.source);
}

test "an option name a config file made up cannot forge a terminal line" {
    // `lib/zurl-core/config.zig` bounds the name and `src/cli/safe.zig`
    // bounds and cleans what reaches standard error. Without both, a
    // config file could put its own bytes on the user's terminal: escape
    // sequences that set a colour, a bell, and a newline that draws a
    // second line reading like one of zurl's own.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;
    var fault: Fault = .{};

    var list: TokenList = .{};
    try expandConfig(
        arena.allocator(),
        "rc.conf",
        "ev\x1b[31mIL\x07\n",
        .named,
        &env,
        &list,
        &warnings,
        null,
    );
    try list.appendArgv(arena.allocator(), &.{"http://x"});

    try testing.expectError(error.UnknownFlag, parseAttributed(
        arena.allocator(),
        try list.tokens.toOwnedSlice(arena.allocator()),
        try list.sources.toOwnedSlice(arena.allocator()),
        &env,
        &fault,
    ));
    try testing.expectEqualStrings("zurl: rc.conf:1: unknown flag: '--ev?[31mIL?'", fault.message);
    try testing.expect(std.mem.indexOfScalar(u8, fault.message, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, fault.message, 0x07) == null);
}

test "an unbounded option name cannot put a config file's bytes on standard error" {
    // 200 000 bytes on one line used to reach standard error whole. The
    // name bound refuses the line, and the sentence that replaces it is a
    // fixed one.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;
    var fault: Fault = .{};

    const text = try std.fmt.allocPrint(arena.allocator(), "-{s}\n", .{"Q" ** 200_000});
    const result = testExpand(arena.allocator(), &env, text, .named, &warnings, &fault);

    try testing.expectError(error.ConfigFileMalformed, result);
    try testing.expect(fault.message.len < 200);
    try testing.expect(std.mem.indexOf(u8, fault.message, "option name longer than") != null);
    try testing.expect(std.mem.indexOf(u8, fault.message, "test.conf:1:") != null);
}

test "the default config file warns about an option this build cannot use and goes on" {
    // Measured against curl 8.21.0. A `~/.curlrc` holding one unknown
    // option printed a warning naming the file and the line, fetched the
    // url, and exited 0. The same for a missing parameter and for a bad
    // numeric parameter. The same file passed to `-K` exited 2.
    //
    // zurl treating the default file as fatal made every run on such an
    // account fail before any transfer, and `compressed` is an ordinary
    // line of a real `~/.curlrc`.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var warnings: std.ArrayList([]const u8) = .empty;

    const tokens = try testExpand(
        arena.allocator(),
        &env,
        "silent\nevIL\nuser-agent\nmax-redirs abc\nfail\n",
        .default,
        &warnings,
        null,
    );

    // The two options this build can use survive, and nothing else does.
    try testing.expectEqual(@as(usize, 2), tokens.len);
    try testing.expectEqualStrings("--silent", tokens[0]);
    try testing.expectEqualStrings("--fail", tokens[1]);

    // One warning for each dropped option, each naming its own line.
    try testing.expectEqual(@as(usize, 3), warnings.items.len);
    try testing.expect(std.mem.indexOf(u8, warnings.items[0], "test.conf:2:") != null);
    try testing.expect(std.mem.indexOf(u8, warnings.items[0], "unknown flag") != null);
    try testing.expect(std.mem.indexOf(u8, warnings.items[1], "test.conf:3:") != null);
    try testing.expect(std.mem.indexOf(u8, warnings.items[1], "needs an argument") != null);
    try testing.expect(std.mem.indexOf(u8, warnings.items[2], "test.conf:4:") != null);
    try testing.expect(std.mem.indexOf(u8, warnings.items[2], "not a valid number") != null);
}

test "a --cacert in the default config file that does not exist warns instead of stopping" {
    // The one fault raised after the parse, over the finished plan. It
    // needs its own path, because `optionIsUsable` parses an option on its
    // own and a parse cannot tell whether a file exists.
    //
    // Measured: a `~/.curlrc` holding `cacert /nope/x.pem` made curl
    // 8.21.0 warn, naming the file and the line, and run the transfer.
    var arena = testArena();
    defer arena.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = ".curlrc",
        .data = "cacert /nonexistent-zurl-test-ca.pem\n",
    });
    const home = try std.fmt.allocPrint(arena.allocator(), ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("HOME", home);

    var fault: Fault = .{};
    const plan = try parseWithConfigFiles(
        arena.allocator(),
        testing.io,
        &.{"http://x"},
        &env,
        &fault,
    );

    // The flag is dropped, so the trust roots stay the ones a run with no
    // flag would have used.
    try testing.expectEqual(@as(?[]const u8, null), plan.options.ca.cacert);
    try testing.expectEqual(@as(usize, 1), plan.warnings.len);
    try testing.expect(std.mem.indexOf(u8, plan.warnings[0], ".curlrc:1:") != null);
    try testing.expect(std.mem.indexOf(u8, plan.warnings[0], "--cacert") != null);

    // The same file under `-K` is a command line, and stops the run.
    var arena2 = testArena();
    defer arena2.deinit();
    const named = try std.fmt.allocPrint(arena2.allocator(), "{s}/.curlrc", .{home});
    var fault2: Fault = .{};
    try testing.expectError(error.CacertMissing, parseWithConfigFiles(
        arena2.allocator(),
        testing.io,
        &.{ "-q", "-K", named, "http://x" },
        &env,
        &fault2,
    ));
    try testing.expect(std.mem.indexOf(u8, fault2.message, ".curlrc:1:") != null);
}

/// A value each flag accepts, for the walk over `flag_table`.
///
/// The switch is exhaustive on purpose: Zig refuses it with no `else`
/// arm when a `FlagId` has no case, so a flag added to the table cannot
/// join it without a value the walk can drive it with. That is the second
/// half of the guard. The first half is that one table row carries both
/// spellings, so the two cannot drift; this half is that no row can be
/// added and left untested.
fn sampleValue(id: FlagId) []const u8 {
    return switch (id) {
        .method => "HEAD",
        .data_ascii => "a=1",
        .data_raw => "b=2",
        .data_binary => "c=3",
        .data_urlencode => "d=4",
        .json => "{\"k\":1}",
        .form => "n=v",
        .form_string => "n=v",
        .upload_file => "up.bin",
        .header => "X-A: 1",
        .max_redirects => "3",
        .connect_timeout => "2",
        .speed_limit => "500",
        .speed_time => "20",
        .limit_rate => "2k",
        .max_filesize => "4M",
        .user => "alice:secret",
        .netrc_file => "/tmp/zurl-test.netrc",
        .user_agent => "walk/1",
        .cacert => "/tmp/zurl-test-ca.pem",
        .capath => "/tmp/zurl-test-certs",
        .output_file => "out.bin",
        .headers_file => "heads.txt",
        .write_out => "%{http_code}",
        .config_file => "/tmp/zurl-test.conf",
        .protocols => "http,https",
        .redirect_protocols => "http,https",
        .default_protocol => "https",
        .tls_max => "1.3",
        .max_time => "5",
        .continue_at => "-",
        // An `=` makes this cookie text and not a file name, so the walk
        // never asks for a file that is not there.
        .cookie => "walk=1",
        .cookie_jar => "jar.txt",
        .range => "0-99",
        .retry => "2",
        .retry_delay => "1",
        .retry_max_time => "30",
        .referer => "http://referer.example/",
        .resolve => "example.test:443:127.0.0.1",
        .connect_to => "example.test:443:127.0.0.1:8443",
        .parallel_max => "4",
        .proxy => "http://127.0.0.1:3128",
        .noproxy => "walk.example",
        .proxy_user => "bob:proxypw",
        .proxy_cacert => "/tmp/zurl-test-proxy-ca.pem",
        .proxy_capath => "/tmp/zurl-test-proxy-certs",
        .socks4 => "127.0.0.1:1080",
        .socks4a => "127.0.0.1:1080",
        .socks5 => "127.0.0.1:1080",
        .socks5_hostname => "127.0.0.1:1080",
        .mail_from => "sender@example.test",
        .mail_rcpt => "recipient@example.test",
        .sasl_authzid => "admin",
        .login_options => "AUTH=PLAIN",
        .mqtt_client_id => "zurl-walk-1",
        .mqtt_messages => "2",
        .rtsp_request => "DESCRIBE",
        .rtsp_session_id => "12345678",
        .rtsp_stream_uri => "rtsp://example.test/stream/trackID=0",
        .rtsp_transport => "RTP/AVP;unicast;client_port=4588-4589",
        .url_arg => "http://second.example.test/",
        .stderr_file => "messages.txt",
        .output_dir => "out",
        .create_file_mode => "0600",
        .etag_compare => "etag.txt",
        .etag_save => "etag.txt",
        // A shape `timecond.readDate` reads, so the walk drives the flag
        // and never falls through to the file check.
        .time_cond => "21 Oct 2015 07:28:00 GMT",
        .rate => "2/s",
        .parallel_max_host => "2",
        .expect100_timeout => "1",
        .happy_eyeballs_timeout_ms => "200",
        .keepalive_time => "60",
        .keepalive_cnt => "9",
        // The seven below are refused by name, not at the parse. The walk
        // still drives each with a value that reads, because a refusal
        // that happened at the parse instead would hide a spelling fault
        // behind it. See `refuse` and `Plan.unsupported_flag`.
        .client_cert => "/tmp/zurl-test-client.pem",
        .client_cert_type => "PEM",
        .client_key => "/tmp/zurl-test-client.key",
        .client_key_type => "PEM",
        .client_key_pass => "phrase",
        .known_hosts => "/tmp/zurl-test-known-hosts",
        .host_pub_md5 => "46cccd198fb5de207e06a590d431e5d7",
        .host_pub_sha256 => "moRo9Xfh5TVMqzcnDMFdnp9ra8zc2Ub1k1noIrv4TYs=",
        .ciphers => "ECDHE-RSA-AES128-GCM-SHA256",
        .curves => "X25519",
        .trace => "trace.txt",
        .trace_ascii => "trace.txt",
        // Every flag below takes no value at all.
        .location,
        .location_trusted,
        .form_escape,
        .get,
        .head,
        .fail_on_error,
        .fail_with_body,
        .fail_early,
        .netrc,
        .netrc_optional,
        .ca_native,
        .insecure,
        .output_url_name,
        .create_dirs,
        .no_clobber,
        .silent,
        .show_error,
        .progress_bar,
        .no_progress_meter,
        .no_buffer,
        .parallel,
        .disable_default_config,
        .compressed,
        .tls_v1_0,
        .tls_v1_1,
        .tls_v1_2,
        .tls_v1_3,
        .http_1_1,
        .http_2,
        .http2_prior_knowledge,
        .http3,
        .http3_only,
        .no_tcp_nodelay,
        .no_keepalive,
        .junk_session_cookies,
        .retry_connrefused,
        .retry_all_errors,
        .no_alpn,
        .globoff,
        .list_only,
        .ssl_required,
        .proxy_basic,
        .proxy_digest,
        .proxy_anyauth,
        .proxy_insecure,
        .verbose,
        .show_headers,
        .suppress_connect_headers,
        .trace_time,
        .trace_ids,
        .auth_basic,
        .auth_digest,
        .auth_anyauth,
        .remove_on_error,
        .remote_time,
        .remote_header_name,
        .clobber,
        .parallel_immediate,

        // The flags with behaviour that take no argument.
        .tcp_nodelay,
        .use_ascii,
        .disable_epsv,
        .tftp_no_options,
        .remote_name_all,
        .out_null,
        .skip_existing,
        .disallow_username_in_url,
        .dump_ca_embed,
        .proxy_ca_native,
        .post301,
        .post302,
        .post303,
        .follow,

        // The flags accepted that take no argument and change nothing.
        .path_as_is,
        .ftp_pasv,
        .ftp_skip_pasv_ip,
        .disable_eprt,
        .no_sessionid,
        .ssl_allow_beast,
        .proxy_ssl_allow_beast,
        .ssl_auto_client_cert,
        .proxy_ssl_auto_client_cert,
        .ssl_no_revoke,
        .ssl_revoke_best_effort,
        .false_start,
        .no_npn,
        .metalink,
        .ntlm_wb,
        .socks5_basic,
        .styled_output,
        .tcp_fastopen,
        .mptcp,

        // The flags refused that take no argument.
        .doh_insecure,
        .doh_cert_status,
        .cert_status,
        .tls_earlydata,
        .opportunistic_ssl,
        .proxy_tls_v1,
        .auth_negotiate,
        .auth_ntlm,
        .proxy_negotiate,
        .proxy_ntlm,
        .socks5_gssapi,
        .socks5_gssapi_nec,
        .sasl_ir,
        .http_0_9,
        .raw,
        .tr_encoding,
        .ignore_content_length,
        .proxy_tunnel,
        .proxy_http2,
        .proxy_http3,
        .haproxy_protocol,
        .ftp_create_dirs,
        .ftp_pret,
        .ftp_ssl_ccc,
        .ftp_ssl_control,
        .append,
        .mail_rcpt_allowfails,
        .compressed_ssh,
        .crlf,
        .xattr,
        .manual,
        => "",

        // Every flag below takes an argument, and the value here is only
        // ever read by the table walk. A refused flag still parses its
        // argument shape, so the value has to be one the flag would take.
        .tftp_blksize => "1024",
        .url_query => "walk=1",
        .oauth2_bearer => "walk-token",
        .egd_file => "/tmp/zurl-test-egd",
        .random_file => "/tmp/zurl-test-random",
        .interface_name => "lo",
        .local_port => "10000-10010",
        .dns_interface => "lo",
        .dns_ipv4_addr => "127.0.0.1",
        .dns_ipv6_addr => "::1",
        .dns_servers => "127.0.0.1",
        .doh_url => "https://dns.example/dns-query",
        .unix_socket => "/tmp/zurl-test.sock",
        .abstract_unix_socket => "zurl-test",
        .ip_tos => "lowdelay",
        .vlan_priority => "3",
        .ipfs_gateway => "http://127.0.0.1:8080",
        .crlfile => "/tmp/zurl-test.crl",
        .proxy_crlfile => "/tmp/zurl-test-proxy.crl",
        .pinnedpubkey => "sha256//AAAA",
        .proxy_pinnedpubkey => "sha256//AAAA",
        .sigalgs => "ECDSA+SHA256",
        .tls13_ciphers => "TLS_AES_128_GCM_SHA256",
        .proxy_tls13_ciphers => "TLS_AES_128_GCM_SHA256",
        .proxy_ciphers => "ECDHE-RSA-AES128-GCM-SHA256",
        .ssl_sessions => "/tmp/zurl-test.sessions",
        .ech => "true",
        .engine => "dynamic",
        .tls_auth_type => "SRP",
        .tls_user => "walk",
        .tls_password => "walkpw",
        .proxy_tls_auth_type => "SRP",
        .proxy_tls_user => "walk",
        .proxy_tls_password => "walkpw",
        .proxy_client_cert => "/tmp/zurl-test-proxy.pem",
        .proxy_client_cert_type => "PEM",
        .proxy_client_key => "/tmp/zurl-test-proxy.key",
        .proxy_client_key_type => "PEM",
        .proxy_client_key_pass => "walkpw",
        .service_name => "HTTP",
        .proxy_service_name => "HTTP",
        .delegation => "none",
        .krb => "clear",
        .socks5_gssapi_service => "rcmd",
        .aws_sigv4 => "aws:amz:us-east-1:s3",
        .request_target => "/walk",
        .alt_svc => "/tmp/zurl-test.altsvc",
        .hsts => "/tmp/zurl-test.hsts",
        .trace_config => "all",
        .proxy_header => "X-Walk: 1",
        .proxy_1_0 => "127.0.0.1:3128",
        .preproxy => "socks5://127.0.0.1:1080",
        .haproxy_clientip => "127.0.0.1",
        .ftp_account => "walk",
        .ftp_alternative_to_user => "SITE WALK",
        .ftp_method => "multicwd",
        .ftp_port => "-",
        .ftp_ssl_ccc_mode => "passive",
        .quote => "PWD",
        .mail_auth => "walk@example.test",
        .upload_flags => "seen",
        .telnet_option => "TTYPE=vt100",
        .ssh_pubkey => "/tmp/zurl-test.pub",
        .variable => "walk=1",
        .libcurl => "/tmp/zurl-test-libcurl.c",
    };
}

test "every flag row answers to every spelling it declares" {
    // **The test that stops the missing-alias bug coming back.** `-o`,
    // `-O`, and `-D` were short forms with no long form, and `-Y`, `-y`,
    // and `-#` were the mirror of that. Both shapes were possible because
    // the long forms lived in one table and the short forms in a separate
    // `switch`. There is one table now, and this walks it.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    for (flag_table) |flag| {
        try testing.expect(flag.long != null or flag.short != null);
        try testing.expectEqual(flag.takes_value, flag.arg.len > 0);

        if (flag.long) |long| {
            const found = longFlagSpec(long).?;
            try testing.expectEqual(flag.id, found.id);
            try testing.expectEqual(flag.takes_value, found.takes_value);

            var argv: [3][]const u8 = undefined;
            var argv_len: usize = 0;
            var spelling: [64]u8 = undefined;
            argv[argv_len] = try std.fmt.bufPrint(&spelling, "--{s}", .{long});
            argv_len += 1;
            if (flag.takes_value) {
                argv[argv_len] = sampleValue(flag.id);
                argv_len += 1;
            }
            argv[argv_len] = "http://x";
            argv_len += 1;
            var fault: Fault = undefined;
            _ = parse(arena.allocator(), argv[0..argv_len], &env, &fault) catch |err| {
                std.debug.print("--{s} was refused: {t}: {s}\n", .{ long, err, fault.message });
                return err;
            };
        }

        if (flag.short) |short| {
            const found = shortFlagSpec(short).?;
            try testing.expectEqual(flag.id, found.id);
            try testing.expectEqual(flag.takes_value, found.takes_value);

            var argv: [3][]const u8 = undefined;
            var argv_len: usize = 0;
            var spelling: [4]u8 = undefined;
            argv[argv_len] = try std.fmt.bufPrint(&spelling, "-{c}", .{short});
            argv_len += 1;
            if (flag.takes_value) {
                argv[argv_len] = sampleValue(flag.id);
                argv_len += 1;
            }
            argv[argv_len] = "http://x";
            argv_len += 1;
            var fault: Fault = undefined;
            _ = parse(arena.allocator(), argv[0..argv_len], &env, &fault) catch |err| {
                std.debug.print("-{c} was refused: {t}: {s}\n", .{ short, err, fault.message });
                return err;
            };
        }
    }
}

test "no flag but -k turns peer verification off, and no flag but --location-trusted trusts a redirect" {
    // **The guard on the two security answers, and it walks the whole
    // table rather than name one flag.** A flag added later that wrote
    // `options.insecure` or `options.location_trusted` by accident, or a
    // `Transfer.Options` default that flipped, fails here on the row that
    // did it and not somewhere far away.
    //
    // The walk runs every spelling of every flag, alone, and asks what
    // the resulting `Plan` says about the two fields. Only the row that
    // owns each answer may give it.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    for (flag_table) |flag| {
        var argv: [3][]const u8 = undefined;
        var argv_len: usize = 0;
        var spelling: [64]u8 = undefined;
        if (flag.long) |long| {
            argv[argv_len] = try std.fmt.bufPrint(&spelling, "--{s}", .{long});
        } else {
            argv[argv_len] = try std.fmt.bufPrint(&spelling, "-{c}", .{flag.short.?});
        }
        argv_len += 1;
        if (flag.takes_value) {
            argv[argv_len] = sampleValue(flag.id);
            argv_len += 1;
        }
        argv[argv_len] = "http://x";
        argv_len += 1;

        const plan = try parse(arena.allocator(), argv[0..argv_len], &env, null);
        if (plan.options.insecure != (flag.id == .insecure)) {
            std.debug.print("'{s}' answered the wrong way about --insecure\n", .{argv[0]});
            return error.TestUnexpectedResult;
        }
        if (plan.options.location_trusted != (flag.id == .location_trusted)) {
            std.debug.print("'{s}' answered the wrong way about --location-trusted\n", .{argv[0]});
            return error.TestUnexpectedResult;
        }
    }

    // And a command line with no flag at all keeps both answers off. This
    // is the default the two guards protect.
    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expect(!bare.options.insecure);
    try testing.expect(!bare.options.location_trusted);
    try testing.expect(bare.options.tcp_no_delay);
}

test "-k and --insecure are the same flag, and neither changes anything else" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const short = try parse(arena.allocator(), &.{ "-k", "http://x" }, &env, null);
    const long = try parse(arena.allocator(), &.{ "--insecure", "http://x" }, &env, null);
    try testing.expect(short.options.insecure);
    try testing.expect(long.options.insecure);
    // The flag turns off the certificate check and nothing else. A `-k`
    // that also let a credential cross an origin would answer a question
    // nobody asked.
    try testing.expect(!short.options.location_trusted);
    try testing.expectEqual(zurl_core.tls.MinVersion.floor, short.options.tls_min_version);
}

test "the three ssh host key flags reach the options and turn no check off" {
    // **These three decide what an sftp or an scp transfer trusts.** Each
    // one is read in `zurl_sftp` and `zurl_scp`, and a flag that carried a
    // trust decision and
    // did nothing would be worse than one that is not there. The test in
    // this file that walks the whole table already proves that none of
    // them sets `insecure`; this one proves each reaches its own field.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plain = try parse(arena.allocator(), &.{"sftp://h/f"}, &env, null);
    try testing.expectEqual(@as(?[]const u8, null), plain.options.ssh_known_hosts);
    try testing.expectEqual(@as(?[]const u8, null), plain.options.ssh_host_pub_md5);
    try testing.expectEqual(@as(?[]const u8, null), plain.options.ssh_host_pub_sha256);
    try testing.expect(!plain.options.insecure);

    const named = try parse(arena.allocator(), &.{
        "--knownhosts",    "/etc/kh",
        "--hostpubmd5",    "46cccd198fb5de207e06a590d431e5d7",
        "--hostpubsha256", "moRo9Xfh5TVMqzcnDMFdnp9ra8zc2Ub1k1noIrv4TYs=",
        "sftp://h/f",
    }, &env, null);
    try testing.expectEqualStrings("/etc/kh", named.options.ssh_known_hosts.?);
    try testing.expectEqualStrings(
        "46cccd198fb5de207e06a590d431e5d7",
        named.options.ssh_host_pub_md5.?,
    );
    try testing.expectEqualStrings(
        "moRo9Xfh5TVMqzcnDMFdnp9ra8zc2Ub1k1noIrv4TYs=",
        named.options.ssh_host_pub_sha256.?,
    );
    // **None of them is `-k`.** The one flag that skips the check is the
    // same one that skips a TLS certificate check, and a second spelling
    // for one decision is a second thing to forget.
    try testing.expect(!named.options.insecure);
}

test "--location-trusted follows a redirect the way -L does" {
    // Measured against curl 8.21.0: the flag alone, with no `-L` beside
    // it, followed a `302` and carried the credential to the target. So
    // it must set the following answer as well as the trusting one.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const trusted = try parse(arena.allocator(), &.{ "--location-trusted", "http://x" }, &env, null);
    try testing.expectEqual(
        zurl.Transfer.Redirects{ .follow = curl_default_max_redirects },
        trusted.options.redirects,
    );
    try testing.expect(trusted.options.location_trusted);

    // And `--max-redirs` still names the limit, whichever order the two
    // flags come in.
    const bounded = try parse(arena.allocator(), &.{ "--max-redirs", "3", "--location-trusted", "http://x" }, &env, null);
    try testing.expectEqual(zurl.Transfer.Redirects{ .follow = 3 }, bounded.options.redirects);
}

test "-m reads a time, and zero asks for no bound" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const bounded = try parse(arena.allocator(), &.{ "-m", "2.5", "http://x" }, &env, null);
    try testing.expectEqual(@as(i64, 2_500), bounded.max_time.duration.raw.toMilliseconds());
    try testing.expectEqual(std.Io.Clock.awake, bounded.max_time.duration.clock);

    const long = try parse(arena.allocator(), &.{ "--max-time", "1", "http://x" }, &env, null);
    try testing.expectEqual(@as(i64, 1_000), long.max_time.duration.raw.toMilliseconds());

    // Measured: `curl --max-time 0` waited for a server that answered
    // nothing, so zero is no bound and not an instant deadline.
    const unbounded = try parse(arena.allocator(), &.{ "-m", "0", "http://x" }, &env, null);
    try testing.expectEqual(std.Io.Timeout.none, unbounded.max_time);

    // With no flag at all, and that is the shape every run had before the
    // flag existed.
    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(std.Io.Timeout.none, bare.max_time);

    // A value that is not a time is a usage fault, which is curl's own
    // answer: `curl -m abc` and `curl -m -1` each exit 2.
    try testing.expectError(
        error.InvalidNumber,
        parse(arena.allocator(), &.{ "-m", "abc", "http://x" }, &env, null),
    );
    try testing.expectError(
        error.InvalidNumber,
        parse(arena.allocator(), &.{ "-m", "-1", "http://x" }, &env, null),
    );
}

test "-C reads an offset, and - asks for the size of the file" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const from_file = try parse(arena.allocator(), &.{ "-C", "-", "http://x" }, &env, null);
    try testing.expectEqual(ResumeAt.file_size, from_file.resume_at.?);

    const named = try parse(arena.allocator(), &.{ "--continue-at", "512", "http://x" }, &env, null);
    try testing.expectEqual(@as(u64, 512), named.resume_at.?.offset);

    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(?ResumeAt, null), bare.resume_at);

    // Measured: `curl -C abc` exits 2.
    try testing.expectError(
        error.InvalidNumber,
        parse(arena.allocator(), &.{ "-C", "abc", "http://x" }, &env, null),
    );
}

test "--fail and --fail-with-body clear each other, and the last one wins" {
    // Measured against curl 8.21.0 with a loopback server answering `404`
    // with a body: `--fail --fail-with-body` writes the body and
    // `--fail-with-body --fail` does not. Both exit 22.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const with_body = try parse(arena.allocator(), &.{ "--fail", "--fail-with-body", "http://x" }, &env, null);
    try testing.expect(with_body.fail_with_body);
    try testing.expect(!with_body.options.fail_on_error);

    const without = try parse(arena.allocator(), &.{ "--fail-with-body", "--fail", "http://x" }, &env, null);
    try testing.expect(!without.fail_with_body);
    try testing.expect(without.options.fail_on_error);
}

test "--netrc, -n, and --netrc-optional each name their own policy" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const off = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(NetrcMode.off, off.netrc_mode);

    const required = try parse(arena.allocator(), &.{ "--netrc", "http://x" }, &env, null);
    try testing.expectEqual(NetrcMode.required, required.netrc_mode);

    const short = try parse(arena.allocator(), &.{ "-n", "http://x" }, &env, null);
    try testing.expectEqual(NetrcMode.required, short.netrc_mode);

    const optional = try parse(arena.allocator(), &.{ "--netrc-optional", "http://x" }, &env, null);
    try testing.expectEqual(NetrcMode.optional, optional.netrc_mode);

    // `--netrc-file` names a file and keeps its own field, so the two
    // never write over each other.
    const named = try parse(arena.allocator(), &.{ "--netrc-file", "/tmp/x", "--netrc", "http://x" }, &env, null);
    try testing.expectEqual(NetrcMode.required, named.netrc_mode);
    try testing.expectEqualStrings("/tmp/x", named.netrc_path.?);
}

test "the accept-only flags reach a Plan that asks for nothing new" {
    // Each of these is accepted so a curl command line still runs. Four
    // of them change nothing at all, and `--no-tcp-nodelay` is the one
    // that does: zurl sets `TCP_NODELAY` by default, so the flag has
    // something to turn off.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const quiet = try parse(arena.allocator(), &.{
        "--http1.1", "--http2", "--no-keepalive", "-N", "http://x",
    }, &env, null);
    try testing.expect(quiet.options.tcp_no_delay);
    try testing.expect(!quiet.silent);
    try testing.expect(!quiet.no_progress_meter);

    const nagling = try parse(arena.allocator(), &.{ "--no-tcp-nodelay", "http://x" }, &env, null);
    try testing.expect(!nagling.options.tcp_no_delay);

    // `--no-progress-meter` is not `-s`. It hides the meter and keeps
    // every message, measured against curl 8.21.0 on a refused
    // connection.
    const no_meter = try parse(arena.allocator(), &.{ "--no-progress-meter", "http://x" }, &env, null);
    try testing.expect(no_meter.no_progress_meter);
    try testing.expect(!no_meter.silent);
}

test "no two flag rows claim one spelling" {
    // A duplicate long name would make the second row unreachable, and a
    // duplicate short letter would make it silently take the first row's
    // effect. Both are the same class of fault the table exists to stop.
    for (flag_table, 0..) |a, i| {
        for (flag_table[i + 1 ..]) |b| {
            if (a.long != null and b.long != null) {
                try testing.expect(!std.mem.eql(u8, a.long.?, b.long.?));
            }
            if (a.short != null and b.short != null) {
                try testing.expect(a.short.? != b.short.?);
            }
        }
    }
}

test "a flag this build cannot run is refused by name and never by its argument" {
    // **The rule this test exists to hold.** `--pass` carries a
    // passphrase, and a refusal that echoed the argument the user typed
    // would write that passphrase to standard error, into a CI log, and
    // into a journal, over the one flag whose whole purpose is to carry a
    // secret. `src/cli/safe.zig` masks a password inside a *url* and has
    // no rule that could find this one, so the name has to come from
    // `flag_table` and never from argv.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "--pass=hunter2", "http://x" }, &env, null);
    const refused = plan.unsupported_flag orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("--pass", refused.flag);
    try testing.expect(std.mem.indexOf(u8, refused.flag, "hunter2") == null);
    try testing.expect(std.mem.indexOf(u8, refused.reason, "hunter2") == null);
}

test "every flag this build refuses says so, and says why" {
    // Each of these asks for something that fails quietly when it is
    // accepted and dropped: a client certificate that never goes out
    // reads as a server that turned it down, and a cipher list that
    // changed nothing reads as a policy that was applied. So each stops
    // the run instead. `src/main.zig` prints the sentence.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const Case = struct { argv: []const []const u8, name: []const u8 };
    const cases = [_]Case{
        .{ .argv = &.{ "--cert", "c.pem", "http://x" }, .name = "--cert" },
        .{ .argv = &.{ "-E", "c.pem", "http://x" }, .name = "--cert" },
        .{ .argv = &.{ "--cert-type", "PEM", "http://x" }, .name = "--cert-type" },
        .{ .argv = &.{ "--key", "c.key", "http://x" }, .name = "--key" },
        .{ .argv = &.{ "--key-type", "PEM", "http://x" }, .name = "--key-type" },
        .{ .argv = &.{ "--pass", "phrase", "http://x" }, .name = "--pass" },
        .{ .argv = &.{ "--ciphers", "AES", "http://x" }, .name = "--ciphers" },
        .{ .argv = &.{ "--curves", "X25519", "http://x" }, .name = "--curves" },
        .{ .argv = &.{ "--trace", "t.txt", "http://x" }, .name = "--trace" },
        .{ .argv = &.{ "--trace-ascii", "t.txt", "http://x" }, .name = "--trace-ascii" },
        .{ .argv = &.{ "--trace-time", "http://x" }, .name = "--trace-time" },
        .{ .argv = &.{ "--trace-ids", "http://x" }, .name = "--trace-ids" },
    };

    for (cases) |case| {
        // The parse itself succeeds. The refusal is a decision the run
        // makes, not a spelling fault, and folding the two together would
        // hide a mistyped flag behind a refusal.
        const plan = try parse(arena.allocator(), case.argv, &env, null);
        const refused = plan.unsupported_flag orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(case.name, refused.flag);
        try testing.expect(refused.reason.len > 0);
    }
}

test "the first flag this build cannot run is the one reported" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(
        arena.allocator(),
        &.{ "--ciphers", "AES", "--cert", "c.pem", "http://x" },
        &env,
        null,
    );
    try testing.expectEqualStrings("--ciphers", plan.unsupported_flag.?.flag);
}

test "a command line with no refused flag names none" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-v", "http://x" }, &env, null);
    try testing.expectEqual(@as(?UnsupportedFlag, null), plan.unsupported_flag);
}

test "--url adds a url and keeps the place it was typed in" {
    // `OutputSpec.bodyTarget` pairs a url with an `-o` by position, so a
    // `--url` that jumped the queue would write another url's file.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(
        arena.allocator(),
        &.{ "-o", "a", "--url", "http://one", "http://two" },
        &env,
        null,
    );
    try testing.expectEqual(@as(usize, 2), plan.urls.len);
    try testing.expectEqualStrings("http://one", plan.urls[0]);
    try testing.expectEqualStrings("http://two", plan.urls[1]);
    try testing.expectEqualStrings("a", plan.output.bodyTarget(0).file);
    try testing.expectEqual(BodyTarget.stdout, plan.output.bodyTarget(1));
}

test "--clobber and --no-clobber read in either order, and the last one wins" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    try testing.expect((try parse(a, &.{ "--no-clobber", "http://x" }, &env, null)).no_clobber);
    try testing.expect(!(try parse(a, &.{ "--clobber", "http://x" }, &env, null)).no_clobber);
    try testing.expect(!(try parse(a, &.{ "--no-clobber", "--clobber", "http://x" }, &env, null)).no_clobber);
    try testing.expect((try parse(a, &.{ "--clobber", "--no-clobber", "http://x" }, &env, null)).no_clobber);
    // Overwriting is the default, so a command line naming neither is the
    // same as one naming `--clobber`.
    try testing.expect(!(try parse(a, &.{"http://x"}, &env, null)).no_clobber);
}

test "--create-file-mode reads an octal mode and refuses what is not one" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    try testing.expectEqual(
        @as(?u32, 0o600),
        (try parse(a, &.{ "--create-file-mode", "0600", "http://x" }, &env, null)).create_file_mode,
    );
    // With no leading zero too, which is how a person often types one.
    try testing.expectEqual(
        @as(?u32, 0o644),
        (try parse(a, &.{ "--create-file-mode", "644", "http://x" }, &env, null)).create_file_mode,
    );
    // And a flag nobody gave leaves the default of the platform.
    try testing.expectEqual(
        @as(?u32, null),
        (try parse(a, &.{"http://x"}, &env, null)).create_file_mode,
    );

    // A digit no octal number holds, and a number above every permission
    // bit, are both usage faults. A user who typed one learns it before a
    // transfer runs, not after a file lands with the wrong mode.
    var fault: Fault = .{};
    try testing.expectError(error.InvalidNumber, parse(
        a,
        &.{ "--create-file-mode", "0999", "http://x" },
        &env,
        &fault,
    ));
    try testing.expect(std.mem.indexOf(u8, fault.message, "octal") != null);
    try testing.expectError(error.InvalidNumber, parse(
        a,
        &.{ "--create-file-mode", "77777", "http://x" },
        &env,
        null,
    ));
}

test "the three origin authentication flags each choose one mode" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    // No flag is `--basic`, which sends `Basic` with the first request.
    try testing.expectEqual(
        Transfer.AuthMode.basic,
        (try parse(a, &.{"http://x"}, &env, null)).options.auth_mode,
    );
    try testing.expectEqual(
        Transfer.AuthMode.basic,
        (try parse(a, &.{ "--basic", "http://x" }, &env, null)).options.auth_mode,
    );
    try testing.expectEqual(
        Transfer.AuthMode.digest,
        (try parse(a, &.{ "--digest", "http://x" }, &env, null)).options.auth_mode,
    );
    try testing.expectEqual(
        Transfer.AuthMode.any,
        (try parse(a, &.{ "--anyauth", "http://x" }, &env, null)).options.auth_mode,
    );
    // The last one wins, the way the last of any other pair does.
    try testing.expectEqual(
        Transfer.AuthMode.basic,
        (try parse(a, &.{ "--digest", "--basic", "http://x" }, &env, null)).options.auth_mode,
    );
}

test "the four waits this build does not keep still check their arguments" {
    // Accepted and doing nothing is not the same as unread. A user who
    // typed a number wrong learns it here, which is the only place the
    // number is ever looked at.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const good = [_][]const []const u8{
        &.{ "--expect100-timeout", "1.5", "http://x" },
        &.{ "--happy-eyeballs-timeout-ms", "200", "http://x" },
        &.{ "--keepalive-time", "60", "http://x" },
        &.{ "--keepalive-cnt", "9", "http://x" },
    };
    for (good) |argv| _ = try parse(a, argv, &env, null);

    const bad = [_][]const []const u8{
        &.{ "--expect100-timeout", "soon", "http://x" },
        &.{ "--happy-eyeballs-timeout-ms", "soon", "http://x" },
        &.{ "--keepalive-time", "soon", "http://x" },
        &.{ "--keepalive-cnt", "soon", "http://x" },
    };
    for (bad) |argv| try testing.expectError(error.InvalidNumber, parse(a, argv, &env, null));
}

test "-v, -i, and the output flags reach the plan" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const plan = try parse(a, &.{
        "-v",
        "-i",
        "-R",
        "--remove-on-error",
        "--output-dir",
        "downloads",
        "--stderr",
        "log.txt",
        "http://x",
    }, &env, null);
    try testing.expect(plan.verbose);
    try testing.expect(plan.show_headers);
    try testing.expect(plan.remote_time);
    try testing.expect(plan.remove_on_error);
    try testing.expectEqualStrings("downloads", plan.output_dir.?);
    try testing.expectEqualStrings("log.txt", plan.stderr_path.?);

    // `--include` is curl's older spelling of `-i` and reaches the same
    // field, so a script written either way works.
    try testing.expect((try parse(a, &.{ "--include", "http://x" }, &env, null)).show_headers);
    try testing.expect((try parse(a, &.{ "--show-headers", "http://x" }, &env, null)).show_headers);
}

test "-J is captured under both spellings and is off with no flag" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    try testing.expect((try parse(a, &.{ "-J", "http://x" }, &env, null)).remote_header_name);
    try testing.expect((try parse(a, &.{ "--remote-header-name", "http://x" }, &env, null)).remote_header_name);
    try testing.expect(!(try parse(a, &.{"http://x"}, &env, null)).remote_header_name);
}

test "-J and -C are refused together, the way curl refuses them" {
    // **The two flags disagree about the order of the work.** `-C` puts a
    // `Range` on the request, and `-J` does not learn which file it is
    // adding to until the answer comes back. Measured against curl
    // 8.21.0: `curl -OJ -C - URL` prints `--continue-at and
    // --remote-header-name cannot be combined` and exits 2 with no socket
    // opened.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    var fault: Fault = .{};
    try testing.expectError(error.ConflictingResumeAndHeaderName, parse(
        a,
        &.{ "-O", "-J", "-C", "-", "http://x" },
        &env,
        &fault,
    ));
    try testing.expect(std.mem.indexOf(u8, fault.message, "-J") != null);
    try testing.expect(std.mem.indexOf(u8, fault.message, "-C") != null);

    // In either order, because the check runs after the whole command
    // line has been read.
    try testing.expectError(error.ConflictingResumeAndHeaderName, parse(
        a,
        &.{ "-C", "100", "-J", "http://x" },
        &env,
        null,
    ));

    // And each one alone still parses.
    _ = try parse(a, &.{ "-J", "http://x" }, &env, null);
    _ = try parse(a, &.{ "-C", "-", "http://x" }, &env, null);
}

test "--etag-compare and --etag-save keep their paths and open nothing" {
    // `parse` does no I/O, so a path that does not exist still parses.
    // `src/main.zig` reads the one and `src/cli/run.zig` writes the other.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const plan = try parse(a, &.{
        "--etag-compare", "/nope/in.txt",
        "--etag-save",    "/nope/out.txt",
        "http://x",
    }, &env, null);
    try testing.expectEqualStrings("/nope/in.txt", plan.etag_compare.?);
    try testing.expectEqualStrings("/nope/out.txt", plan.etag_save.?);

    // The last of two wins, which is what curl does with two of one flag.
    const twice = try parse(a, &.{
        "--etag-save", "first.txt",
        "--etag-save", "second.txt",
        "http://x",
    }, &env, null);
    try testing.expectEqualStrings("second.txt", twice.etag_save.?);

    // No flag leaves both null, and the wire bytes stay what they were
    // before the pair existed.
    const bare = try parse(a, &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(?[]const u8, null), bare.etag_compare);
    try testing.expectEqual(@as(?[]const u8, null), bare.etag_save);
}

test "-z keeps its argument raw, prefix and all" {
    // The prefix decides the header and the rest may name a file, so
    // neither half can be read here: reading a file's time is I/O, and
    // `parse` does none. `src/cli/timecond.zig` splits it and
    // `src/main.zig` resolves it.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings(
        "-21 Oct 2015 07:28:00 GMT",
        (try parse(a, &.{ "-z", "-21 Oct 2015 07:28:00 GMT", "http://x" }, &env, null)).time_cond.?,
    );
    try testing.expectEqualStrings(
        "somefile",
        (try parse(a, &.{ "--time-cond", "somefile", "http://x" }, &env, null)).time_cond.?,
    );
    // A value that is not a date at all still parses. curl warns at the
    // transfer rather than refuse the command line, measured, and so
    // does zurl.
    try testing.expectEqualStrings(
        "gibberish",
        (try parse(a, &.{ "-z", "gibberish", "http://x" }, &env, null)).time_cond.?,
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        (try parse(a, &.{"http://x"}, &env, null)).time_cond,
    );
}

test "--rate reads curl's own grammar and refuses what curl refuses" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    const waitFor = struct {
        fn f(alloc: Allocator, e: *std.process.Environ.Map, text: []const u8) !?u64 {
            return (try parse(alloc, &.{ "--rate", text, "http://x" }, e, null)).rate_wait_ms;
        }
    }.f;

    // Every accepted line ran under curl 8.21.0. The wait is the unit
    // divided by the count.
    try testing.expectEqual(@as(?u64, 500), try waitFor(a, &env, "2/s"));
    try testing.expectEqual(@as(?u64, 6000), try waitFor(a, &env, "10/m"));
    try testing.expectEqual(@as(?u64, 3600000), try waitFor(a, &env, "1/h"));
    try testing.expectEqual(@as(?u64, 86400000), try waitFor(a, &env, "1/d"));
    // An argument with no unit is per hour, which is curl's documented
    // default and what `--rate 3` measured as.
    try testing.expectEqual(@as(?u64, 1200000), try waitFor(a, &env, "3"));
    // The ceiling, which is the same rate under every unit.
    try testing.expectEqual(@as(?u64, 1), try waitFor(a, &env, "1000/s"));
    try testing.expectEqual(@as(?u64, 1), try waitFor(a, &env, "60000/m"));

    // And no flag leaves the run unpaced.
    try testing.expectEqual(
        @as(?u64, null),
        (try parse(a, &.{"http://x"}, &env, null)).rate_wait_ms,
    );

    // Each of these made curl exit 2 before any socket opened.
    var fault: Fault = .{};
    const refused = [_][]const u8{ "0", "2/x", "5/S", "abc", "-1", "1001/s", "60001/m", "2/", "/s", "" };
    for (refused) |text| {
        _ = parse(a, &.{ "--rate", text, "http://x" }, &env, &fault) catch continue;
        std.debug.print("--rate '{s}' was accepted, and curl refuses it\n", .{text});
        return error.TestUnexpectedResult;
    }
}

test "--parallel-max-host reads a number and --parallel-immediate takes none" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    const a = arena.allocator();

    try testing.expectEqual(
        @as(?usize, 2),
        (try parse(a, &.{ "--parallel-max-host", "2", "http://x" }, &env, null)).parallel_max_host,
    );
    try testing.expectEqual(
        @as(?usize, null),
        (try parse(a, &.{"http://x"}, &env, null)).parallel_max_host,
    );
    // A number outside the range still parses and is read as though the
    // flag were not there, at the run. That is curl's own answer, and
    // `run.parallelHostCapped` writes the note.
    try testing.expectEqual(
        @as(?usize, 0),
        (try parse(a, &.{ "--parallel-max-host", "0", "http://x" }, &env, null)).parallel_max_host,
    );
    // A value that is not a number at all is a usage fault, which is what
    // curl answers: `option --parallel-max-host: expected a proper
    // numerical parameter`.
    try testing.expectError(error.InvalidNumber, parse(
        a,
        &.{ "--parallel-max-host", "abc", "http://x" },
        &env,
        null,
    ));

    // `--parallel-immediate` takes no argument and changes no field. It
    // is here so the row cannot be dropped from the table by accident.
    const immediate = try parse(a, &.{ "--parallel-immediate", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 1), immediate.urls.len);
}

test "-o, -O and -D each answer to the long form curl gives them" {
    // The three the repo owner measured as missing. Each long form must
    // reach the same effect its short form does.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const short_o = try parse(arena.allocator(), &.{ "-o", "out.bin", "http://x" }, &env, null);
    const long_o = try parse(arena.allocator(), &.{ "--output", "out.bin", "http://x" }, &env, null);
    try testing.expectEqualStrings("out.bin", short_o.output.bodyTarget(0).file);
    try testing.expectEqualStrings("out.bin", long_o.output.bodyTarget(0).file);

    const short_upper_o = try parse(arena.allocator(), &.{ "-O", "http://x/a.bin" }, &env, null);
    const long_upper_o = try parse(arena.allocator(), &.{ "--remote-name", "http://x/a.bin" }, &env, null);
    try testing.expectEqual(BodyTarget.url_name, short_upper_o.output.bodyTarget(0));
    try testing.expectEqual(BodyTarget.url_name, long_upper_o.output.bodyTarget(0));

    const short_d = try parse(arena.allocator(), &.{ "-D", "heads.txt", "http://x" }, &env, null);
    const long_d = try parse(arena.allocator(), &.{ "--dump-header", "heads.txt", "http://x" }, &env, null);
    try testing.expectEqualStrings("heads.txt", short_d.output.headers_file.?.file);
    try testing.expectEqualStrings("heads.txt", long_d.output.headers_file.?.file);
}

test "-Y, -y and -# each answer to the short form curl gives them" {
    // The reverse of the same fault: a long form in the table with no
    // short form beside it, where curl has one.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const short = try parse(arena.allocator(), &.{ "-Y", "500", "-y", "20", "-#", "http://x" }, &env, null);
    const long = try parse(
        arena.allocator(),
        &.{ "--speed-limit", "500", "--speed-time", "20", "--progress-bar", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(@as(u64, 500), short.options.low_speed_limit);
    try testing.expectEqual(@as(u64, 500), long.options.low_speed_limit);
    try testing.expectEqual(@as(u32, 20), short.options.low_speed_time_s);
    try testing.expectEqual(@as(u32, 20), long.options.low_speed_time_s);
    try testing.expect(short.progress_bar);
    try testing.expect(long.progress_bar);
}

test "--proto and --proto-redir fill their own sets and leave the other alone" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const default = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expect(default.options.protocols.hasScheme("http"));
    try testing.expect(default.options.protocols.hasScheme("file"));
    try testing.expect(!default.options.redirect_protocols.hasScheme("file"));

    const narrowed = try parse(arena.allocator(), &.{ "--proto", "-all,http", "http://x" }, &env, null);
    try testing.expect(narrowed.options.protocols.hasScheme("http"));
    try testing.expect(!narrowed.options.protocols.hasScheme("https"));
    // `--proto` said nothing about a redirect, so that set is untouched.
    try testing.expect(narrowed.options.redirect_protocols.hasScheme("https"));

    const redir = try parse(arena.allocator(), &.{ "--proto-redir", "+file", "http://x" }, &env, null);
    try testing.expect(redir.options.redirect_protocols.hasScheme("file"));
    try testing.expect(redir.options.protocols.hasScheme("https"));
}

test "a --proto list that leaves nothing enabled is a usage fault, not a silent default" {
    // curl 8.21.0 answers `--proto -all` with exit 2 before any transfer.
    // A parser that shrugged and used its default would run a transfer the
    // user asked it not to run.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var fault: Fault = undefined;
    try testing.expectError(
        error.InvalidProtocolList,
        parse(arena.allocator(), &.{ "--proto", "-all", "http://x" }, &env, &fault),
    );
    try testing.expect(std.mem.indexOf(u8, fault.message, "--proto") != null);
    try testing.expect(std.mem.indexOf(u8, fault.message, "no protocol enabled") != null);

    var redir_fault: Fault = undefined;
    try testing.expectError(
        error.InvalidProtocolList,
        parse(arena.allocator(), &.{ "--proto-redir", "=nosuchproto", "http://x" }, &env, &redir_fault),
    );
    try testing.expect(std.mem.indexOf(u8, redir_fault.message, "--proto-redir") != null);
}

test "a --proto list past a bound is refused, and the message shows no raw bytes" {
    // The argument is untrusted input. A list past either bound reports
    // the bound, and the flag name reaches standard error through
    // `safe.Text` like every other echoed string.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const long = "http," ** ((zurl_core.redirect.Set.max_list_bytes / 5) + 1);
    var fault: Fault = undefined;
    try testing.expectError(
        error.InvalidProtocolList,
        parse(arena.allocator(), &.{ "--proto", long, "http://x" }, &env, &fault),
    );
    try testing.expect(std.mem.indexOf(u8, fault.message, "longer than") != null);

    const many = "," ** (zurl_core.redirect.Set.max_entries + 1);
    var many_fault: Fault = undefined;
    try testing.expectError(
        error.InvalidProtocolList,
        parse(arena.allocator(), &.{ "--proto", many, "http://x" }, &env, &many_fault),
    );
    try testing.expect(std.mem.indexOf(u8, many_fault.message, "names more than") != null);
}

test "a --proto value carrying a control byte reaches the message sanitised" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var fault: Fault = undefined;
    try testing.expectError(
        error.InvalidProtocolList,
        parse(arena.allocator(), &.{ "--proto", "=ev\x1b[31mIL\nzurl: forged", "http://x" }, &env, &fault),
    );
    // No escape and no newline may reach the line the user sees, so the
    // value cannot draw a second line that reads like one of zurl's own.
    try testing.expect(std.mem.indexOfScalar(u8, fault.message, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, fault.message, '\n') == null);
}

test "each --tlsv1.x flag is accepted, and only 1.2 and 1.3 move the floor" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    // The floor of a run that names nothing.
    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_2, bare.options.tls_min_version);

    // Accepted, and they leave the floor where it was. Refusing either
    // would exit 2 on a command line curl runs.
    for ([_][]const u8{ "--tlsv1", "--tlsv1.0", "--tlsv1.1", "-1" }) |flag| {
        const plan = try parse(arena.allocator(), &.{ flag, "http://x" }, &env, null);
        try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_2, plan.options.tls_min_version);
    }

    const twelve = try parse(arena.allocator(), &.{ "--tlsv1.2", "http://x" }, &env, null);
    try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_2, twelve.options.tls_min_version);

    const thirteen = try parse(arena.allocator(), &.{ "--tlsv1.3", "http://x" }, &env, null);
    try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_3, thirteen.options.tls_min_version);

    // The highest wins, whichever order the two arrived in, and a lower
    // flag after a higher one cannot walk it back.
    const both = try parse(arena.allocator(), &.{ "--tlsv1.3", "--tlsv1.2", "http://x" }, &env, null);
    try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_3, both.options.tls_min_version);
    const lowered = try parse(arena.allocator(), &.{ "--tlsv1.3", "--tlsv1.0", "http://x" }, &env, null);
    try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_3, lowered.options.tls_min_version);
}

test "--tls-max reads every value curl reads, and the last one wins" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    // The ceiling of a run that names nothing is the highest this build
    // offers, so the flag's absence changes nothing.
    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(zurl_core.tls.Version.highest, bare.options.tls_max_version);
    try testing.expectEqual(zurl_core.tls.Version.tls_1_3, bare.options.tls_max_version);

    const cases = [_]struct { text: []const u8, want: zurl_core.tls.Version }{
        .{ .text = "1.0", .want = .tls_1_0 },
        .{ .text = "1.1", .want = .tls_1_1 },
        .{ .text = "1.2", .want = .tls_1_2 },
        .{ .text = "1.3", .want = .tls_1_3 },
        .{ .text = "default", .want = .tls_1_3 },
    };
    for (cases) |case| {
        const plan = try parse(arena.allocator(), &.{ "--tls-max", case.text, "http://x" }, &env, null);
        try testing.expectEqual(case.want, plan.options.tls_max_version);
    }

    // curl keeps the last `--tls-max`, and does not tighten to the
    // lowest. Measured: `--tls-max 1.2 --tls-max 1.3 --tlsv1.3` runs.
    const last = try parse(
        arena.allocator(),
        &.{ "--tls-max", "1.2", "--tls-max", "1.3", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(zurl_core.tls.Version.tls_1_3, last.options.tls_max_version);
}

test "a --tls-max value curl refuses is a usage fault naming the flag" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    for ([_][]const u8{ "1.4", "", "1", "tlsv1.2", "DEFAULT" }) |bad| {
        var fault: Fault = .{};
        try testing.expectError(
            error.InvalidTlsVersion,
            parse(arena.allocator(), &.{ "--tls-max", bad, "http://x" }, &env, &fault),
        );
        try testing.expect(std.mem.indexOf(u8, fault.message, "--tls-max") != null);
    }
}

test "a --tls-max value carrying a control byte reaches the message sanitised" {
    // The value is a command-line or config-file string, so it is
    // untrusted input and must not draw a line that reads like one of
    // zurl's own.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var fault: Fault = .{};
    try testing.expectError(
        error.InvalidTlsVersion,
        parse(arena.allocator(), &.{ "--tls-max", "1.\x1b[31m9\nzurl: forged", "http://x" }, &env, &fault),
    );
    try testing.expect(std.mem.indexOfScalar(u8, fault.message, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, fault.message, '\n') == null);
}

test "a --tlsv1.x above a --tls-max is a usage fault, in either order" {
    // curl reports this while it parses and never opens a socket. The
    // order decides which sentence prints, because each flag can only
    // check what the command line has already said. Both exit 2. Measured
    // against curl 8.21.0.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    {
        var fault: Fault = .{};
        try testing.expectError(
            error.TlsVersionRangeEmpty,
            parse(arena.allocator(), &.{ "--tls-max", "1.2", "--tlsv1.3", "http://x" }, &env, &fault),
        );
        try testing.expect(std.mem.indexOf(u8, fault.message, "--tlsv1.3") != null);
        try testing.expect(std.mem.indexOf(u8, fault.message, "above") != null);
    }
    {
        var fault: Fault = .{};
        try testing.expectError(
            error.TlsVersionRangeEmpty,
            parse(arena.allocator(), &.{ "--tlsv1.3", "--tls-max", "1.2", "http://x" }, &env, &fault),
        );
        try testing.expect(std.mem.indexOf(u8, fault.message, "--tls-max") != null);
        try testing.expect(std.mem.indexOf(u8, fault.message, "below") != null);
    }
    // A ceiling below the floor of this build, with a `--tlsv1.x` naming
    // something above it, is the same fault.
    {
        var fault: Fault = .{};
        try testing.expectError(
            error.TlsVersionRangeEmpty,
            parse(arena.allocator(), &.{ "--tls-max", "1.0", "--tlsv1.1", "http://x" }, &env, &fault),
        );
        try testing.expect(fault.message.len > 0);
    }
}

test "a --tlsv1.x at or below a --tls-max is not a fault, whatever the floor became" {
    // **The row that needs the named version and not the floor.** zurl
    // clamps `--tlsv1.0` up to its TLS 1.2 floor, and this pair must
    // still parse, because curl parses it and fails at the handshake with
    // 35 instead. Measured: `curl --tls-max 1.0 --tlsv1.0 URL` exits 35,
    // and `curl --tls-max 1.0 --tlsv1.1 URL` exits 2.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const low = try parse(
        arena.allocator(),
        &.{ "--tls-max", "1.0", "--tlsv1.0", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(zurl_core.tls.Version.tls_1_0, low.options.tls_max_version);
    try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_2, low.options.tls_min_version);

    // `-1` and `--tlsv1` name TLS 1.0 too, so neither closes the range.
    for ([_][]const u8{ "-1", "--tlsv1" }) |flag| {
        const plan = try parse(arena.allocator(), &.{ "--tls-max", "1.2", flag, "http://x" }, &env, null);
        try testing.expectEqual(zurl_core.tls.Version.tls_1_2, plan.options.tls_max_version);
    }

    // And the equal case is not a fault either.
    const equal = try parse(
        arena.allocator(),
        &.{ "--tls-max", "1.2", "--tlsv1.2", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(zurl_core.tls.Version.tls_1_2, equal.options.tls_max_version);
    try testing.expectEqual(zurl_core.tls.MinVersion.tls_1_2, equal.options.tls_min_version);
}

test "--proto-default names the scheme a url with none is read with" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    // Not given, and the url parser keeps its own guess.
    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(?[]const u8, null), bare.options.default_protocol);

    for ([_][]const u8{ "http", "https", "file", "ftp", "ftps", "HTTPS" }) |name| {
        const plan = try parse(arena.allocator(), &.{ "--proto-default", name, "x" }, &env, null);
        try testing.expectEqualStrings(name, plan.options.default_protocol.?);
    }

    // The last one wins, the way curl reads a repeated flag. Measured:
    // `--proto-default file --proto-default http 127.0.0.1:1/x` dials
    // http.
    const last = try parse(
        arena.allocator(),
        &.{ "--proto-default", "file", "--proto-default", "http", "x" },
        &env,
        null,
    );
    try testing.expectEqualStrings("http", last.options.default_protocol.?);
}

test "a --proto-default name nobody knows is exit 1, and an empty one is exit 2" {
    // Two different faults, because curl gives them two different exit
    // codes. Measured: `--proto-default nosuchproto` is exit 1 and
    // `a specified protocol is unsupported by libcurl`, even beside a url
    // that already spells its scheme out; `--proto-default ''` is exit 2
    // and `blank argument where content is expected`.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    {
        var fault: Fault = .{};
        try testing.expectError(
            error.UnsupportedProtocolName,
            parse(arena.allocator(), &.{ "--proto-default", "nosuchproto", "http://x" }, &env, &fault),
        );
        try testing.expect(std.mem.indexOf(u8, fault.message, "--proto-default") != null);
        try testing.expect(std.mem.indexOf(u8, fault.message, "nosuchproto") != null);
    }
    {
        var fault: Fault = .{};
        try testing.expectError(
            error.MissingProtocolName,
            parse(arena.allocator(), &.{ "--proto-default", "", "http://x" }, &env, &fault),
        );
        try testing.expect(std.mem.indexOf(u8, fault.message, "--proto-default") != null);
    }
    // And an untrusted name reaches the message sanitised, like every
    // other flag value.
    {
        var fault: Fault = .{};
        try testing.expectError(
            error.UnsupportedProtocolName,
            parse(arena.allocator(), &.{ "--proto-default", "ht\x1b[31mtp\nzurl: forged", "http://x" }, &env, &fault),
        );
        try testing.expect(std.mem.indexOfScalar(u8, fault.message, 0x1b) == null);
        try testing.expect(std.mem.indexOfScalar(u8, fault.message, '\n') == null);
    }
}

test "--compressed raises the offer, and a run without it offers nothing" {
    // **The flag is the whole difference, and it used to be no
    // difference at all.** Measured on the wire with a loopback listener
    // that captured the request bytes: curl sends no `Accept-Encoding` at
    // all without `--compressed` and `Accept-Encoding: deflate, gzip, br,
    // zstd` with it. zurl sent `accept-encoding: gzip, deflate` either
    // way, so a server could compress for zurl where it sent curl the
    // plain body, and the flag chose nothing.
    //
    // This test read the two header counts and found them equal, which
    // was true and was the defect. It reads the option the flag sets now.
    // Being an unknown flag is still a fault a real `~/.curlrc` would
    // meet, so the accepting half has to stay.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const with = try parse(arena.allocator(), &.{ "--compressed", "http://x" }, &env, null);
    const without = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expect(with.options.accept_encoding);
    try testing.expect(!without.options.accept_encoding);
    // The flag adds no header of the caller's own. The engine writes the
    // one line, from the option above.
    try testing.expectEqual(without.options.headers.len, with.options.headers.len);
    try testing.expectEqual(@as(usize, 1), with.urls.len);
}

test "parseWithConfigFiles reads a real -K file from disk, and a later command-line flag still wins" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "zurl.conf",
        .data = "user-agent config-agent/1\nheader = \"X-From: config\"\n",
    });
    const path = try std.fmt.allocPrint(arena.allocator(), ".zig-cache/tmp/{s}/zurl.conf", .{tmp.sub_path});

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{
        "-K",           path,
        "--user-agent", "cli-agent/1",
        "http://x",
    }, &env, null);

    try testing.expectEqualStrings("cli-agent/1", plan.options.user_agent);
    try testing.expectEqual(@as(usize, 1), plan.options.headers.len);
    try testing.expectEqualStrings("X-From", plan.options.headers[0].name);
    try testing.expectEqualStrings("config", plan.options.headers[0].value);
}

test "-K can be given more than once, applied in order" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "first.conf", .data = "header \"X-A: 1\"\n" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "second.conf", .data = "header \"X-B: 2\"\n" });
    const first = try std.fmt.allocPrint(arena.allocator(), ".zig-cache/tmp/{s}/first.conf", .{tmp.sub_path});
    const second = try std.fmt.allocPrint(arena.allocator(), ".zig-cache/tmp/{s}/second.conf", .{tmp.sub_path});

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{
        "-K",       first,
        "-K",       second,
        "http://x",
    }, &env, null);

    try testing.expectEqual(@as(usize, 2), plan.options.headers.len);
    try testing.expectEqualStrings("X-A", plan.options.headers[0].name);
    try testing.expectEqualStrings("X-B", plan.options.headers[1].name);
}

test "--cacert naming a missing file is a usage error exiting before any network access" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    var fault: Fault = .{};

    const result = parseWithConfigFiles(arena.allocator(), testing.io, &.{
        "--cacert",             "/nonexistent/zurl-test-ca.pem",
        "https://example.com/",
    }, &env, &fault);

    try testing.expectError(error.CacertMissing, result);
    try testing.expect(std.mem.indexOf(u8, fault.message, "--cacert") != null);
    try testing.expect(std.mem.indexOf(u8, fault.message, "/nonexistent/zurl-test-ca.pem") != null);
}

test "--cacert naming a real file parses cleanly" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "ca.pem", .data = "" });
    const path = try std.fmt.allocPrint(arena.allocator(), ".zig-cache/tmp/{s}/ca.pem", .{tmp.sub_path});

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{
        "--cacert",             path,
        "https://example.com/",
    }, &env, null);

    try testing.expectEqualStrings(path, plan.options.ca.cacert.?);
}

test "--capath naming a missing directory is not a usage error, matching curl" {
    // A real curl 8.21.0 run of `--capath /nonexistent` still reaches
    // the TLS handshake and fails there, as curl's 60, rather than being
    // refused at parse time the way `--cacert` is. This asymmetry
    // between the two flags is the point of this test: `--cacert` gets
    // an eager check and `--capath` does not.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{
        "--capath",             "/nonexistent/zurl-test-certs",
        "https://example.com/",
    }, &env, null);

    try testing.expectEqualStrings("/nonexistent/zurl-test-certs", plan.options.ca.capath.?);
}

test "an environment variable naming something unreadable is not a usage error, matching curl" {
    // curl validates `--cacert` when it parses the flag, but does no such
    // check for `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, or `SSL_CERT_DIR`: a
    // real curl 8.21.0 run with any of those set to a missing path still
    // reaches the transfer and fails there, as curl's 77 or 60.
    // `Client.zig`'s "each certificate source reports the curl code this
    // task assigns it" test drives that half. This half proves `Args`
    // never turns the same input into a usage fault.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("CURL_CA_BUNDLE", "/nonexistent/zurl-test-ca.pem");

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{"https://example.com/"}, &env, null);

    try testing.expectEqualStrings("/nonexistent/zurl-test-ca.pem", plan.options.ca.curl_ca_bundle.?);
}

test "-q as the first argument stops parseWithConfigFiles reading a real default curlrc" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = ".curlrc", .data = "user-agent should-not-be-read/1\n" });
    const home = try std.fmt.allocPrint(arena.allocator(), ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try env.put("HOME", home);

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{ "-q", "http://x" }, &env, null);
    // The library default, from `Transfer.Options.user_agent`'s own field
    // default. `.curlrc`'s "should-not-be-read/1" must not appear.
    try testing.expectEqualStrings("zurl/0.1", plan.options.user_agent);
}

test "with no -q, parseWithConfigFiles reads a real default curlrc found via HOME" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = ".curlrc", .data = "user-agent default-agent/1\n" });
    const home = try std.fmt.allocPrint(arena.allocator(), ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try env.put("HOME", home);

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{"http://x"}, &env, null);
    try testing.expectEqualStrings("default-agent/1", plan.options.user_agent);
}

test "a command-line flag still overrides a real default curlrc found via HOME" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = ".curlrc", .data = "user-agent default-agent/1\n" });
    const home = try std.fmt.allocPrint(arena.allocator(), ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try env.put("HOME", home);

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{
        "--user-agent", "cli-agent/1",
        "http://x",
    }, &env, null);
    try testing.expectEqualStrings("cli-agent/1", plan.options.user_agent);
}

test "a missing default curlrc is silent, not a fault" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();
    try env.put("HOME", "/nonexistent-zurl-test-home-directory");

    const plan = try parseWithConfigFiles(arena.allocator(), testing.io, &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(usize, 1), plan.urls.len);
}

test "the --retry family fills Plan.retry, and no flag asks for no try at all" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expect(!bare.retry.enabled());
    try testing.expectEqual(@as(u32, 0), bare.retry.attempts);
    try testing.expectEqual(@as(?u32, null), bare.retry.delay_s);
    try testing.expectEqual(@as(u32, 0), bare.retry.max_time_s);
    try testing.expect(!bare.retry.connrefused);
    try testing.expect(!bare.retry.all_errors);

    const full = try parse(arena.allocator(), &.{
        "--retry",             "3",
        "--retry-delay",       "2",
        "--retry-max-time",    "30",
        "--retry-connrefused", "--retry-all-errors",
        "http://x",
    }, &env, null);
    try testing.expect(full.retry.enabled());
    try testing.expectEqual(@as(u32, 3), full.retry.attempts);
    try testing.expectEqual(@as(?u32, 2), full.retry.delay_s);
    try testing.expectEqual(@as(u32, 30), full.retry.max_time_s);
    try testing.expect(full.retry.connrefused);
    try testing.expect(full.retry.all_errors);

    // **`--retry-delay 0` reads as no delay named at all.** Measured
    // against curl 8.21.0: `--retry 3 --retry-delay 0` tried at 0, 1, 3,
    // and 7 seconds, which is the doubling wait and not a wait of
    // nothing. So zero must reach `run.zig` as null, or the run would
    // hammer the peer with no wait between tries.
    const zero = try parse(arena.allocator(), &.{ "--retry", "1", "--retry-delay", "0", "http://x" }, &env, null);
    try testing.expectEqual(@as(?u32, null), zero.retry.delay_s);

    // The last of each wins, the way the last of any other pair does.
    const twice = try parse(arena.allocator(), &.{
        "--retry",       "1", "--retry",       "5",
        "--retry-delay", "9", "--retry-delay", "4",
        "http://x",
    }, &env, null);
    try testing.expectEqual(@as(u32, 5), twice.retry.attempts);
    try testing.expectEqual(@as(?u32, 4), twice.retry.delay_s);
}

test "a --retry argument that is not a number is a usage fault" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var fault: Fault = .{};
    try testing.expectError(
        error.InvalidNumber,
        parse(arena.allocator(), &.{ "--retry", "many", "http://x" }, &env, &fault),
    );
    try testing.expect(std.mem.indexOf(u8, fault.message, "many") != null);
}

test "-r builds the Range header value, and a bare number gains the dash curl adds" {
    // Every row was measured against curl 8.21.0 on a loopback server
    // that logged the request head. See `resolveRange`.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const rows = [_]struct { arg: []const u8, want: []const u8 }{
        .{ .arg = "0-99", .want = "bytes=0-99" },
        .{ .arg = "100-", .want = "bytes=100-" },
        .{ .arg = "-100", .want = "bytes=-100" },
        .{ .arg = "0-9,20-29", .want = "bytes=0-9,20-29" },
        .{ .arg = "0-0", .want = "bytes=0-0" },
        // A bare number names a start with no end, and curl writes the
        // dash for it.
        .{ .arg = "5", .want = "bytes=5-" },
    };
    for (rows) |row| {
        const plan = try parse(arena.allocator(), &.{ "-r", row.arg, "http://x" }, &env, null);
        try testing.expectEqualStrings(row.want, plan.range.?);
    }

    // The long spelling reads the same, and the last one wins.
    const last = try parse(arena.allocator(), &.{ "-r", "0-9", "--range", "5-6", "http://x" }, &env, null);
    try testing.expectEqualStrings("bytes=5-6", last.range.?);

    // No flag names no range at all, so nothing new reaches the wire.
    const none = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(?[]const u8, null), none.range);
}

test "-r with a character that is not a digit is sent, with a note, the way curl does" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plan = try parse(arena.allocator(), &.{ "-r", "a-b", "http://x" }, &env, null);
    // curl warns and sends the value anyway, measured. The value must
    // reach the wire unchanged, so a peer that reads a unit other than
    // bytes still gets what the user typed.
    try testing.expectEqualStrings("bytes=a-b", plan.range.?);
    try testing.expectEqual(@as(usize, 1), plan.warnings.len);
    try testing.expect(std.mem.indexOf(u8, plan.warnings[0], "a-b") != null);

    // A range of digits earns no note at all.
    const clean = try parse(arena.allocator(), &.{ "-r", "0-9", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 0), clean.warnings.len);
}

test "-r refuses an empty argument and refuses -C beside it, both the way curl does" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var blank: Fault = .{};
    try testing.expectError(
        error.InvalidNumber,
        parse(arena.allocator(), &.{ "-r", "", "http://x" }, &env, &blank),
    );

    // **Both orders, because either flag may come first and the pair is
    // refused either way.** Measured against curl 8.21.0: `-r 0-99 -C 5`
    // exits 2 with `--continue-at is mutually exclusive with --range`,
    // and no socket opens.
    var first: Fault = .{};
    try testing.expectError(
        error.ConflictingRangeAndResume,
        parse(arena.allocator(), &.{ "-r", "0-99", "-C", "5", "http://x" }, &env, &first),
    );
    try testing.expect(std.mem.indexOf(u8, first.message, "--range") != null);

    var second: Fault = .{};
    try testing.expectError(
        error.ConflictingRangeAndResume,
        parse(arena.allocator(), &.{ "-C", "-", "-r", "0-99", "http://x" }, &env, &second),
    );

    // Each flag on its own is fine, so the refusal is about the pair.
    _ = try parse(arena.allocator(), &.{ "-r", "0-99", "http://x" }, &env, null);
    _ = try parse(arena.allocator(), &.{ "-C", "5", "http://x" }, &env, null);
}

test "-e writes one Referer header, and ;auto asks the engine to keep it current" {
    // Every row was measured against curl 8.21.0. See the `.referer` arm
    // of `applyEffect`.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const plain = try parse(arena.allocator(), &.{ "-e", "http://a/", "http://x" }, &env, null);
    try testing.expectEqualStrings("Referer", plain.options.headers[0].name);
    try testing.expectEqualStrings("http://a/", plain.options.headers[0].value);
    try testing.expect(!plain.options.auto_referer);

    // `;auto` alone sends no `Referer` on the first request and turns the
    // per-hop half on.
    const auto = try parse(arena.allocator(), &.{ "-e", ";auto", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 0), auto.options.headers.len);
    try testing.expect(auto.options.auto_referer);

    // A url with the suffix does both.
    const both = try parse(arena.allocator(), &.{ "--referer", "http://a/;auto", "http://x" }, &env, null);
    try testing.expectEqualStrings("http://a/", both.options.headers[0].value);
    try testing.expect(both.options.auto_referer);

    // An empty value adds no header, and the last `-e` wins.
    const empty = try parse(arena.allocator(), &.{ "-e", "", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 0), empty.options.headers.len);

    const last = try parse(arena.allocator(), &.{ "-e", "a", "-e", "b", "http://x" }, &env, null);
    try testing.expectEqual(@as(usize, 1), last.options.headers.len);
    try testing.expectEqualStrings("b", last.options.headers[0].value);

    // A `-H` of the same name replaces it outright, and adds no second
    // line. Two `Referer` headers would let a peer read one request as
    // coming from two pages.
    const written = try parse(arena.allocator(), &.{
        "-e", "x", "-H", "Referer: y", "http://x",
    }, &env, null);
    try testing.expectEqual(@as(usize, 1), written.options.headers.len);
    try testing.expectEqualStrings("y", written.options.headers[0].value);

    // No flag at all leaves both answers off.
    const none = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(usize, 0), none.options.headers.len);
    try testing.expect(!none.options.auto_referer);
}

test "--resolve and --connect-to fill options.connect_to and move the dial alone" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const resolved = try parse(arena.allocator(), &.{
        "--resolve", "example.test:8443:127.0.0.1", "https://example.test:8443/",
    }, &env, null);
    try testing.expectEqual(@as(usize, 1), resolved.options.connect_to.len);
    const one = resolved.options.connect_to[0];
    try testing.expectEqualStrings("example.test", one.from_host);
    try testing.expectEqual(@as(?u16, 8443), one.from_port);
    try testing.expectEqualStrings("127.0.0.1", one.to_host);
    // `--resolve` never moves the port. Measured.
    try testing.expectEqual(@as(?u16, 8443), one.to_port);

    // The leading `+` curl allows is read and dropped.
    const plus = try parse(arena.allocator(), &.{
        "--resolve", "+example.test:80:127.0.0.1", "http://example.test/",
    }, &env, null);
    try testing.expectEqualStrings("example.test", plus.options.connect_to[0].from_host);

    const connected = try parse(arena.allocator(), &.{
        "--connect-to", "example.test:80:127.0.0.1:8080", "http://example.test/",
    }, &env, null);
    const two = connected.options.connect_to[0];
    try testing.expectEqualStrings("example.test", two.from_host);
    try testing.expectEqual(@as(?u16, 80), two.from_port);
    try testing.expectEqualStrings("127.0.0.1", two.to_host);
    try testing.expectEqual(@as(?u16, 8080), two.to_port);

    // An empty field means "any" on the left and "keep" on the right,
    // which is curl's own reading of `::127.0.0.1:8080`.
    const wild = try parse(arena.allocator(), &.{
        "--connect-to", "::127.0.0.1:8080", "http://anything/",
    }, &env, null);
    const three = wild.options.connect_to[0];
    try testing.expectEqualStrings("", three.from_host);
    try testing.expectEqual(@as(?u16, null), three.from_port);
    try testing.expectEqualStrings("127.0.0.1", three.to_host);
    try testing.expectEqual(@as(?u16, 8080), three.to_port);

    // An IPv6 literal keeps its colons and loses its brackets, because
    // `zurl_core.url.parse` hands the engine a bare host too.
    const six = try parse(arena.allocator(), &.{
        "--resolve", "[::1]:443:[::1]", "https://[::1]/",
    }, &env, null);
    try testing.expectEqualStrings("::1", six.options.connect_to[0].from_host);
    try testing.expectEqualStrings("::1", six.options.connect_to[0].to_host);

    // Both flags fill one list, in command-line order, and nothing else
    // in the plan changes.
    const mixed = try parse(arena.allocator(), &.{
        "--resolve",      "a.test:80:127.0.0.1",
        "--connect-to",   "b.test:80:127.0.0.2:81",
        "http://a.test/",
    }, &env, null);
    try testing.expectEqual(@as(usize, 2), mixed.options.connect_to.len);
    try testing.expectEqualStrings("a.test", mixed.options.connect_to[0].from_host);
    try testing.expectEqualStrings("b.test", mixed.options.connect_to[1].from_host);

    // No flag leaves the list empty, so every transfer dials what the url
    // says, exactly as it did before these flags existed.
    const none = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(usize, 0), none.options.connect_to.len);
}

test "a --resolve or --connect-to entry that does not read is refused before any socket" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const bad_resolve = [_][]const u8{
        // No colon at all.
        "bogus",
        // A port that is not a number.
        "host:notaport:1.2.3.4",
        // No address behind the port.
        "host:80:",
        // curl takes a list of addresses; zurl dials one and refuses the
        // list rather than drop the rest without a word.
        "host:80:1.2.3.4,5.6.7.8",
        // An empty host names nothing to match.
        ":80:1.2.3.4",
        // A `-` in front removes an entry from curl's own name cache.
        // zurl keeps no cache, so the entry names nothing to dial.
        "-host:80:1.2.3.4",
        // A port past a `u16`.
        "host:70000:1.2.3.4",
    };
    for (bad_resolve) |entry| {
        var fault: Fault = .{};
        _ = parse(arena.allocator(), &.{ "--resolve", entry, "http://x" }, &env, &fault) catch |err| {
            try testing.expectEqual(error.InvalidHostOverride, err);
            continue;
        };
        std.debug.print("--resolve '{s}' was accepted\n", .{entry});
        return error.TestUnexpectedResult;
    }

    const bad_connect = [_][]const u8{
        "bogus",
        "a:80:b",
        "a:80:b:80:extra",
        "a:notaport:b:80",
        "a:80:b:notaport",
    };
    for (bad_connect) |entry| {
        var fault: Fault = .{};
        _ = parse(arena.allocator(), &.{ "--connect-to", entry, "http://x" }, &env, &fault) catch |err| {
            try testing.expectEqual(error.InvalidHostOverride, err);
            continue;
        };
        std.debug.print("--connect-to '{s}' was accepted\n", .{entry});
        return error.TestUnexpectedResult;
    }
}

test "a run may not name more host overrides than the bound" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(testing.allocator);
    var i: usize = 0;
    while (i <= max_host_overrides) : (i += 1) {
        try argv.append(testing.allocator, "--resolve");
        try argv.append(testing.allocator, try std.fmt.allocPrint(
            arena.allocator(),
            "h{d}.test:80:127.0.0.1",
            .{i},
        ));
    }
    try argv.append(testing.allocator, "http://x");

    var fault: Fault = .{};
    try testing.expectError(
        error.TooManyHostOverrides,
        parse(arena.allocator(), argv.items, &env, &fault),
    );

    // One fewer is accepted, so the bound refuses exactly what it names.
    const ok = try parse(arena.allocator(), argv.items[0 .. max_host_overrides * 2], &env, null);
    try testing.expectEqual(max_host_overrides, ok.options.connect_to.len);
}

test "--parallel-max is carried through, and no flag leaves the default alone" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const named = try parse(arena.allocator(), &.{ "--parallel-max", "4", "http://x" }, &env, null);
    try testing.expectEqual(@as(?usize, 4), named.parallel_max);

    const none = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expectEqual(@as(?usize, null), none.parallel_max);

    // A number outside the range reaches `run.zig` as it was written.
    // That file names the range and writes the note, because only it
    // knows the default it falls back to.
    const large = try parse(arena.allocator(), &.{ "--parallel-max", "5000", "http://x" }, &env, null);
    try testing.expectEqual(@as(?usize, 5000), large.parallel_max);
}

test "--no-alpn leaves the ALPN extension out of the handshake" {
    // The flag used to be accepted and do nothing, because zurl sent no
    // ALPN extension at all. The hello carries one now, so the flag has
    // something to turn off and it writes the field that turns it off.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    // A run with no flag offers ALPN, which is what curl does.
    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    try testing.expect(!bare.options.no_alpn);

    const off = try parse(arena.allocator(), &.{ "--no-alpn", "https://x" }, &env, null);
    try testing.expect(off.options.no_alpn);

    // And the flag changes nothing else about the plan. It is a property
    // of the handshake and of no request.
    try testing.expectEqual(bare.options.method, off.options.method);
    try testing.expectEqual(@as(usize, 0), off.options.headers.len);
    try testing.expectEqual(@as(usize, 1), off.urls.len);
    try testing.expect(!off.options.insecure);
}

test "--http1.1 narrows the ALPN offer and --http2 leaves it at the default" {
    // **The flag is the way back to the older protocol.** zurl offers `h2`
    // and `http/1.1` now, and a peer that speaks HTTP/2 chooses `h2`. A
    // user whose peer misbehaves over HTTP/2 needs one flag that takes it
    // out of the offer, which is what curl's own `--http1.1` does.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const bare = try parse(arena.allocator(), &.{"https://x"}, &env, null);
    try testing.expectEqual(zurl.Transfer.HttpVersion.any, bare.options.http_version);

    const older = try parse(arena.allocator(), &.{ "--http1.1", "https://x" }, &env, null);
    try testing.expectEqual(zurl.Transfer.HttpVersion.http_1_1, older.options.http_version);

    // **`--http2` is a request and not a demand, and over TLS it names the
    // default.** It has a value of its own because it does change one
    // thing: over cleartext it sends the `Upgrade: h2c` fields, which no
    // flag and `--http1.1` both leave off. See `engine.HttpVersion`.
    const two = try parse(arena.allocator(), &.{ "--http2", "https://x" }, &env, null);
    try testing.expectEqual(zurl.Transfer.HttpVersion.http_2, two.options.http_version);

    // **`--http2-prior-knowledge` is accepted now, and it demands.** Over
    // cleartext the preface goes out first and no HTTP/1.1 octet is
    // written; over TLS the ALPN offer is `h2` alone, so a peer with no
    // HTTP/2 ends the handshake. curl behaves the same way for both,
    // measured.
    const prior = try parse(
        arena.allocator(),
        &.{ "--http2-prior-knowledge", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(
        zurl.Transfer.HttpVersion.prior_knowledge,
        prior.options.http_version,
    );
    // It used to be refused by name. It is not any more.
    try testing.expectEqual(@as(?UnsupportedFlag, null), prior.unsupported_flag);

    // The last version flag wins here too, whichever pair is written.
    const prior_then_older = try parse(
        arena.allocator(),
        &.{ "--http2-prior-knowledge", "--http1.1", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(
        zurl.Transfer.HttpVersion.http_1_1,
        prior_then_older.options.http_version,
    );
    const older_then_prior = try parse(
        arena.allocator(),
        &.{ "--http1.1", "--http2-prior-knowledge", "http://x" },
        &env,
        null,
    );
    try testing.expectEqual(
        zurl.Transfer.HttpVersion.prior_knowledge,
        older_then_prior.options.http_version,
    );

    // The last version flag on the command line wins, in either order.
    // curl reads its own the same way.
    const last_older = try parse(
        arena.allocator(),
        &.{ "--http2", "--http1.1", "https://x" },
        &env,
        null,
    );
    try testing.expectEqual(zurl.Transfer.HttpVersion.http_1_1, last_older.options.http_version);

    const last_two = try parse(
        arena.allocator(),
        &.{ "--http1.1", "--http2", "https://x" },
        &env,
        null,
    );
    try testing.expectEqual(zurl.Transfer.HttpVersion.http_2, last_two.options.http_version);

    // And the flag changes nothing else about the plan. It is a property
    // of the handshake and of no request.
    try testing.expectEqual(bare.options.method, older.options.method);
    try testing.expectEqual(@as(usize, 0), older.options.headers.len);
    try testing.expect(!older.options.no_alpn);
}

test "--http3 and --http3-only reach the HTTP/3 engine, and neither is the default" {
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    // **HTTP/3 is never the default.** A command line with no version flag
    // asks for `any`, which offers `h2` and `http/1.1` over TCP and opens
    // no UDP socket at all. curl 8.21.0 takes the same view: measured,
    // `curl https://cloudflare.com/`, a host that does speak HTTP/3,
    // reported `%{http_version} 2`.
    const bare = try parse(arena.allocator(), &.{"https://x"}, &env, null);
    try testing.expectEqual(zurl.Transfer.HttpVersion.any, bare.options.http_version);

    // Both flags used to be refused by name. Neither one is any more.
    const three = try parse(arena.allocator(), &.{ "--http3", "https://x" }, &env, null);
    try testing.expectEqual(zurl.Transfer.HttpVersion.http_3, three.options.http_version);
    try testing.expectEqual(@as(?UnsupportedFlag, null), three.unsupported_flag);

    const only = try parse(arena.allocator(), &.{ "--http3-only", "https://x" }, &env, null);
    try testing.expectEqual(zurl.Transfer.HttpVersion.http_3_only, only.options.http_version);
    try testing.expectEqual(@as(?UnsupportedFlag, null), only.unsupported_flag);

    // The last version flag wins, in either order, the way every other
    // version flag reads.
    const then_two = try parse(
        arena.allocator(),
        &.{ "--http3", "--http2", "https://x" },
        &env,
        null,
    );
    try testing.expectEqual(zurl.Transfer.HttpVersion.http_2, then_two.options.http_version);

    const then_three = try parse(
        arena.allocator(),
        &.{ "--http1.1", "--http3-only", "https://x" },
        &env,
        null,
    );
    try testing.expectEqual(
        zurl.Transfer.HttpVersion.http_3_only,
        then_three.options.http_version,
    );

    // **`--proxy-http3` is still refused, and for a reason of its own.**
    // It names the protocol spoken to a proxy, and this build speaks
    // HTTP/1.1 to a proxy and offers no other version, which is what
    // `--proxy1.0` and `--proxy-http2` are refused for as well.
    const proxied = try parse(arena.allocator(), &.{ "--proxy-http3", "https://x" }, &env, null);
    try testing.expect(proxied.unsupported_flag != null);
    try testing.expectEqualStrings("--proxy-http3", proxied.unsupported_flag.?.flag);

    // And the flags change nothing else about the plan.
    try testing.expectEqual(bare.options.method, three.options.method);
    try testing.expectEqual(@as(usize, 0), three.options.headers.len);
    try testing.expect(!three.options.no_alpn);
}

test "-g and -l are accepted and change nothing in the plan" {
    // Each of these is a flag curl runs and zurl already behaves as if it
    // were given. Refusing one would exit 2 on a command line curl
    // accepts, which is the opposite of a drop-in replacement. This
    // proves each is accepted and that none of them writes a field.
    var arena = testArena();
    defer arena.deinit();
    var env = testEnv();
    defer env.deinit();

    const bare = try parse(arena.allocator(), &.{"http://x"}, &env, null);
    const rows = [_][]const []const u8{
        &.{ "-g", "http://x" },
        &.{ "--globoff", "http://x" },
        &.{ "-l", "http://x" },
        &.{ "--list-only", "http://x" },
    };
    for (rows) |argv| {
        const plan = try parse(arena.allocator(), argv, &env, null);
        try testing.expectEqual(bare.options.method, plan.options.method);
        try testing.expectEqual(@as(usize, 0), plan.options.headers.len);
        try testing.expectEqual(@as(usize, 1), plan.urls.len);
        try testing.expect(!plan.options.insecure);
        try testing.expectEqual(@as(?[]const u8, null), plan.range);
        try testing.expect(!plan.retry.enabled());
    }
}
