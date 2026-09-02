//! Where the response body and the response headers go.
//!
//! `Args` records the choice in `Args.OutputSpec`. This file acts on it:
//! it turns `-O` into a file name, it writes a body to a file, and it
//! writes the response head blocks that `-D` names a file for.
//!
//! **`-O` takes a file name from a url, and a url is untrusted.** A url
//! comes from a person, a lockfile, a manifest, or a redirect, so the name
//! it carries is input and not a value zurl may trust. `checkName` is the
//! one rule that decides whether zurl writes such a name, and every `-O`
//! name goes through it. A second copy of that rule somewhere else is how
//! the next hole gets in, so there is no second copy: `nameFromUrl` cuts
//! the segment out of the url and calls `checkName`, and nothing else in
//! zurl decides this.
//!
//! **zurl never percent-decodes a `-O` name before it writes it.** Measured
//! against curl 8.21.0: a url path of `/a%2fb` gives the file `a%2fb`, not
//! `a/b`, and a url path of `/%2fetc%2fpasswd` gives the file
//! `%2fetc%2fpasswd`, not `/etc/passwd`. curl writes the escaped bytes the
//! url carried, and so does zurl. Because the name is never decoded, a
//! percent escape cannot turn into a path separator or a NUL once the name
//! reaches the operating system: the bytes `checkName` reads are the bytes
//! `open` gets.
//!
//! **`checkName` decodes a name only to ask one question: does it name
//! nothing, or does it name the working directory or its parent?** curl
//! 8.21.0 finds no usable name in a url whose last path segment is empty,
//! or decodes whole to `.` or `..`, checked directly against the real
//! program: a raw `.` or `..`, and the same two percent-escaped, in either
//! case. curl does not fail there. It invents the name `curl_response` and
//! writes it, and so does zurl, as `fallback_name`.
//!
//! A name that survives that question is written exactly as the url wrote
//! it. Nothing else about its content is judged: a percent escape that
//! does not decode, such as `100%`, is still a plain six bytes to write.
//! curl 8.21.0 agrees, checked against the real program.
//!
//! What still stops a name, past that, is structural, not a guess about
//! what a byte might mean once decoded:
//!
//! - **A byte no path may carry reaches `open` unchanged.** A NUL ends a C
//!   string before the name does, a CR or an LF lets a later log line
//!   pretend to be a different line, and the others make a name a terminal
//!   cannot show or, worse, a name a terminal acts on. zurl reads this off
//!   the raw bytes, never the decoded ones, because the raw bytes are what
//!   `open` gets. The rule is `safe.controlLen`, which covers the C1
//!   controls spelled in UTF-8 as well as the C0 bytes, and which `-w`
//!   shares so no second copy of it can drift.
//! - **A raw `/` or `\` would turn one name into a path.** A single path
//!   segment cannot hold a raw `/`: it is what `lastSegment` cuts the name
//!   apart on, so the check on it can never fire through `nameFromUrl`
//!   today. It stays, because `checkName` is the one place this rule lives
//!   and a caller other than `nameFromUrl` may one day hand it a name that
//!   was never split. `\` is the separator on the other platform zurl
//!   builds for, and curl's own tool treats a raw `\` in a url the same
//!   way it treats a raw `/`: as a place to cut, so curl never writes a
//!   name that carries one either. zurl instead refuses such a name
//!   outright, which is stricter than curl but never lets a `\` reach a
//!   file it writes.
//! - **A name past `max_name_len` bytes is refused before it reaches
//!   `open`.** curl 8.21.0 exits 23 for a very long name too, checked
//!   against the real program, so this is not zurl inventing a limit curl
//!   has none of; it is zurl naming its own.
//!
//! **What zurl does not copy from curl.** curl 8.21.0 walks back past a
//! trailing `/`, or a trailing `/.`, to the segment before it: a url
//! ending in `/dir/` writes the file `dir`, checked against the real
//! program. `checkName` never looks past the one segment `lastSegment`
//! cuts, so zurl answers `fallback_name` for that shape instead of
//! guessing `dir`. The file this writes still lands inside the working
//! directory and the exit code still stays 0, so the property this file
//! exists to keep is unaffected; it is only curl's cleverer guess that
//! zurl does not reproduce, and reproducing it would mean walking the
//! path backward through an unbounded number of segments for a decision
//! that today costs one.
//!
//! `-o` gets no such rule. The user typed that path, so an absolute path,
//! a parent directory, or a name of any shape is what they asked for.

const std = @import("std");
const zurl_core = @import("zurl-core");

/// For `safe.controlLen` alone. The rule for "a byte a server chose that a
/// terminal or a file system must not get" lives in one place, and this
/// file asks it rather than keep a second copy. See `src/cli/safe.zig`.
const safe = @import("safe.zig");

const Io = std.Io;

/// The longest `-O` name zurl accepts, in bytes.
///
/// 255 is `NAME_MAX` on Linux, and no common filesystem takes a longer
/// entry name. The bound lives here rather than in the `open` syscall so
/// a long name gets a sentence that names the limit, and so a segment
/// past the bound never reaches `checkBytes` or the dot check at all.
pub const max_name_len: usize = 255;

/// The name `-O` writes when the url's last path segment names nothing
/// zurl can use.
///
/// curl 8.21.0 writes this exact name in that case, checked directly
/// against the real program, and zurl matches it rather than fail: a
/// working script that runs `curl -O` against a url ending in `/` gets a
/// file and exit 0 today, and a fault it never asked for from a stricter
/// zurl would be a regression, not a safety gain, because curl's own rule
/// already stays inside the working directory.
pub const fallback_name: []const u8 = "curl_response";

/// Why zurl will not take a file name from a url.
pub const NameError = error{
    /// The url does not parse, so it holds no path to read a name from.
    InvalidUrl,
    /// The name reads as a path and not as one new entry in the working
    /// directory.
    UnsafeName,
    /// The name holds a control code point no file name may carry: a NUL,
    /// another C0 control byte, a DEL, or a C1 control spelled in UTF-8.
    /// `safe.controlLen` is the rule.
    UnsafeByte,
    /// The name is longer than `max_name_len`.
    NameTooLong,
};

/// What `checkName` decided to do with a `-O` name.
pub const Verdict = union(enum) {
    /// Write these bytes, unchanged, as the file name. Borrows from the
    /// name `checkName` was given.
    write: []const u8,
    /// The segment named nothing zurl can use. Write `fallback_name`
    /// instead.
    fallback,
};

/// Returns the file name `-O` takes from `url_text`, or `fallback_name`.
///
/// The name is the text after the last `/` of the url's path, exactly as
/// the url wrote it. The result borrows from `url_text`, unless
/// `checkName` chose `fallback_name`, so `url_text` must outlive it.
pub fn nameFromUrl(url_text: []const u8) NameError![]const u8 {
    const parsed = zurl_core.url.parse(url_text) catch return error.InvalidUrl;
    const segment = lastSegment(parsed.path);
    return switch (try checkName(segment)) {
        .write => |name| name,
        .fallback => fallback_name,
    };
}

/// The longest `Content-Disposition` value `nameFromDisposition` reads.
///
/// The header comes from the server, so its length is the server's choice.
/// The scan below walks the value once for each parameter, so a bound
/// keeps that walk cheap. 1024 bytes holds far more than any real
/// disposition, and a name past `max_name_len` is refused later anyway.
pub const max_disposition_len: usize = 1024;

/// What `-J` found in a `Content-Disposition` header.
pub const HeaderName = union(enum) {
    /// Write these bytes as the file name. Borrows from the header value.
    write: []const u8,
    /// The header named no file this build can use, so `-O`'s own name
    /// from the url stands instead.
    none,
};

/// Returns the file name `-J` takes from a `Content-Disposition` value.
///
/// **The bytes come from the server, so they are the most untrusted name
/// zurl ever writes.** A url at least passed through the user's hands; a
/// response header did not. The rule that judges the result is therefore
/// the very same `checkName` that judges a `-O` name, and there is no
/// second copy of it here. This function does one job `checkName` cannot
/// do for itself: it cuts the header's own value down to one path segment
/// first, exactly as `lastSegment` cuts a url path down for
/// `nameFromUrl`. `checkName` then reads that segment and answers.
///
/// **Measured against curl 8.21.0, with a loopback server.** The parameter
/// scan below is curl's own, byte for byte:
///
/// ```
/// filename="hello.txt"      writes hello.txt
/// filename=plain.txt        writes plain.txt, an unquoted token
/// filename="one.txt"; filename="two.txt"   writes one.txt, the first wins
/// FILENAME="upper.txt"      no name: the match is case sensitive
/// filename = "spaced.txt"   no name: no space may sit before the =
/// filename*=UTF-8''star.txt no name: curl reads no encoded parameter
/// attachment                no name: the header names no parameter
/// ```
///
/// A value that names no file gives `.none`, and the caller then keeps the
/// name `-O` already took from the url. curl does the same, measured: a
/// response with no `Content-Disposition` at all writes the url's own last
/// segment.
///
/// **The path part is cut off, and never refused.** curl strips everything
/// up to the last `/`, then everything up to the last `\`, so
/// `filename="../../evil.txt"` writes `evil.txt` into the working
/// directory and `filename="/tmp/evil.txt"` writes `evil.txt` there too.
/// Both measured against the real program. zurl cuts the same two ways, so
/// it writes the same file curl does, and `checkName` still reads the
/// result: a separator that survived the cut is refused, which is the
/// backstop that makes this safe whatever the header holds.
///
/// **Two shapes answer `.none` here where curl exits 23.** A header naming
/// `.`, `..`, or nothing at all reaches `fopen` under curl, which fails,
/// and curl reports a write fault. `checkName` calls all three "no usable
/// name", so zurl keeps the url's name and finishes the transfer. That is
/// the one rule reused rather than a second rule written, and the file it
/// writes still lands inside the working directory.
pub fn nameFromDisposition(value: []const u8) NameError!HeaderName {
    if (value.len > max_disposition_len) return .none;
    const raw = dispositionFilename(value) orelse return .none;
    const segment = lastNameSegment(raw);
    return switch (try checkName(segment)) {
        .write => |name| .{ .write = name },
        .fallback => .none,
    };
}

/// Returns the raw text of the first `filename=` parameter in `value`, or
/// null when the header names none.
///
/// This is curl's own scan, and it is written the way curl writes it
/// because the two must agree on which byte starts the name. Each round
/// skips forward to the next letter, asks whether the nine bytes there
/// spell `filename=` exactly, and jumps to the byte after the next `;`
/// when they do not.
///
/// The value is quoted with `"` or `'`, and ends at the matching quote, or
/// it is a bare token that ends at the next `;` or at the end of the
/// header.
///
/// The loop is bounded twice: `value.len` is bounded by
/// `max_disposition_len` before this runs, and every round moves `at`
/// forward by at least one byte.
fn dispositionFilename(value: []const u8) ?[]const u8 {
    const marker = "filename=";
    var at: usize = 0;
    while (at < value.len) {
        // Forward to the next letter, which is where a parameter name may
        // start. curl skips every byte that is not a letter here.
        while (at < value.len and !std.ascii.isAlphabetic(value[at])) at += 1;
        if (at + marker.len > value.len) return null;

        if (!std.mem.eql(u8, value[at..][0..marker.len], marker)) {
            // Not this parameter. Forward past the next `;`, which is
            // where the next one starts. A value with no further `;` ends
            // the scan.
            const next = std.mem.indexOfScalarPos(u8, value, at, ';') orelse return null;
            at = next + 1;
            continue;
        }

        const rest = value[at + marker.len ..];
        if (rest.len == 0) return null;
        if (rest[0] == '"' or rest[0] == '\'') {
            const quote = rest[0];
            const end = std.mem.indexOfScalarPos(u8, rest, 1, quote) orelse return rest[1..];
            return rest[1..end];
        }
        const end = std.mem.indexOfScalar(u8, rest, ';') orelse rest.len;
        return rest[0..end];
    }
    return null;
}

/// Returns the text after the last `/` or `\` in `name`.
///
/// **This is what keeps a header name one entry in the working
/// directory.** A `Content-Disposition` value carries whatever the server
/// wrote, so it may spell a whole path, an absolute one included.
/// `lastSegment` cuts a url path on `/` alone, because a url path holds no
/// other separator; a header value holds both, and curl cuts on both.
/// Measured: `filename="..\\..\\evil2.txt"` writes `evil2.txt`.
fn lastNameSegment(name: []const u8) []const u8 {
    var cut = name;
    if (std.mem.lastIndexOfScalar(u8, cut, '/')) |at| cut = cut[at + 1 ..];
    if (std.mem.lastIndexOfScalar(u8, cut, '\\')) |at| cut = cut[at + 1 ..];
    return cut;
}

/// Returns the sentence that tells the user why zurl refused a `-J` name.
///
/// The sentence names no part of the header. The bytes came from the
/// server, and a message that echoed them would put a string the server
/// chose into a log. `src/cli/safe.zig` masks a control byte but nothing
/// here needs the header's text to act.
pub fn explainHeaderName(err: NameError) []const u8 {
    return switch (err) {
        // `nameFromDisposition` parses no url, so this cannot arise. The
        // arm stays because `NameError` is one set and a silent
        // `unreachable` on input is never right.
        error.InvalidUrl => "-J found a name in the header that zurl cannot read",
        error.UnsafeName => "-J found a name in the header that is a path, not a file name",
        error.UnsafeByte => "-J found a name in the header with a byte no file name may carry",
        error.NameTooLong => std.fmt.comptimePrint(
            "-J found a name in the header longer than {d} bytes",
            .{max_name_len},
        ),
    };
}

/// Returns the text after the last `/` in `path`.
///
/// `zurl_core.url.parse` gives a path that always starts with `/`, and it
/// has already cut the query and the fragment off. A path with no `/` at
/// all cannot reach here, and the whole path is the answer if one ever
/// does.
fn lastSegment(path: []const u8) []const u8 {
    const cut = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[cut + 1 ..];
}

/// The one rule that decides whether zurl writes a `-O` name.
///
/// `segment` is the raw, still-escaped text `lastSegment` cut from the
/// url's path. See this file's own doc comment for what each verdict
/// means and why the check reads the decoded form only far enough to ask
/// whether the segment names nothing.
///
/// A name that fails is a runtime fault and never an assertion. The name
/// comes from a url, and a url is input.
pub fn checkName(segment: []const u8) NameError!Verdict {
    if (hasNoUsableName(segment)) return .fallback;

    // Bounded before `checkBytes` walks it, so a segment with no bound of
    // its own never costs more than one comparison.
    if (segment.len > max_name_len) return error.NameTooLong;

    try checkBytes(segment);
    return .{ .write = segment };
}

/// Whether `segment` is empty, or decodes whole to `.` or `..`.
///
/// Percent-decoding never grows a string, so a decoded result of one or
/// two bytes can only come from a raw segment of six bytes or fewer: two
/// escapes of three bytes each is the longest way to spell two bytes. A
/// longer segment is turned away before the decoder runs, so this never
/// costs more than a length check for an ordinary name.
///
/// A segment whose escapes do not decode is not a match here: it cannot
/// read as `.` or `..` either way, so it falls through to `checkName`'s
/// other rules like any other name. curl 8.21.0 agrees: `100%` writes as
/// a literal six-byte name, checked against the real program.
fn hasNoUsableName(segment: []const u8) bool {
    if (segment.len == 0) return true;
    if (segment.len > 6) return false;

    if (std.mem.indexOfScalar(u8, segment, '%') == null) {
        return std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..");
    }

    var buf: [6]u8 = undefined;
    const decoded = zurl_core.url.percentDecode(&buf, segment) catch return false;
    return std.mem.eql(u8, decoded, ".") or std.mem.eql(u8, decoded, "..");
}

/// Whether the raw bytes of a name stay one new entry in the working
/// directory.
///
/// Two shapes fail.
///
/// - `/` and `\` split a name into a path. `/` is the separator zurl runs
///   on and `\` is the separator on Windows, which zurl also builds for.
///   A name that holds either one would reach a directory the url chose.
/// - A control code point, which is what `safe.controlLen` names. A NUL
///   ends a path for the operating system, so a name holding one would
///   reach a shorter path than the name reads. The others make a name a
///   terminal cannot show, and one of them makes a name a terminal acts
///   on.
///
/// **The control rule reads code points and not bytes, and it is
/// `safe.controlLen`.** An earlier version of this function refused
/// `0x00...0x1f` and `0x7f` and passed every byte over `0x7f`, so the two
/// bytes `0xc2 0x9b` reached `open`. A UTF-8 terminal decodes those two as
/// U+009B, the CSI, and acts on what follows them exactly as it acts on an
/// ESC and a `[`. The file name `<CSI>31mred.txt` then colours the output
/// of any `ls` that prints it. curl 8.21.0 writes that file, so this is
/// zurl being stricter than curl and not zurl fixing a divergence.
///
/// The rule lives in `safe.zig` because `-w` asks the same question of the
/// same kind of bytes. Two copies of it drifted once already, which is how
/// the C1 half went missing here.
///
/// A leading `-` passes. curl writes such a name too, and zurl never
/// hands the name to a shell: it opens the file relative to the working
/// directory and passes the bytes to one `open` call.
fn checkBytes(name: []const u8) NameError!void {
    var index: usize = 0;
    while (index < name.len) {
        switch (name[index]) {
            '/', '\\' => return error.UnsafeName,
            else => {},
        }
        if (safe.controlLen(name[index..]) != 0) return error.UnsafeByte;
        index += 1;
    }
}

/// Returns the zurl fault for a `-O` name zurl will not use.
///
/// A url that does not parse is the same fault the transfer would have
/// reported, so it keeps that error and its exit code, 3. Every other
/// shape is a failure to write the output file, which curl calls
/// `CURLE_WRITE_ERROR` and exits 23 for. Checked against curl 8.21.0: an
/// `-o` path curl cannot open exits 23, and a name past curl's own length
/// bound exits 23 too.
pub fn faultFor(err: NameError) zurl_core.Error {
    return switch (err) {
        error.InvalidUrl => error.InvalidUrl,
        error.UnsafeName, error.UnsafeByte, error.NameTooLong => error.WriteError,
    };
}

/// Returns the sentence that tells the user why zurl refused the name.
///
/// The sentence names no part of the url. The name zurl refused is a
/// slice of the url the user typed, and a `-O` name says nothing a reader
/// needs that the flag name does not. A password could not reach a
/// message through this path in any case:
/// `zurl_core.Diagnostics.record` masks whatever url it is given.
pub fn explain(err: NameError) []const u8 {
    return switch (err) {
        error.InvalidUrl => "-O needs a url it can parse",
        error.UnsafeName => "-O found a name in the url that is a path, not a file name",
        error.UnsafeByte => "-O found a name in the url with a byte no file name may carry",
        // Built from the bound itself, so the sentence cannot go stale if
        // `max_name_len` moves.
        error.NameTooLong => std.fmt.comptimePrint(
            "-O found a name in the url longer than {d} bytes",
            .{max_name_len},
        ),
    };
}

/// How large a buffer `toFile` gives its file writer. Large enough that a
/// big body costs few write calls, and small enough for the stack of the
/// one thread that runs a transfer.
const write_buffer_len = 32 * 1024;

/// The flags that change where `toFile` puts the bytes, and what it leaves
/// behind.
///
/// Every field is off by default, so a caller that names none gets exactly
/// the behaviour `toFile` had before these flags existed: one file,
/// truncated, written from the start.
pub const FileOptions = struct {
    /// `--create-dirs`: create the directory tree the path names, before
    /// the file is opened.
    ///
    /// Measured against curl 8.21.0: `-o cd/a/b/c.txt` with no such
    /// directory exits 23 and writes nothing, and the same command with
    /// `--create-dirs` exits 0 and creates `cd/a/b`.
    create_dirs: bool = false,
    /// `--no-clobber`: never overwrite a file that already exists. See
    /// `freeName`.
    no_clobber: bool = false,
    /// `-J`: stop rather than overwrite a file that already exists.
    ///
    /// **This is not `--no-clobber`, and the difference is the point.**
    /// `--no-clobber` picks the next free name in the `.1`, `.2` series
    /// and writes there. This writes nothing at all and fails the url.
    ///
    /// It exists for `-J` alone, and `-J` is the one flag that lets a
    /// server choose the name of a file zurl writes. A server that could
    /// also overwrite an existing file could replace any file in the
    /// working directory whose name it can guess. curl keeps the same
    /// rule for the same flag: measured against curl 8.21.0, `-OJ` onto a
    /// directory already holding the header's name exits 23 and leaves
    /// the old bytes untouched.
    ///
    /// `no_clobber` outranks it. That pair still writes, under the next
    /// free name, which is what curl does too: measured, `-OJ
    /// --no-clobber` onto an existing `cd.txt` wrote `cd.txt.1`.
    refuse_existing: bool = false,
    /// `-C`: where in the file the body starts. Zero writes from the
    /// start of a truncated file, which is the behaviour with no flag.
    ///
    /// A value above zero turns the truncation off, so the bytes already
    /// in the file stay.
    offset: u64 = 0,
    /// `--create-file-mode`: the octal mode a file this call creates gets,
    /// or null for the default of the platform.
    ///
    /// **It reaches the `create` call and is not a `chmod` afterwards.**
    /// A file created wide open and narrowed a moment later is readable
    /// for that moment, and the whole point of the flag is a body that no
    /// other user ever reads.
    ///
    /// The umask of the process still applies, which is what curl says of
    /// its own flag and what every `open` call does. A mode has no meaning
    /// on a platform with no file modes, and the field is ignored there.
    ///
    /// A file that already exists keeps the mode it has. That is what
    /// `open` does with `O_CREAT` and it is what curl does.
    mode: ?u32 = null,
    /// `-R`, `--remote-time`: the time the server said the body was last
    /// changed, in seconds since the epoch, or null to leave the file with
    /// the time of the write.
    ///
    /// The caller reads `Last-Modified` and parses it. This call only
    /// stamps the file, and it stamps it before the file is closed, so no
    /// other process sees the wrong time on a file zurl has finished
    /// writing.
    modified_at: ?i64 = null,
    /// `--remove-on-error`: delete the file when the transfer did not
    /// finish, instead of leaving the bytes that did arrive.
    ///
    /// **A resume never deletes.** `offset` above zero says the file held
    /// the first part of the body before this call started, and those
    /// bytes are not this transfer's to throw away. curl removes the file
    /// either way; zurl keeps the earlier bytes, because a `-C` that
    /// failed and then deleted the file it was adding to would destroy the
    /// very thing the flag exists to build on.
    remove_on_error: bool = false,
    /// `-i`, `--show-headers`: bytes to write into the file before the
    /// body. Empty when the flag was not given.
    ///
    /// It goes through the same writer as the body, so nothing can come
    /// between the head and the bytes it describes, and it counts toward
    /// nothing else: `offset` still names where the *body* would have
    /// resumed, and `Args` refuses `-C` beside a flag that would move it.
    prefix: []const u8 = "",
    /// `-O` and `-J`: stop rather than write through a symbolic link that
    /// already sits at the destination.
    ///
    /// **This is on when the name came from the url or from a header, and
    /// off when the user typed it.** That is the same line `-o` and `-O`
    /// are already divided by everywhere else in this file. A `-o` path is
    /// what the user asked for, symbolic link and all, and `-o
    /// /dev/stdout` is a symbolic link on Linux that a script depends on.
    /// A `-O` name is the last segment of a url, which the threat model
    /// calls attacker-chosen, so a link already at that name sends the
    /// body to a file no part of the command line ever named.
    ///
    /// **zurl is stricter than curl here, on purpose.** Measured against
    /// curl 8.21.0 with a loopback server, a working directory holding
    /// `tgt.bin` as a symbolic link to `victim.txt`, and `victim.txt`
    /// holding `VICTIM`:
    ///
    /// ```
    /// curl -o tgt.bin URL          exit 0, victim.txt became the body
    /// curl -O URL/tgt.bin          exit 0, victim.txt became the body
    /// curl --no-clobber -o tgt.bin exit 0, wrote tgt.bin.1, victim kept
    /// ```
    ///
    /// So curl follows the link for both flags. zurl keeps curl's answer
    /// for `-o`, where the user named the path, and refuses for `-O` and
    /// `-J`, where a url or a server named it. A refusal costs a download
    /// the user can repeat with `-o`; following costs a file the user
    /// never named.
    ///
    /// **The check is a `lstat` before the create, and that is one
    /// syscall behind the open.** An attacker who can replace a plain file
    /// with a link between the two calls wins, and there is no
    /// `O_NOFOLLOW` in the `std.Io` create this build uses to close it.
    /// The same attacker already has write access to the working
    /// directory, which is out of the threat model. `-J` needs no window
    /// at all: its create is exclusive, so a link already there fails the
    /// create itself.
    refuse_symlink: bool = false,
};

/// How many suffixed names `--no-clobber` tries after the one the user
/// named.
///
/// Measured against curl 8.21.0: with `t.out` and `t.out.1` through
/// `t.out.99` all present, `--no-clobber -o t.out` exits 23 and creates no
/// further file. So curl stops after `.99`.
const no_clobber_suffix_max: u32 = 99;

/// How long a name `--no-clobber` builds may be.
///
/// `PATH_MAX` on Linux is 4096, and a longer path is refused by the
/// operating system anyway. The suffix adds at most four bytes, `.` and
/// three digits, so this holds every name the search can build.
const no_clobber_name_max = std.fs.max_path_bytes;

/// Which side of `toFile` stopped.
pub const StreamError = error{
    /// The peer stopped. `Response.body` says only that a read failed, so
    /// the caller asks its `Client` which fault it was.
    ReadFailed,
    /// The file stopped. `d` holds the operating system's own name for
    /// the cause, such as `FileNotFound` or `AccessDenied`.
    WriteError,
};

/// Writes everything left in `body` to `path`, relative to the working
/// directory.
///
/// **A failed transfer leaves a partial file, and this is deliberate.**
/// curl 8.21.0 does the same: it opens the file, truncates it, and writes
/// the body as it arrives, so a transfer that stops halfway leaves the
/// bytes that did arrive. Measured against the real program. zurl's own
/// `zurl.download.toFile` behaves the opposite way, staging through a
/// temporary file so a cache never publishes a partial artifact, and the
/// CLI does not use it for three reasons. It hashes every byte with
/// SHA-256, which the CLI throws away. Its atomic replace needs to create
/// and rename inside the destination directory, so `-o /dev/null` and
/// `-o` onto any other special file would fail. And a user who ran curl
/// expects curl's file, partial bytes and all.
///
/// `options` carries the three flags that change where the bytes land.
/// See `FileOptions`.
pub fn toFile(
    io: Io,
    path: []const u8,
    body: *Io.Reader,
    options: FileOptions,
    d: ?*zurl_core.Diagnostics,
) StreamError!void {
    if (options.create_dirs) try createParentDirs(io, path, d);

    // The name to write, which `--no-clobber` may move off `path`, and
    // the storage behind it. `chosen` borrows from `name_buffer` whenever
    // a suffix was added, so both live to the end of this function.
    var name_buffer: [no_clobber_name_max]u8 = undefined;
    const chosen = if (options.no_clobber)
        try freeName(io, path, &name_buffer, options.mode, d)
    else
        path;

    // **A `-O` or `-J` name never writes through a symbolic link.** See
    // `FileOptions.refuse_symlink` for the measurement against curl and
    // for why `-o` keeps curl's answer. A `--no-clobber` name needs no
    // check of its own, because `freeName` took it with an exclusive
    // create and the file behind it is therefore new, but running the
    // check on every such name costs one `lstat` and keeps one rule.
    if (options.refuse_symlink) try refuseSymlink(io, chosen, d);

    // Truncates an existing file, which is curl's own behaviour for `-o`
    // and `-O`.
    //
    // **`-C` is the one case that must not truncate.** A resume writes
    // the answer into a file that already holds the first part of the
    // body, so `truncate` goes off and the writer seeks to the offset
    // below. Measured against curl 8.21.0: `-C 5` onto a file holding
    // `XXXXX` left those five bytes and wrote the answer after them.
    const resuming = options.offset > 0;

    // **`-J` never overwrites, and the check is the `open` call itself.**
    // An exclusive create is one syscall that both asks and takes, so no
    // other process can create the file between the question and the
    // answer. A stat followed by an open would leave exactly that window,
    // and the whole reason this option exists is a name a server chose.
    //
    // `freeName` already opened its own candidate exclusively, so a
    // `--no-clobber` run needs no second exclusive create and gets none.
    const exclusive = options.refuse_existing and !options.no_clobber and !resuming;
    var file = Io.Dir.cwd().createFile(io, chosen, .{
        .truncate = !resuming,
        .exclusive = exclusive,
        .permissions = permissionsFor(options.mode),
    }) catch |err|
        return writeFault(d, @errorName(err));
    defer file.close(io);

    // **The file goes away only on a path that failed, and only when the
    // caller asked.** `removed` stays false on every success, so a
    // finished transfer cannot reach the delete below.
    var failed = false;
    defer if (failed and options.remove_on_error and !resuming) {
        // A delete that itself fails changes nothing a user can act on:
        // the transfer already failed, and the fault it earned is the one
        // that reaches standard error. Recovery is never silent, so the
        // reason is recorded when nothing else has claimed the message.
        Io.Dir.cwd().deleteFile(io, chosen) catch |err| {
            if (d) |dg| {
                if (dg.message == null) dg.message = @errorName(err);
            }
        };
    };

    var write_buf: [write_buffer_len]u8 = undefined;
    var file_writer = file.writer(io, &write_buf);
    if (resuming) file_writer.seekTo(options.offset) catch |err| {
        failed = true;
        return writeFault(d, @errorName(err));
    };

    if (options.prefix.len > 0) file_writer.interface.writeAll(options.prefix) catch {
        failed = true;
        return writeFault(d, @errorName(file_writer.err orelse error.Unexpected));
    };

    if (body.streamRemaining(&file_writer.interface)) |_| {
        // Bytes the last stream call took into the writer's own buffer
        // are not on disk until this runs.
        file_writer.flush() catch |err| {
            failed = true;
            return writeFault(d, @errorName(err));
        };
    } else |err| switch (err) {
        error.ReadFailed => {
            // The peer stopped. The bytes that did arrive still belong in
            // the file, because curl leaves them there, so the flush runs
            // on this path too. A flush that fails wins over the read
            // fault: a file zurl cannot even finish writing is the fault
            // the user must act on first.
            failed = true;
            file_writer.flush() catch |flush_err| return writeFault(d, @errorName(flush_err));
            return error.ReadFailed;
        },
        // The file stopped. `file_writer.err` holds the real cause, such
        // as a full disk. No flush follows: the writer already failed to
        // drain, and a second try would only rename the same fault.
        error.WriteFailed => {
            failed = true;
            return writeFault(
                d,
                @errorName(file_writer.err orelse error.Unexpected),
            );
        },
    }

    // **The stamp goes on before the close.** A file zurl has finished
    // writing must never be seen by another process with the time of the
    // write on it, and then the server's time a moment later. A stamp that
    // does not take is not a failed transfer: the body is whole and on
    // disk, so the fault is recorded and the transfer stands.
    if (options.modified_at) |seconds| {
        file.setTimestamps(io, .{
            .modify_timestamp = .{ .new = .{ .nanoseconds = @as(i96, seconds) * std.time.ns_per_s } },
        }) catch |err| {
            if (d) |dg| {
                if (dg.message == null) dg.message = @errorName(err);
            }
        };
    }
}

/// The permissions a file `toFile` creates gets.
///
/// A null mode is the default of the platform, which is what every write
/// before `--create-file-mode` existed used.
///
/// A named mode reaches the `create` call on a platform that has file
/// modes at all. A platform with none, such as Windows, has nothing to
/// apply it to, so the default stands there. `--help` says so.
fn permissionsFor(mode: ?u32) Io.File.Permissions {
    const named = mode orelse return .default_file;
    if (!@hasDecl(Io.File.Permissions, "fromMode")) return .default_file;
    return .fromMode(@intCast(named));
}

/// Creates the directory tree `path` names, up to but not including the
/// last segment. This is `--create-dirs`.
///
/// A path with no directory part, such as `out.bin`, names the working
/// directory, which already exists, so nothing is created.
///
/// A tree that is already there is not a fault: `createDirPath` reports
/// success for it, the way `mkdir -p` does, and that is what curl's flag
/// means.
fn createParentDirs(io: Io, path: []const u8, d: ?*zurl_core.Diagnostics) StreamError!void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0) return;
    Io.Dir.cwd().createDirPath(io, parent) catch |err|
        return writeFault(d, @errorName(err));
}

/// The first name in the `--no-clobber` series that no file holds yet.
///
/// The series is `path`, then `path.1`, `path.2`, and so on. Measured
/// against curl 8.21.0 with a loopback server: three runs of
/// `--no-clobber -o t.out` onto an existing `t.out` left `t.out`
/// untouched and created `t.out.1`, `t.out.2`, and `t.out.3`, each holding
/// one body. `-O` follows the same series.
///
/// **Every name is taken with an exclusive create.** A search that
/// stats the name and opens it afterward would let a second process
/// create the same file in between, and the second writer would truncate
/// the first one's bytes. The file this opens is closed again straight
/// away, so the caller re-opens it by name, which leaves that same window
/// open for one instant. That is curl's own window too, and closing it
/// would need `toFile` to hand the open handle down instead of the path.
///
/// A series with no free name left is `error.WriteError`, which is exit
/// 23. That is curl's answer as well, measured: with `.1` through `.99`
/// all present, curl exits 23 and writes nothing. A body silently thrown
/// away would be worse than either.
///
/// **`mode` is `--create-file-mode`, and it belongs on this create and not
/// only on the caller's.** This function is the call that brings the file
/// into being, so this is the only place the mode can reach. `toFile`
/// re-opens the same name afterward, and `open` ignores a mode for a file
/// that already exists, so a create here with no mode left
/// `--create-file-mode` doing nothing at all under `--no-clobber`: with a
/// `0o022` umask, `--create-file-mode 0600 --no-clobber -o b.bin` gave a
/// `0644` file and exit 0. A body the user asked to keep at `0600` was
/// readable by every other user on the machine. There is no curl parity
/// argument for that: curl's own `--create-file-mode` does not reach a
/// plain `-o` download at all, so the extension is zurl's and the hole
/// was zurl's too.
fn freeName(
    io: Io,
    path: []const u8,
    buffer: []u8,
    mode: ?u32,
    d: ?*zurl_core.Diagnostics,
) StreamError![]const u8 {
    var candidate: []const u8 = path;
    var suffix: u32 = 0;
    while (true) {
        const file = Io.Dir.cwd().createFile(io, candidate, .{
            .exclusive = true,
            .permissions = permissionsFor(mode),
        }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                if (suffix == no_clobber_suffix_max) return writeFault(d, "NoClobberNamesExhausted");
                suffix += 1;
                candidate = std.fmt.bufPrint(buffer, "{s}.{d}", .{ path, suffix }) catch
                    return writeFault(d, "NameTooLong");
                continue;
            },
            else => return writeFault(d, @errorName(err)),
        };
        file.close(io);
        return candidate;
    }
}

/// Fails when `path` names a symbolic link. This is
/// `FileOptions.refuse_symlink`, and that field carries the measurement
/// against curl and the reason the rule covers `-O` and not `-o`.
///
/// A path that names nothing is not a fault: the create that follows makes
/// the file, and there is no link to follow. Every other reason a `lstat`
/// can fail, such as a missing directory in the path, is left to that same
/// create, which reports the operating system's own cause for it. A
/// refusal here that named a cause the create would name better would tell
/// the user about the wrong step.
fn refuseSymlink(io: Io, path: []const u8, d: ?*zurl_core.Diagnostics) StreamError!void {
    const stat = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return;
    if (stat.kind == .sym_link) return writeFault(d, "DestinationIsSymbolicLink");
}

/// Writes the response head blocks `block` to `path`, relative to the
/// working directory. This is `-D`.
///
/// `block` is `zurl.Response.headers`: the status line through the empty
/// line of every response head the transfer received, byte for byte as the
/// peer wrote them, CRLF line endings and all. curl 8.21.0 writes exactly
/// these bytes, and writes one block for each hop of a followed redirect,
/// checked against the real program.
///
/// **This appends. It does not truncate.** `-D` names one file for a
/// whole run, and curl 8.21.0 writes every url's head blocks into it, one
/// after the other: measured with two loopback servers, `curl -D h.txt -o
/// /dev/null URL1 URL2` left eight lines in `h.txt`, both heads. zurl used
/// to truncate on each url, so a run over two urls kept the last head and
/// said nothing about the first. `emptyHeadersFile` does the one
/// truncation, once, before the first transfer.
///
/// A `-D` path that cannot be opened is `error.WriteError`, and `d` then
/// holds the operating system's own name for the cause.
pub fn headersToFile(
    io: Io,
    path: []const u8,
    block: []const u8,
    d: ?*zurl_core.Diagnostics,
) error{WriteError}!void {
    // `truncate = false` keeps what earlier urls wrote. The writer still
    // starts at offset zero, so the seek below is what makes this an
    // append and not an overwrite.
    var file = Io.Dir.cwd().createFile(io, path, .{ .truncate = false }) catch |err|
        return @errorCast(writeFault(d, @errorName(err)));
    defer file.close(io);

    const end = file.stat(io) catch |err| return @errorCast(writeFault(d, @errorName(err)));

    var write_buf: [write_buffer_len]u8 = undefined;
    var file_writer = file.writer(io, &write_buf);
    file_writer.seekTo(end.size) catch |err|
        return @errorCast(writeFault(d, @errorName(err)));

    file_writer.interface.writeAll(block) catch
        return @errorCast(writeFault(d, @errorName(file_writer.err orelse error.Unexpected)));
    file_writer.flush() catch |err| return @errorCast(writeFault(d, @errorName(err)));
}

/// The longest entity tag `etagToFile` writes.
///
/// The tag comes from the server, so its length is the server's choice.
/// A real tag is a short quoted string; a value past this bound is written
/// cut to it rather than refused, because a tag that does not match is
/// exactly what `--etag-compare` is for and a truncated one simply does
/// not match.
pub const max_etag_len: usize = 8 * 1024;

/// Writes `tag` and one newline to `path`. This is `--etag-save`.
///
/// **The bytes are the header value, unchanged.** Measured against curl
/// 8.21.0: `ETag: "abc123"` left the nine bytes `"abc123"\n`, and
/// `ETag: W/"weak1"` left `W/"weak1"\n`. curl neither adds a quote nor
/// takes one off, so neither does this, and a file zurl wrote reads back
/// through `--etag-compare` as the same tag.
///
/// An empty `tag` writes an empty file. curl creates the file even for a
/// response that carried no `ETag` at all, measured, and leaving a tag
/// from an earlier run in place would be worse than an empty file: the
/// next `--etag-compare` would claim a version the server never sent.
///
/// The file is truncated, so one run's tag never lands after another's.
pub fn etagToFile(
    io: Io,
    path: []const u8,
    tag: []const u8,
    d: ?*zurl_core.Diagnostics,
) error{WriteError}!void {
    var file = Io.Dir.cwd().createFile(io, path, .{}) catch |err|
        return @errorCast(writeFault(d, @errorName(err)));
    defer file.close(io);

    if (tag.len == 0) return;

    var write_buf: [256]u8 = undefined;
    var file_writer = file.writer(io, &write_buf);
    file_writer.interface.writeAll(tag[0..@min(tag.len, max_etag_len)]) catch
        return @errorCast(writeFault(d, @errorName(file_writer.err orelse error.Unexpected)));
    file_writer.interface.writeByte('\n') catch
        return @errorCast(writeFault(d, @errorName(file_writer.err orelse error.Unexpected)));
    file_writer.flush() catch |err| return @errorCast(writeFault(d, @errorName(err)));
}

/// Creates `path` empty, or truncates it if it already holds something.
/// This is the one truncation of a `-D` run, and `src/cli/run.zig` does it
/// once, before the first transfer.
///
/// **A run whose transfers all fail still leaves the file empty.**
/// Measured: `curl -D h.txt <a url that refuses the connection>` exits 7
/// and leaves `h.txt` there and empty, whatever it held before. A zurl
/// that truncated at the first head instead would leave a stale file
/// behind, and a script that read it would read the previous run's
/// headers as this run's.
pub fn emptyHeadersFile(
    io: Io,
    path: []const u8,
    d: ?*zurl_core.Diagnostics,
) error{WriteError}!void {
    var file = Io.Dir.cwd().createFile(io, path, .{}) catch |err|
        return @errorCast(writeFault(d, @errorName(err)));
    file.close(io);
}

/// Why `-D` has nothing to write, when the engine dropped the head blocks
/// at a bound of its own.
///
/// A part of a header block reads exactly like a whole one, so zurl writes
/// no file at all and says why. curl has no such bound and writes the
/// blocks; a zurl that quietly wrote half of them would be worse than
/// either.
pub const headers_oversize_message: []const u8 =
    "-D: the response headers passed the limit the engine keeps, so none were kept";

/// Why `-D` and `-I` have nothing to write, when the protocol that ran the
/// transfer reports no response head at all.
///
/// **Every protocol outside http and https answers this way in this
/// build.** The nine packages that speak ftp, the three mail protocols,
/// telnet, ws, dict, gopher, tftp, and file set no `Response.headers` at
/// all, so `-D` and `-I` cannot be satisfied for any of them. curl invents
/// a head for some of them, such as a `SIZE` and an `MDTM` for
/// `-I ftp://host/file`, and zurl has none to invent.
///
/// The refusal is `error.NotBuiltIn`, exit 4, and not a write fault: no
/// write went wrong. A user who reads a write fault looks at the file
/// system, and the cause is that this build has no head for this protocol.
pub const headers_missing_message: []const u8 =
    "this protocol reports no response headers in this build, so -D and -I " ++
    "have nothing to write. Only http and https report a head here.";

/// Records the operating system's own name for the cause in `d`, then
/// returns the fault for a file that would not take the body.
///
/// `Diagnostics.record` returns `zurl_core.Error`, a wider set than
/// `toFile` reports, and Zig lets no error value go unused. The cast
/// narrows the one error `record` was given back to the one error this
/// file returns.
fn writeFault(d: ?*zurl_core.Diagnostics, cause: []const u8) StreamError {
    return @errorCast(zurl_core.Diagnostics.record(d, error.WriteError, .{ .message = cause }));
}

const testing = std.testing;

test "nameFromUrl takes the last path segment" {
    try testing.expectEqualStrings("file.bin", try nameFromUrl("http://example.com/file.bin"));
    try testing.expectEqualStrings("c", try nameFromUrl("http://example.com/a/b/c"));
    // The query and the fragment are not part of the name. curl 8.21.0
    // writes `file.bin` for both of these too.
    try testing.expectEqualStrings("file.bin", try nameFromUrl("http://example.com/file.bin?v=2"));
    try testing.expectEqualStrings("file.bin", try nameFromUrl("http://example.com/file.bin#top"));
}

test "checkName drives every name shape through one rule" {
    // The table is the point of this test. Every shape zurl has a verdict
    // for is here, next to the shape it is easy to confuse it with, so a
    // change to the rule shows every case it moved. Checked against curl
    // 8.21.0 wherever the comment says so.
    const Case = struct { name: []const u8, want: NameError!Verdict, why: []const u8 };
    const w = struct {
        fn f(name: []const u8) NameError!Verdict {
            return .{ .write = name };
        }
    }.f;
    const cases = [_]Case{
        // Ordinary names.
        .{ .name = "file.bin", .want = w("file.bin"), .why = "a plain name" },
        .{ .name = ".bashrc", .want = w(".bashrc"), .why = "a hidden file is still one entry" },
        .{ .name = "...", .want = w("..."), .why = "only . and .. name an existing entry" },
        .{ .name = "-rf", .want = w("-rf"), .why = "zurl never hands the name to a shell" },
        .{ .name = "--", .want = w("--"), .why = "same reason as -rf" },
        .{ .name = "a b", .want = w("a b"), .why = "a space is an ordinary name byte" },

        // curl 8.21.0 never decodes a `-O` name before it writes it, so
        // every one of these is the literal, still-escaped text, not the
        // path or byte it would decode to.
        .{ .name = "a%20b", .want = w("a%20b"), .why = "written literally, curl 8.21.0 does the same" },
        .{ .name = "100%", .want = w("100%"), .why = "a % that does not decode is still a literal name" },
        .{ .name = "a%zzb", .want = w("a%zzb"), .why = "same reason, a non-hex escape" },
        .{
            .name = "a/b",
            .want = error.UnsafeName,
            .why = "a raw / still refuses. lastSegment never hands checkName one, but the rule must prove it anyway",
        },
        .{
            .name = "%2e%2e%2f%2e%2e%2fetc",
            .want = w("%2e%2e%2f%2e%2e%2fetc"),
            .why = "decodes to ../../etc, but curl 8.21.0 writes it literally, checked against the real program",
        },
        .{ .name = "a%2fb", .want = w("a%2fb"), .why = "decodes to a/b, curl 8.21.0 writes it literally" },
        .{ .name = "a%2Fb", .want = w("a%2Fb"), .why = "same, upper case" },
        .{
            .name = "%2fetc%2fpasswd",
            .want = w("%2fetc%2fpasswd"),
            .why = "decodes to an absolute path, curl 8.21.0 writes it literally",
        },

        // The shapes that name nothing zurl can use. Every one of these
        // gets `.fallback`, checked against curl 8.21.0's own
        // `curl_response`.
        .{ .name = "", .want = .fallback, .why = "an empty segment" },
        .{ .name = ".", .want = .fallback, .why = "names the working directory" },
        .{ .name = "..", .want = .fallback, .why = "names its parent" },
        .{ .name = "%2e", .want = .fallback, .why = "decodes to ., same verdict as the raw byte" },
        .{ .name = "%2E", .want = .fallback, .why = "decodes to ., upper case" },
        .{ .name = "%2e%2e", .want = .fallback, .why = "decodes to .." },
        .{ .name = "%2E%2E", .want = .fallback, .why = "decodes to .., upper case" },
        .{ .name = ".%2e", .want = .fallback, .why = "decodes to .., mixed raw and escaped" },
        .{ .name = "%2e.", .want = .fallback, .why = "decodes to .., mixed the other way" },

        // Bytes that must never reach a path. These are refusals, not a
        // shape curl 8.21.0 also refuses; see the file's own doc comment
        // for why zurl keeps them anyway.
        .{ .name = "a\x00b", .want = error.UnsafeByte, .why = "a raw NUL ends a path" },
        .{ .name = "a\nb", .want = error.UnsafeByte, .why = "a raw control byte" },
        .{ .name = "a\x7fb", .want = error.UnsafeByte, .why = "a raw DEL" },
        .{ .name = "a\\b", .want = error.UnsafeName, .why = "a raw Windows separator" },

        // The C1 controls, spelled the only way a UTF-8 terminal reads
        // them. `\xc2\x9b` is U+009B, the CSI, so the name below moves a
        // cursor and sets a colour in any program that prints it. curl
        // 8.21.0 writes this file; zurl refuses it.
        .{ .name = "\xc2\x9b31mred.txt", .want = error.UnsafeByte, .why = "a UTF-8 C1 CSI" },
        .{ .name = "a\xc2\x80b", .want = error.UnsafeByte, .why = "U+0080, the first C1" },
        .{ .name = "a\xc2\x9fb", .want = error.UnsafeByte, .why = "U+009F, the last C1" },

        // The boundary of that rule, from both sides. A name in an
        // ordinary language must still be written.
        .{ .name = "a\xc2\xa0b", .want = w("a\xc2\xa0b"), .why = "U+00A0, one past the C1 range" },
        .{ .name = "caf\xc3\xa9.txt", .want = w("caf\xc3\xa9.txt"), .why = "U+00E9, ordinary text" },
        .{
            .name = "\xe6\x97\xa5\xe6\x9c\xac.txt",
            .want = w("\xe6\x97\xa5\xe6\x9c\xac.txt"),
            .why = "U+65E5 carries 0x97 as a continuation byte, which is not a control",
        },
    };

    for (cases) |case| {
        const got = checkName(case.name);
        if (case.want) |want_verdict| {
            const got_verdict = got catch |e| {
                std.debug.print("case '{s}' ({s}) was refused: {s}\n", .{ case.name, case.why, @errorName(e) });
                return e;
            };
            switch (want_verdict) {
                .write => |want_name| {
                    testing.expectEqualStrings(want_name, got_verdict.write) catch |e| {
                        std.debug.print("case '{s}' ({s}) wrote the wrong name\n", .{ case.name, case.why });
                        return e;
                    };
                },
                .fallback => switch (got_verdict) {
                    .fallback => {},
                    .write => |got_name| {
                        std.debug.print(
                            "case '{s}' ({s}) wrote '{s}' instead of falling back\n",
                            .{ case.name, case.why, got_name },
                        );
                        return error.TestUnexpectedResult;
                    },
                },
            }
        } else |want_err| {
            testing.expectError(want_err, got) catch |e| {
                std.debug.print("case '{s}' ({s}) did not fail as expected\n", .{ case.name, case.why });
                return e;
            };
        }
    }
}

test "a name at the length bound passes and one byte past it does not" {
    var buf: [max_name_len + 1]u8 = @splat('x');
    try testing.expectEqualStrings(buf[0..max_name_len], (try checkName(buf[0..max_name_len])).write);
    try testing.expectError(error.NameTooLong, checkName(buf[0 .. max_name_len + 1]));
}

test "hasNoUsableName is bounded before it decodes, so a long run of escapes never reaches the decoder" {
    // A segment of more than six bytes cannot decode to one or two bytes,
    // so `checkName` must fall through to its other rules for one, not
    // read it as `.` or `..`. This name is nine `%41` escapes, decoding to
    // nine `A` characters: far longer than `.` or `..`, and far longer
    // than six bytes raw.
    var buf: [3 * 9]u8 = undefined;
    var i: usize = 0;
    while (i < buf.len) : (i += 3) {
        buf[i] = '%';
        buf[i + 1] = '4';
        buf[i + 2] = '1';
    }
    const verdict = try checkName(&buf);
    try testing.expectEqualStrings(&buf, verdict.write);
}

test "nameFromUrl falls back to curl_response when the url names nothing usable" {
    // Checked against curl 8.21.0: every one of these writes
    // `curl_response` and exits 0 on the real program.
    try testing.expectEqualStrings(fallback_name, try nameFromUrl("http://example.com/"));
    try testing.expectEqualStrings(fallback_name, try nameFromUrl("http://example.com"));
    try testing.expectEqualStrings(fallback_name, try nameFromUrl("http://example.com/a/.."));
    try testing.expectEqualStrings(fallback_name, try nameFromUrl("http://example.com/%2e%2e"));

    // `http://example.com/a/.` is the one shape here where zurl's answer
    // is not curl 8.21.0's: the real program walks back past the `.` and
    // writes `a`. `checkName` never looks past the last segment, so it
    // sees only `.` and falls back. `curl_response` is still a real file
    // and still exit 0, so the property this file exists to keep holds;
    // it is only curl's cleverer guess that zurl does not copy. See this
    // file's own doc comment.
    try testing.expectEqualStrings(fallback_name, try nameFromUrl("http://example.com/a/."));
}

test "nameFromUrl writes curl 8.21.0's own escaped names literally" {
    try testing.expectEqualStrings(
        "%2fetc%2fpasswd",
        try nameFromUrl("http://example.com/%2fetc%2fpasswd"),
    );
    try testing.expectEqualStrings("a%2fb", try nameFromUrl("http://example.com/dir/a%2fb"));
    try testing.expectError(error.InvalidUrl, nameFromUrl("http://"));
}

test "every name fault has a fault code and a sentence" {
    // A new member of `NameError` with no row here would reach the user as
    // a silent exit or a bare error name.
    inline for (@typeInfo(NameError).error_set.?) |field| {
        const err = @field(NameError, field.name);
        const code = zurl_core.errors.curlCode(faultFor(err));
        try testing.expect(code == 3 or code == 23);
        try testing.expect(explain(err).len > 0);
        try testing.expect(std.mem.startsWith(u8, explain(err), "-O "));
    }
}

test "toFile writes a body and truncates what was there before" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // `toFile` writes relative to the working directory, so the test names
    // a path inside the temporary directory rather than changing it.
    const path = try std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/out.bin",
        .{tmp.sub_path},
    );
    defer testing.allocator.free(path);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "out.bin", .data = "a much longer old file" });

    var body: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &body, .{}, null);

    const contents = try tmp.dir.readFileAlloc(testing.io, "out.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "toFile reports the operating system's own cause for a path it cannot open" {
    var body: Io.Reader = .fixed("payload");
    var d: zurl_core.Diagnostics = .{};

    try testing.expectError(
        error.WriteError,
        toFile(testing.io, "/nonexistent-zurl-output-dir/out.bin", &body, .{}, &d),
    );
    try testing.expectEqualStrings("FileNotFound", d.message.?);
    try testing.expectEqual(@as(?u32, 23), d.curl_code);
}

/// Builds the path a test names inside `tmp`, the way the tests above do.
///
/// `toFile` writes relative to the working directory, so a test names a
/// path inside the temporary directory rather than changing it.
fn tmpPath(tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        testing.allocator,
        ".zig-cache/tmp/{s}/{s}",
        .{ tmp.sub_path, name },
    );
}

test "--show-headers writes the head into the file before the body" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "head.bin");
    defer testing.allocator.free(path);

    var body: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &body, .{ .prefix = "HTTP/1.1 200 OK\r\n\r\n" }, null);

    const contents = try tmp.dir.readFileAlloc(testing.io, "head.bin", testing.allocator, .limited(128));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n\r\npayload", contents);
}

test "--create-file-mode gives a file it creates that mode and no other" {
    // A mode has no meaning on a platform with no file modes, and `stat`
    // has nothing to report there either.
    if (!@hasDecl(Io.File.Permissions, "fromMode")) return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "narrow.bin");
    defer testing.allocator.free(path);

    var body: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &body, .{ .mode = 0o600 }, null);

    var file = try tmp.dir.openFile(testing.io, "narrow.bin", .{});
    defer file.close(testing.io);
    const stat = try file.stat(testing.io);
    // The mode carries the file type in its high bits, so only the
    // permission bits are compared. The umask of the process can take a
    // bit away and never add one, so the check is that no bit outside the
    // mode survived. A default 0o022 umask leaves 0o600 whole.
    const permission_bits = @as(u32, @intCast(stat.permissions.toMode())) & 0o7777;
    try testing.expectEqual(@as(u32, 0), permission_bits & ~@as(u32, 0o600));
}

test "--create-file-mode reaches the file --no-clobber names, not only the one -o names" {
    // A mode has no meaning on a platform with no file modes, and `stat`
    // has nothing to report there either.
    if (!@hasDecl(Io.File.Permissions, "fromMode")) return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "nc.bin");
    defer testing.allocator.free(path);

    // The first name of the series is free, so `freeName` creates it.
    // Before the fix that create passed no mode and the file was born at
    // `0o666 & ~umask`, which the re-open in `toFile` could not narrow.
    var first: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &first, .{ .no_clobber = true, .mode = 0o600 }, null);

    // The second run finds that name taken and lands on `nc.bin.1`, which
    // is the shape the security review reproduced.
    var second: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &second, .{ .no_clobber = true, .mode = 0o600 }, null);

    for ([_][]const u8{ "nc.bin", "nc.bin.1" }) |name| {
        var file = try tmp.dir.openFile(testing.io, name, .{});
        defer file.close(testing.io);
        const stat = try file.stat(testing.io);
        // The same comparison the `-o` test above makes: the umask can
        // take a bit away and never add one, so no bit outside the asked
        // mode may survive.
        const permission_bits = @as(u32, @intCast(stat.permissions.toMode())) & 0o7777;
        testing.expectEqual(@as(u32, 0), permission_bits & ~@as(u32, 0o600)) catch |e| {
            std.debug.print("'{s}' got mode 0o{o}, wider than the 0o600 asked for\n", .{ name, permission_bits });
            return e;
        };
    }
}

test "refuse_symlink stops a url-chosen name from writing through a link, and -o still writes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const link_path = try tmpPath(&tmp, "tgt.bin");
    defer testing.allocator.free(link_path);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "victim.txt", .data = "VICTIM" });
    tmp.dir.symLink(testing.io, "victim.txt", "tgt.bin", .{}) catch |err| switch (err) {
        // A platform that needs a privilege to make a symbolic link, such
        // as Windows, has nothing this rule can be shown on.
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };

    // `-O` and `-J`: the name came from the url or from a header, so the
    // body must not land in a file no part of the command line named.
    var body: Io.Reader = .fixed("PWNED");
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.WriteError,
        toFile(testing.io, link_path, &body, .{ .refuse_symlink = true }, &d),
    );
    try testing.expectEqualStrings("DestinationIsSymbolicLink", d.message.?);
    try testing.expectEqual(@as(?u32, 23), d.curl_code);

    const kept = try tmp.dir.readFileAlloc(testing.io, "victim.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("VICTIM", kept);

    // `-o`: the user typed the path, so the link is followed, which is
    // what curl 8.21.0 does for both flags. `-o /dev/stdout` is a link on
    // Linux, and a script that names it must keep working.
    var typed: Io.Reader = .fixed("PWNED");
    try toFile(testing.io, link_path, &typed, .{}, null);
    const followed = try tmp.dir.readFileAlloc(testing.io, "victim.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(followed);
    try testing.expectEqualStrings("PWNED", followed);
}

test "refuse_symlink lets an ordinary name and a name that is not there through" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const fresh_path = try tmpPath(&tmp, "fresh.bin");
    defer testing.allocator.free(fresh_path);

    // Nothing is at the name, so the check finds no link and the create
    // makes the file.
    var body: Io.Reader = .fixed("payload");
    try toFile(testing.io, fresh_path, &body, .{ .refuse_symlink = true }, null);

    // A plain file that is already there is still overwritten, because
    // that is what `-O` does and what curl does.
    var again: Io.Reader = .fixed("second");
    try toFile(testing.io, fresh_path, &again, .{ .refuse_symlink = true }, null);

    const contents = try tmp.dir.readFileAlloc(testing.io, "fresh.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("second", contents);
}

test "--remote-time stamps the file with the time the caller read off the head" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "stamped.bin");
    defer testing.allocator.free(path);

    // `Wed, 21 Oct 2015 07:28:00 GMT`, which is what
    // `zurl_core.cookie.parseDate` reads a `Last-Modified` into.
    const seconds: i64 = 1445412480;
    var body: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &body, .{ .modified_at = seconds }, null);

    var file = try tmp.dir.openFile(testing.io, "stamped.bin", .{});
    defer file.close(testing.io);
    const stat = try file.stat(testing.io);
    const stamped = @divFloor(stat.mtime.nanoseconds, std.time.ns_per_s);
    try testing.expectEqual(@as(i96, seconds), stamped);
}

test "--remove-on-error deletes what a failed transfer wrote, and a resume keeps it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "partial.bin");
    defer testing.allocator.free(path);

    // A reader that hands back some bytes and then fails is what a peer
    // that stopped halfway looks like from here.
    var failing: Io.Reader = .failing;
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.ReadFailed,
        toFile(testing.io, path, &failing, .{ .remove_on_error = true }, &d),
    );
    try testing.expectError(
        error.FileNotFound,
        tmp.dir.readFileAlloc(testing.io, "partial.bin", testing.allocator, .limited(64)),
    );

    // Without the flag the bytes that did arrive stay, which is curl's
    // own default and what every zurl write did before the flag existed.
    var failing_again: Io.Reader = .failing;
    try testing.expectError(
        error.ReadFailed,
        toFile(testing.io, path, &failing_again, .{}, &d),
    );
    const kept = try tmp.dir.readFileAlloc(testing.io, "partial.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("", kept);
}

test "--remove-on-error never deletes a file a -C resume was adding to" {
    // The one place the flag and curl part company. Those bytes were in
    // the file before this transfer started, and a `-C` that failed and
    // then deleted the file it was adding to would destroy the very thing
    // the flag exists to build on.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "resumed.bin");
    defer testing.allocator.free(path);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "resumed.bin", .data = "XXXXX" });

    var failing: Io.Reader = .failing;
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.ReadFailed,
        toFile(testing.io, path, &failing, .{ .remove_on_error = true, .offset = 5 }, &d),
    );

    const kept = try tmp.dir.readFileAlloc(testing.io, "resumed.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("XXXXX", kept);
}

test "a transfer that finished is never deleted, whatever the flag says" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "whole.bin");
    defer testing.allocator.free(path);

    var body: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &body, .{ .remove_on_error = true }, null);

    const contents = try tmp.dir.readFileAlloc(testing.io, "whole.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

/// Returns the name `-J` would write for `header`, for a test that cares
/// about the name and not about the verdict shape.
fn expectHeaderName(header: []const u8, wanted: []const u8) !void {
    switch (try nameFromDisposition(header)) {
        .write => |name| try testing.expectEqualStrings(wanted, name),
        .none => {
            std.debug.print("'{s}' found no name, wanted '{s}'\n", .{ header, wanted });
            return error.TestUnexpectedResult;
        },
    }
}

/// Fails unless `-J` finds no usable name in `header`.
fn expectNoHeaderName(header: []const u8) !void {
    switch (try nameFromDisposition(header)) {
        .write => |name| {
            std.debug.print("'{s}' found the name '{s}', wanted none\n", .{ header, name });
            return error.TestUnexpectedResult;
        },
        .none => {},
    }
}

test "-J reads the filename parameter curl 8.21.0 reads" {
    // Every line was sent by a loopback server to the real curl, and curl
    // wrote the file named on the right.
    try expectHeaderName("attachment; filename=\"hello.txt\"", "hello.txt");
    try expectHeaderName("attachment; filename=plain.txt", "plain.txt");
    try expectHeaderName("inline; filename=\"inline.txt\"", "inline.txt");
    // The first `filename=` wins, and the second is never read.
    try expectHeaderName("attachment; filename=\"one.txt\"; filename=\"two.txt\"", "one.txt");
    // A single quote opens and closes a value too, which is what curl's
    // own scan does.
    try expectHeaderName("attachment; filename='quoted.txt'", "quoted.txt");
}

test "-J refuses a control byte in a header name, where curl writes it" {
    // **The one place zurl is stricter than curl on a `-J` name, and the
    // reason is the flag itself.** Measured against curl 8.21.0:
    // `filename="ta<tab>b.txt"` wrote a file whose name carries a raw
    // tab. zurl refuses it, because `checkName` refuses every C0 byte and
    // the DEL in a `-O` name and `-J` reads that one rule.
    //
    // The rule earns more here than it does for `-O`, not less. A `-O`
    // name comes from a url a person typed or a lockfile holds; a `-J`
    // name is whatever a server wrote. A name carrying a CR or an escape
    // byte lets that server write a line of its own into any terminal or
    // log that later lists the directory.
    try testing.expectError(
        error.UnsafeByte,
        nameFromDisposition("attachment; filename=\"ta\tb.txt\""),
    );
    try testing.expectError(
        error.UnsafeByte,
        nameFromDisposition("attachment; filename=\"a\x1b[2Kb.txt\""),
    );
    try testing.expectError(
        error.UnsafeByte,
        nameFromDisposition("attachment; filename=\"a\x00b.txt\""),
    );
    try testing.expectError(
        error.UnsafeByte,
        nameFromDisposition("attachment; filename=\"a\x7fb.txt\""),
    );
}

test "-J finds no name where curl 8.21.0 finds none" {
    // Each of these left curl writing the url's own last path segment, so
    // curl found no name in the header either.
    try expectNoHeaderName("attachment");
    try expectNoHeaderName("");
    // The match on `filename=` is case sensitive and takes no space
    // before the `=`. curl uses a plain `memcmp` for it.
    try expectNoHeaderName("attachment; FILENAME=\"upper.txt\"");
    try expectNoHeaderName("attachment; filename = \"spaced.txt\"");
    // curl reads no RFC 5987 encoded parameter, so this names nothing.
    try expectNoHeaderName("attachment; filename*=UTF-8''star.txt");
    // A value that is a path with an empty last segment. curl returns no
    // name here as well, measured, and writes the url's own.
    try expectNoHeaderName("attachment; filename=\"dir/\"");
    // Past the bound this file keeps. The header is the server's, so its
    // length is the server's choice.
    const long = "attachment; filename=\"" ++ "x" ** max_disposition_len ++ "\"";
    try expectNoHeaderName(long);
}

test "-J cuts the path off a header name, exactly as curl does" {
    // **The security measurement.** Each header below was sent to the real
    // curl 8.21.0 from a loopback server, with the process in a scratch
    // directory. curl wrote the name on the right into that directory and
    // nothing outside it. zurl writes the same name, because it cuts on
    // the same two separators before the one name rule reads the result.
    try expectHeaderName("attachment; filename=\"../../evil.txt\"", "evil.txt");
    try expectHeaderName("attachment; filename=\"/tmp/evil-abs.txt\"", "evil-abs.txt");
    try expectHeaderName("attachment; filename=\"..\\..\\evil2.txt\"", "evil2.txt");
    try expectHeaderName("attachment; filename=\"a/b/c/deep.txt\"", "deep.txt");
    // A separator of each kind, mixed. The last one of either kind wins,
    // which is what two `lastIndexOf` calls give and what curl's two
    // `strrchr` calls give.
    try expectHeaderName("attachment; filename=\"a\\b/c.txt\"", "c.txt");
    try expectHeaderName("attachment; filename=\"a/b\\c.txt\"", "c.txt");
}

test "-J never hands checkName a name that is still a path" {
    // **The property, stated as a property and not as a list.** Whatever a
    // header holds, the bytes `nameFromDisposition` returns carry no path
    // separator and no byte a file name may not hold. That is what keeps
    // the file inside the working directory, and it holds because the one
    // rule `checkName` reads every result.
    const headers = [_][]const u8{
        "attachment; filename=\"../../evil.txt\"",
        "attachment; filename=\"/etc/passwd\"",
        "attachment; filename=\"..\\..\\evil.txt\"",
        "attachment; filename=\"C:\\Windows\\System32\\evil.dll\"",
        "attachment; filename=\"/\"",
        "attachment; filename=\"\\\"",
        "attachment; filename=\"...\"",
        "attachment; filename=\".config\"",
        "attachment; filename=\"-rf\"",
        "attachment; filename=\"%2e%2e%2fpwned\"",
        "attachment; filename=\"a%00b\"",
        "attachment; filename=\"100%\"",
        "attachment; filename=.",
        "attachment; filename=..",
        "attachment; filename=\"\"",
        "attachment; filename=",
    };
    for (headers) |header| {
        const found = nameFromDisposition(header) catch continue;
        const name = switch (found) {
            .write => |bytes| bytes,
            .none => continue,
        };
        if (name.len == 0) {
            std.debug.print("'{s}' gave an empty name\n", .{header});
            return error.TestUnexpectedResult;
        }
        for (name) |byte| switch (byte) {
            '/', '\\', 0x00...0x1f, 0x7f => {
                std.debug.print("'{s}' gave the name '{s}', which is a path\n", .{ header, name });
                return error.TestUnexpectedResult;
            },
            else => {},
        };
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) {
            std.debug.print("'{s}' gave the name '{s}'\n", .{ header, name });
            return error.TestUnexpectedResult;
        }
        if (name.len > max_name_len) {
            std.debug.print("'{s}' gave a name past the bound\n", .{header});
            return error.TestUnexpectedResult;
        }
    }
}

test "-J refuses a header name past the length bound" {
    // A name that survived the path cut is still judged by `checkName`,
    // and that is where the length bound lives. One rule, both flags.
    const long = "attachment; filename=\"" ++ "x" ** (max_name_len + 1) ++ "\"";
    try testing.expectError(error.NameTooLong, nameFromDisposition(long));

    // And exactly at the bound it writes.
    const edge = "attachment; filename=\"" ++ "x" ** max_name_len ++ "\"";
    try expectHeaderName(edge, "x" ** max_name_len);
}

test "every -J name fault has a fault code and a sentence" {
    // The mirror of the `-O` guard above. A new `NameError` member with
    // no `-J` sentence would reach the user as a bare error name.
    inline for (@typeInfo(NameError).error_set.?) |field| {
        const err = @field(NameError, field.name);
        try testing.expect(explainHeaderName(err).len > 0);
        try testing.expect(std.mem.startsWith(u8, explainHeaderName(err), "-J "));
    }
}

test "--refuse-existing writes a new file and stops on one that is there" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "j.bin");
    defer testing.allocator.free(path);

    // Nothing there yet, so the write goes through.
    var first: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &first, .{ .refuse_existing = true }, null);

    const written = try tmp.dir.readFileAlloc(testing.io, "j.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(written);
    try testing.expectEqualStrings("payload", written);

    // **The second write must not land.** Measured against curl 8.21.0:
    // `-OJ` onto a directory already holding the header's name exits 23
    // and leaves the old bytes alone.
    var d: zurl_core.Diagnostics = .{};
    var second: Io.Reader = .fixed("replaced");
    try testing.expectError(
        error.WriteError,
        toFile(testing.io, path, &second, .{ .refuse_existing = true }, &d),
    );

    const kept = try tmp.dir.readFileAlloc(testing.io, "j.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("payload", kept);
}

test "--no-clobber outranks --refuse-existing, which is what curl does for the pair" {
    // Measured against curl 8.21.0: `-OJ --no-clobber` onto an existing
    // `cd.txt` wrote `cd.txt.1` and exited 0, rather than fail the url.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "j.bin");
    defer testing.allocator.free(path);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "j.bin", .data = "old" });

    var body: Io.Reader = .fixed("payload");
    try toFile(testing.io, path, &body, .{ .refuse_existing = true, .no_clobber = true }, null);

    const kept = try tmp.dir.readFileAlloc(testing.io, "j.bin", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("old", kept);

    const suffixed = try tmp.dir.readFileAlloc(testing.io, "j.bin.1", testing.allocator, .limited(64));
    defer testing.allocator.free(suffixed);
    try testing.expectEqualStrings("payload", suffixed);
}

test "--etag-save writes the header value and one newline" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(&tmp, "etag.txt");
    defer testing.allocator.free(path);

    // Measured against curl 8.21.0: the file held these exact bytes.
    try etagToFile(testing.io, path, "\"abc123\"", null);
    const strong = try tmp.dir.readFileAlloc(testing.io, "etag.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(strong);
    try testing.expectEqualStrings("\"abc123\"\n", strong);

    // A weak tag keeps its `W/` mark. curl writes it too.
    try etagToFile(testing.io, path, "W/\"weak1\"", null);
    const weak = try tmp.dir.readFileAlloc(testing.io, "etag.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(weak);
    try testing.expectEqualStrings("W/\"weak1\"\n", weak);

    // **A response with no tag leaves the file empty and never leaves the
    // last run's tag in place.** curl creates the empty file too,
    // measured, and a stale tag would claim a version the server never
    // sent.
    try etagToFile(testing.io, path, "", null);
    const none = try tmp.dir.readFileAlloc(testing.io, "etag.txt", testing.allocator, .limited(64));
    defer testing.allocator.free(none);
    try testing.expectEqualStrings("", none);
}

test "--etag-save reports a path it cannot write" {
    var d: zurl_core.Diagnostics = .{};
    try testing.expectError(
        error.WriteError,
        etagToFile(testing.io, "/nope/zurl-etag-test/tag.txt", "\"x\"", &d),
    );
    try testing.expect(d.message != null);
}
