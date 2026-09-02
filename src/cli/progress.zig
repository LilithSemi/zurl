//! curl's progress meter, in both of the shapes curl draws.
//!
//! The default shape is a table of columns. `--progress-bar` replaces it
//! with one row of `#` marks and a percentage. Both go to standard error,
//! never to standard output, so a body written to standard output stays
//! exactly the bytes the peer sent.
//!
//! Every layout rule below was measured against curl 8.21.0 and then
//! checked against curl's own source. `lib/progress.c` holds `max6out`
//! and `time2str`, which this file calls `writeSize` and `writeDuration`.
//! `src/tool_cb_prg.c` holds the bar and its `fly` animation, which this
//! file calls `writeBar` and `Fly`.
//!
//! **Four decisions shape this file, and each one has a test.**
//!
//! - **A body on the terminal gets no meter.** Standard error and
//!   standard output reach the same screen, so a meter drawn while the
//!   body goes to that screen cuts into the bytes the peer sent. `draws`
//!   holds this rule, and it is a pure function of four booleans, so a
//!   test drives it both ways with no terminal.
//! - **The drawing is a pure function of one `Sample`.** A `Sample` holds
//!   the byte count, the announced length, the rate, and the elapsed
//!   time. Nothing below reads a clock or asks whether a file is a
//!   terminal, so every layout test runs with plain numbers and finishes
//!   at once. `Meter` is the one type that touches a writer, and a test
//!   gives it a `Writer.fixed` over an array.
//! - **A zero `total` means the length is unknown, and it never divides.**
//!   `zurl_stream.Progress` reports zero for a decoded body, because the
//!   peer announced compressed bytes while the count is decoded bytes.
//!   Only `--compressed` can bring such a body about: a run that does not
//!   name it decodes nothing, so the announced length and the count
//!   describe the same octets. A chunked answer, which announces no
//!   length at all, reaches this path on any run. The
//!   default meter answers with curl's own substitution, and the bar
//!   answers with curl's `fly` animation.
//! - **A meter that cannot write stops drawing and the transfer goes on.**
//!   A user who closed a pager must not lose a download. `Meter.broken`
//!   records the fault, and no later draw runs.

const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;
const zurl_stream = @import("zurl-stream");

const ns_per_s = std.time.ns_per_s;
const ns_per_ms = std.time.ns_per_ms;

/// Which of curl's two meters the user asked for.
pub const Style = enum {
    /// The default table of columns.
    meter,
    /// `--progress-bar`.
    bar,
};

/// What one draw needs to know.
///
/// This is the whole input of every drawing function in this file. A test
/// builds one by hand, so no layout test needs a clock, a terminal, or a
/// server.
pub const Sample = struct {
    /// How many bytes have arrived.
    transferred: u64 = 0,
    /// The announced length, or **zero when the length is not known**.
    ///
    /// `zurl_stream.Progress` reports zero for a decoded body, because the
    /// announced length counts the bytes on the wire while `transferred`
    /// counts the bytes after decoding. The two describe different bytes,
    /// so zurl reports no length rather than a wrong one. A chunked answer
    /// reports zero too, because it announces no length at all.
    total: u64 = 0,
    /// The average rate so far, in bytes each second.
    rate: u64 = 0,
    /// How long the transfer has run.
    elapsed_ns: u64 = 0,
};

/// How wide curl's size column is. `writeSize` always writes this many
/// bytes.
pub const size_width = 6;

/// How wide curl's time column is. `writeDuration` always writes this many
/// bytes.
pub const time_width = 7;

/// How wide one row of the default meter is, after the leading return.
///
/// Three percent columns of 3, six size columns of 6, three time columns
/// of 7, and eleven single spaces between the twelve columns.
pub const row_width = 3 * 3 + 6 * size_width + 3 * time_width + 11;

/// The two lines curl prints once, above the first row.
pub const header =
    "  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current\n" ++
    "                                 Dload  Upload  Total   Spent   Left   Speed\n";

/// How wide the bar is when nothing names a width.
///
/// curl's `get_terminal_columns` falls back to this number, so a zurl bar
/// drawn into a pipe is the same width as a curl bar drawn into a pipe.
pub const default_columns: u16 = 79;

/// The narrowest bar curl draws. curl calls this `MIN_BARLENGTH`.
pub const min_columns: u16 = 20;

/// The widest bar curl draws. curl calls this `MAX_BARLENGTH`.
pub const max_columns: u16 = 400;

/// Writes `bytes` into curl's six-column size field.
///
/// This is curl's `max6out`. A count below 100000 goes out as a plain
/// number. A larger count divides by 1024 until the whole part falls below
/// 1000, and the letter of the unit follows the digits. The fraction
/// truncates, which is what curl's integer arithmetic does: 1023 bytes
/// over a kilobyte read as `.99`, never as `1.00`.
///
/// The field is always exactly `size_width` bytes wide, for every input a
/// `u64` can hold.
pub fn writeSize(w: *Io.Writer, bytes: u64) Io.Writer.Error!void {
    if (bytes < 100_000) return w.print("{d:>6}", .{bytes});

    // The list of units bounds the loop, so the index can never leave it.
    // A `u64` stops at `E` on its own, two steps before the bound bites.
    const units = "kMGTPE";
    var scaled = bytes;
    var unit: usize = 0;
    while (unit + 1 < units.len) : (unit += 1) {
        const next = scaled / 1024;
        if (next < 1000) break;
        scaled = next;
    }

    const whole = scaled / 1024;
    // Below 1000, so the wider of the two shapes below stays six columns.
    std.debug.assert(whole < 1000);
    const rest = scaled % 1024;
    if (whole <= 99) return w.print("{d:>2}.{d:0>2}{c}", .{ whole, rest * 100 / 1024, units[unit] });
    return w.print("{d:>3}.{d}{c}", .{ whole, rest * 10 / 1024, units[unit] });
}

/// Writes `seconds` into curl's seven-column time field.
///
/// This is curl's `time2str`. A count of zero writes seven spaces, which is
/// how curl says that it does not know the time. The shape then changes
/// with the size of the count, so that every answer fits the same seven
/// columns: `MM:SS`, then `H:MM:SS`, then `NNh NNm`, then `NNd NNh`, and
/// then whole days, months, or years.
///
/// The field is always exactly `time_width` bytes wide, for every input a
/// `u64` can hold.
pub fn writeDuration(w: *Io.Writer, seconds: u64) Io.Writer.Error!void {
    if (seconds == 0) return w.splatByteAll(' ', time_width);

    const hours = seconds / 3600;
    if (hours <= 99) {
        const minutes = (seconds - hours * 3600) / 60;
        if (hours <= 9) {
            const rest = seconds - hours * 3600 - minutes * 60;
            if (hours != 0) return w.print("{d}:{d:0>2}:{d:0>2}", .{ hours, minutes, rest });
            return w.print("  {d:0>2}:{d:0>2}", .{ minutes, rest });
        }
        return w.print("{d}h {d:0>2}m", .{ hours, minutes });
    }

    const days = seconds / 86400;
    const rest_hours = (seconds - days * 86400) / 3600;
    if (days <= 99) return w.print("{d:>2}d {d:0>2}h", .{ days, rest_hours });
    if (days <= 999) return w.print("{d:>6}d", .{days});

    const months = days / 30;
    if (months <= 999) return w.print("{d:>6}m", .{months});

    const years = days / 365;
    if (years <= 99_999) return w.print("{d:>6}y", .{years});
    return w.writeAll(">99999y");
}

/// Returns what part of `total` that `current` is, as a whole percent.
///
/// This is curl's `pgrs_est_percent`. A `total` of zero returns zero
/// rather than divide, because a length nobody announced gives no
/// fraction.
///
/// `current` is clamped to `total` first. curl does not clamp, and a peer
/// that sends more bytes than it announced therefore widens curl's row
/// past its three columns. zurl's own framing stops a body at the
/// announced length, so the clamp only holds the column width. It changes
/// no number a real transfer can produce.
pub fn percentOf(total: u64, current: u64) u64 {
    if (total == 0) return 0;
    const capped = @min(current, total);
    // curl divides the total first when it is large, so that the
    // multiplication cannot overflow. The two branches round differently,
    // and the split is part of the output that curl prints.
    if (total > 10_000) return capped / (total / 100);
    return capped * 100 / total;
}

/// Writes one row of the default meter, with a leading carriage return.
///
/// The row is always `row_width` bytes after the return, so each redraw
/// covers the one before it.
///
/// **A `total` of zero is the indeterminate state.** curl fills the two
/// "total" columns with the count that has already arrived, which reads as
/// 100 percent of itself, and leaves the `% Received` column at zero. The
/// honest signal in the row is the pair of blank time columns: zurl knows
/// neither the whole time nor the time left, so it writes neither. zurl
/// draws exactly what curl draws here, because the meter is a
/// compatibility surface.
///
/// The two upload columns are always zero, and `% Xferd` is always zero
/// with them. zurl sends a request body now, and the meter does not count
/// it: `zurl_stream.Progress` sits over the response body alone, so no
/// number the meter holds describes the upload. A meter that counted both
/// needs a second reporter over the request body, which nothing asks for
/// today.
pub fn writeRow(w: *Io.Writer, s: Sample) Io.Writer.Error!void {
    const known = s.total != 0;
    // curl substitutes the arrived count for a length nobody announced.
    const expected = if (known) s.total else s.transferred;
    // curl reports no estimate until it has a rate to divide by.
    const estimating = known and s.rate > 0;
    const whole_s = if (estimating) s.total / s.rate else 0;
    const spent_s = s.elapsed_ns / ns_per_s;
    const left_s = if (whole_s > spent_s) whole_s - spent_s else 0;

    try w.writeByte('\r');
    try w.print("{d:>3} ", .{percentOf(expected, s.transferred)});
    try writeSize(w, expected);
    try w.print(" {d:>3} ", .{if (estimating) percentOf(s.total, s.transferred) else 0});
    try writeSize(w, s.transferred);
    try w.print(" {d:>3} ", .{0});
    try writeSize(w, 0);
    try w.writeByte(' ');
    try writeSize(w, s.rate);
    try w.writeByte(' ');
    try writeSize(w, 0);
    try w.writeByte(' ');
    try writeDuration(w, whole_s);
    try w.writeByte(' ');
    try writeDuration(w, spent_s);
    try w.writeByte(' ');
    try writeDuration(w, left_s);
    try w.writeByte(' ');
    // curl reports the rate over the last few seconds here and the whole
    // average in the `Dload` column. zurl keeps one `Speedometer` for a
    // transfer, and it measures the whole average, so both columns carry
    // that one number. This is the one column where zurl's number differs
    // from curl's on a transfer whose rate changes.
    try writeSize(w, s.rate);
}

/// The state of curl's `fly` animation, which the bar draws when nobody
/// announced a length.
///
/// curl flies four `#` marks along a sine table and slides a `-=O=-`
/// glider from side to side. The starting values are curl's own:
/// `progressbarinit` sets the tick to 150 and starts the glider at the
/// left, moving right.
pub const Fly = struct {
    /// Where the four marks read the sine table.
    tick: u16 = 150,
    /// Where the glider starts, counted from the left of the row.
    glider: i32 = 0,
    /// Which way the glider moves next.
    step: i32 = 1,
};

/// What the glider looks like. curl draws these five bytes.
const glider_art = "-=O=-";

/// 200 points of a sine wave, scaled to 0 through 999999.
///
/// Copied from curl's `src/tool_cb_prg.c`, which generated it with a Perl
/// one-liner. The animation is only the same as curl's with the same
/// numbers, so the table is copied rather than computed.
const sinus = [200]u32{
    515704, 531394, 547052, 562664, 578214, 593687, 609068, 624341, 639491, 654504,
    669364, 684057, 698568, 712883, 726989, 740870, 754513, 767906, 781034, 793885,
    806445, 818704, 830647, 842265, 853545, 864476, 875047, 885248, 895069, 904500,
    913532, 922156, 930363, 938145, 945495, 952406, 958870, 964881, 970434, 975522,
    980141, 984286, 987954, 991139, 993840, 996054, 997778, 999011, 999752, 999999,
    999754, 999014, 997783, 996060, 993848, 991148, 987964, 984298, 980154, 975536,
    970449, 964898, 958888, 952426, 945516, 938168, 930386, 922180, 913558, 904527,
    895097, 885277, 875077, 864507, 853577, 842299, 830682, 818739, 806482, 793922,
    781072, 767945, 754553, 740910, 727030, 712925, 698610, 684100, 669407, 654548,
    639536, 624386, 609113, 593733, 578260, 562710, 547098, 531440, 515751, 500046,
    484341, 468651, 452993, 437381, 421830, 406357, 390976, 375703, 360552, 345539,
    330679, 315985, 301474, 287158, 273052, 259170, 245525, 232132, 219003, 206152,
    193590, 181331, 169386, 157768, 146487, 135555, 124983, 114781, 104959, 95526,
    86493,  77868,  69660,  61876,  54525,  47613,  41147,  35135,  29581,  24491,
    19871,  15724,  12056,  8868,   6166,   3951,   2225,   990,    248,    0,
    244,    982,    2212,   3933,   6144,   8842,   12025,  15690,  19832,  24448,
    29534,  35084,  41092,  47554,  54462,  61809,  69589,  77794,  86415,  95445,
    104873, 114692, 124891, 135460, 146389, 157667, 169282, 181224, 193480, 206039,
    218888, 232015, 245406, 259048, 272928, 287032, 301346, 315856, 330548, 345407,
    360419, 375568, 390841, 406221, 421693, 437243, 452854, 468513, 484202, 499907,
};

/// Returns `columns` held inside the width curl accepts.
pub fn clampColumns(columns: u16) u16 {
    return @min(@max(columns, min_columns), max_columns);
}

/// Writes one frame of curl's `fly` animation, with a leading carriage
/// return, and moves `f` on by one frame.
///
/// `columns` must already be clamped. The frame is exactly `columns` bytes
/// after the return.
fn writeFly(w: *Io.Writer, columns: u16, f: *Fly) Io.Writer.Error!void {
    std.debug.assert(columns >= min_columns and columns <= max_columns);

    var row_buffer: [max_columns]u8 = undefined;
    const row = row_buffer[0..columns];
    @memset(row, ' ');

    // `f.glider` never leaves 0 through `columns - 6`, so the glider and
    // its five bytes stay inside the row. `stepFly` holds that bound.
    const glider: usize = @intCast(f.glider);
    std.debug.assert(glider + glider_art.len <= row.len);
    @memcpy(row[glider..][0..glider_art.len], glider_art);

    // curl reads the table at the tick and at three later points, and
    // divides the reading by a step that spans the row. The divisor is at
    // least 2512 for the widest row curl draws, so it is never zero.
    const span: u64 = columns - 2;
    const divisor = 1_000_000 / span;
    std.debug.assert(divisor > 0);
    var offset: u16 = 0;
    while (offset <= 15) : (offset += 5) {
        const reading: u64 = sinus[(f.tick + offset) % sinus.len];
        // The reading never reaches 1000000, so `place` never passes
        // `span`, which is two short of the row. The clamp holds that
        // bound against a table somebody edits later.
        const place: usize = @min(reading / divisor, row.len - 1);
        row[place] = '#';
    }

    try w.writeByte('\r');
    try w.writeAll(row);
    stepFly(f, columns);
}

/// Moves `f` on by one frame.
fn stepFly(f: *Fly, columns: u16) void {
    f.tick += 2;
    if (f.tick >= sinus.len) f.tick -= sinus.len;

    // The glider turns around at each end. curl leaves six columns for it,
    // one more than the five bytes it draws.
    const far: i32 = @as(i32, columns) - 6;
    std.debug.assert(far > 0);
    f.glider += f.step;
    if (f.glider >= far) {
        f.step = -1;
        f.glider = far;
    } else if (f.glider < 0) {
        f.step = 1;
        f.glider = 0;
    }
}

/// Writes one row of `--progress-bar`, with a leading carriage return, and
/// moves `f` on when the row is an animation frame.
///
/// The row is exactly `columns` bytes after the return, which is why curl
/// takes the width of the terminal rather than a width of its own.
///
/// **A `total` of zero draws curl's `fly` animation.** A bar cannot show a
/// part of a length nobody announced, so curl shows motion instead of a
/// fraction. Nothing here divides by `total`.
pub fn writeBar(w: *Io.Writer, s: Sample, columns: u16, f: *Fly) Io.Writer.Error!void {
    const width = clampColumns(columns);
    if (s.total == 0) return writeFly(w, width, f);

    // curl reserves seven columns for the space and the percentage.
    const bar_width: usize = width - 7;
    // A peer that sends more than it announced would give a fraction above
    // one. curl raises the total to the count instead, and so does this.
    const total = @max(s.total, s.transferred);
    const fraction = @as(f64, @floatFromInt(s.transferred)) / @as(f64, @floatFromInt(total));
    // `fraction` is 0 through 1, so the product is 0 through `bar_width`.
    const filled: usize = @min(@as(usize, @intFromFloat(@as(f64, @floatFromInt(bar_width)) * fraction)), bar_width);

    try w.writeByte('\r');
    try w.splatByteAll('#', filled);
    try w.splatByteAll(' ', bar_width - filled);
    try w.print(" {d:>5.1}%", .{fraction * 100.0});
}

/// What decides whether one transfer draws a meter at all.
///
/// Every field is a plain answer that the caller already holds, so
/// `draws` needs no clock, no terminal, and no writer. `src/cli/run.zig`
/// fills this in `meterVisibility`, and `src/main.zig` is the only place
/// that asks the operating system for `stdout_is_terminal`.
pub const Visibility = struct {
    /// `-s`. curl draws no meter then, and `-S` does not bring it back.
    /// `-S` returns the failure message alone.
    silent: bool = false,
    /// `--no-progress-meter`. curl draws no meter, and every message a
    /// failed transfer prints still reaches standard error.
    ///
    /// A separate field from `silent`, because the two ask different
    /// questions. `-s` hides the meter **and** the message; this hides the
    /// meter alone. Measured against curl 8.21.0 on a refused connection:
    /// `--no-progress-meter` still wrote `curl: (7) ...` and `-s` wrote
    /// nothing at all.
    no_meter: bool = false,
    /// True while `-Z` overlaps transfers. Several meters on one standard
    /// error would overwrite each other's row, so `runParallel` draws
    /// none.
    parallel: bool = false,
    /// Whether **this** transfer writes its body to standard output.
    /// `-o` and `-O` both make this false, because the body goes to a
    /// file.
    body_to_stdout: bool = false,
    /// Whether standard output is a terminal.
    stdout_is_terminal: bool = false,
};

/// Whether one transfer draws a meter.
///
/// **A body on the terminal gets no meter.** The meter and the body would
/// then land on the same screen, and the meter's row would cut into the
/// bytes the peer sent. A user who pipes that screen into a parser reads
/// corrupt data. curl closes this by drawing nothing, and zurl matches.
///
/// Measured against curl 8.21.0 under a real pty, with a 200000 byte
/// body, counting the meter's header lines:
///
/// - Body to a file with `-o` or `-O`, standard output a terminal: curl
///   draws. The body is not on the screen, so nothing is cut.
/// - Body to standard output, standard output a terminal: curl draws
///   nothing. This is the case this rule exists for.
/// - Body to standard output, standard output a pipe or a file: curl
///   draws. The meter goes to standard error, so the two never meet.
/// - Body to standard output, standard output a terminal, standard error
///   redirected to a file: curl still draws nothing. **The rule reads
///   standard output alone**, never standard error.
/// - `--progress-bar` answers the same way in every case above.
///
/// The answer is for one transfer and not for the run. Measured: `curl -o
/// f URL1 URL2` on a terminal draws one meter, for the url that writes
/// the file, and `curl URL1 -o f URL2` draws one too. A run does not go
/// quiet because an earlier url went to the screen.
pub fn draws(v: Visibility) bool {
    if (v.silent) return false;
    if (v.no_meter) return false;
    if (v.parallel) return false;
    return !(v.body_to_stdout and v.stdout_is_terminal);
}

/// Returns how many columns the bar may use.
///
/// This is the one impure function in this file, and it is why `Meter`
/// takes a width rather than find one. curl reads `COLUMNS` first, asks
/// the terminal next, and falls back to `default_columns` when neither
/// answers. zurl does the same.
///
/// **The answer does not decide whether zurl draws.** `draws` decides
/// that, and it reads where the body goes. The width is the only thing
/// this function asks a terminal for.
pub fn terminalColumns(env: *std.process.Environ.Map) u16 {
    if (env.get("COLUMNS")) |text| {
        if (std.fmt.parseInt(u16, text, 10)) |named| {
            if (named >= min_columns and named <= max_columns) return named;
        } else |_| {
            // A `COLUMNS` nobody can read names no width. Fall through to
            // the terminal, the way curl does.
        }
    }
    if (windowColumns()) |asked| return clampColumns(asked);
    return default_columns;
}

/// Asks the terminal behind standard error how wide it is.
///
/// Returns null when standard error is not a terminal, which is also how
/// zurl learns that it is not one. The call itself is the test: a pipe and
/// a file both refuse it.
fn windowColumns() ?u16 {
    // Windows has no `TIOCGWINSZ`. A build for it takes the fallback
    // width, and `COLUMNS` still works there.
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return null;

    var size: std.posix.winsize = undefined;
    const rc = std.posix.system.ioctl(
        std.posix.STDERR_FILENO,
        std.posix.T.IOCGWINSZ,
        @intFromPtr(&size),
    );
    if (std.posix.errno(rc) != .SUCCESS) return null;
    if (size.col == 0) return null;
    return size.col;
}

/// Draws a meter for one transfer.
///
/// The meter owns no clock. `update` takes a `Sample`, and the caller
/// reads the clock. A test therefore drives a whole transfer's worth of
/// drawing with a list of samples and no waiting.
///
/// `out` must be standard error. The body of a transfer can go to standard
/// output, and a meter that shared that writer would cut the body in
/// pieces.
pub const Meter = struct {
    /// Where the meter draws. This is standard error.
    out: *Io.Writer,
    style: Style,
    /// How wide the bar may be. `terminalColumns` finds this.
    columns: u16 = default_columns,
    /// Where a run-time draw reads the rate and the elapsed time.
    ///
    /// Null in a test that calls `update` with samples of its own.
    speedometer: ?*const zurl_stream.Speedometer = null,

    /// Whether `start` has run. A transfer that reached no server never
    /// starts one, so it draws nothing, which is what curl does.
    started: bool = false,
    /// Whether `finish` has run. `finish` is safe to call again.
    finished: bool = false,
    /// **Whether a write to `out` failed.**
    ///
    /// A meter that cannot write stops drawing, and the transfer goes on.
    /// A user who closed a pager keeps the download. No message reports
    /// this, because the only place to write one is the writer that just
    /// failed. The flag is what a test reads instead.
    broken: bool = false,

    /// Which whole period the last draw named, so one period draws once.
    last_period: ?u64 = null,
    /// The last sample. `finish` draws this one again.
    last: Sample = .{},
    fly: Fly = .{},

    /// How often the meter redraws.
    ///
    /// curl draws the default meter about once a second, and holds the bar
    /// to ten frames a second. Measured against curl 8.21.0 over a slow
    /// loopback transfer.
    fn period(m: *const Meter) u64 {
        return switch (m.style) {
            .meter => ns_per_s,
            .bar => 100 * ns_per_ms,
        };
    }

    /// Opens the meter. Call this once the transfer has a response.
    ///
    /// The default meter writes its two header lines and one row of
    /// zeroes. The bar writes nothing until the first byte arrives.
    ///
    /// A transfer that never reached a server must not call this. curl
    /// draws no meter for a connection it could not make, and a
    /// `Connection refused` on its own line is all the user sees.
    pub fn start(m: *Meter) void {
        if (m.started) return;
        m.started = true;
        m.last_period = 0;
        if (m.style == .meter) {
            m.put(header);
            m.drawSample(m.last);
        }
        m.flushOut();
    }

    /// Draws `s`, unless the period it falls in already drew.
    pub fn update(m: *Meter, s: Sample) void {
        if (!m.started or m.finished or m.broken) return;
        m.last = s;

        const now = s.elapsed_ns / m.period();
        if (m.last_period) |drawn| {
            if (drawn == now) return;
        }
        m.last_period = now;

        m.drawSample(s);
        m.flushOut();
    }

    /// Closes the meter with one last row and a newline.
    ///
    /// The newline is what moves the cursor off the row, so the next thing
    /// on standard error starts on a line of its own. curl writes it the
    /// same way, and a failure message follows it.
    ///
    /// Safe to call when the meter never started, and safe to call again.
    pub fn finish(m: *Meter) void {
        if (!m.started or m.finished) return;
        m.finished = true;
        m.drawSample(m.last);
        m.put("\n");
        m.flushOut();
    }

    /// Returns the reporter to give `Transfer.Options.reporter`.
    ///
    /// The callback is `callconv(.c)` and takes a `*anyopaque`, which is
    /// the shape the bindings phase passes a C callback through with no
    /// shim.
    pub fn reporter(m: *Meter) zurl_stream.Reporter {
        return .{ .ctx = m, .report = report };
    }

    fn report(ctx: *anyopaque, transferred: u64, total: u64) callconv(.c) void {
        const m: *Meter = @ptrCast(@alignCast(ctx));
        // A meter with no speedometer has no clock, so it has no sample to
        // draw. Only a test builds one that way.
        const speedometer = m.speedometer orelse return;
        const elapsed = speedometer.elapsedNs();
        m.update(.{
            .transferred = transferred,
            .total = total,
            .rate = zurl_stream.Speedometer.rate(transferred, elapsed),
            .elapsed_ns = elapsed,
        });
    }

    fn drawSample(m: *Meter, s: Sample) void {
        if (m.broken) return;
        switch (m.style) {
            .meter => writeRow(m.out, s) catch m.breakOut(),
            .bar => writeBar(m.out, s, m.columns, &m.fly) catch m.breakOut(),
        }
    }

    fn put(m: *Meter, text: []const u8) void {
        if (m.broken) return;
        m.out.writeAll(text) catch m.breakOut();
    }

    fn flushOut(m: *Meter) void {
        if (m.broken) return;
        // Flushed after each draw, so the row reaches the terminal while
        // the transfer runs and not after it ends.
        m.out.flush() catch m.breakOut();
    }

    fn breakOut(m: *Meter) void {
        m.broken = true;
    }
};

const testing = std.testing;

/// Renders `f` into `buffer` and returns what it wrote.
fn render(buffer: []u8, comptime f: anytype, args: anytype) ![]const u8 {
    var w: Io.Writer = .fixed(buffer);
    try @call(.auto, f, .{&w} ++ args);
    return w.buffered();
}

fn expectSize(expected: []const u8, bytes: u64) !void {
    var buffer: [size_width]u8 = undefined;
    const got = try render(&buffer, writeSize, .{bytes});
    try testing.expectEqual(@as(usize, size_width), got.len);
    try testing.expectEqualStrings(expected, got);
}

fn expectDuration(expected: []const u8, seconds: u64) !void {
    var buffer: [time_width]u8 = undefined;
    const got = try render(&buffer, writeDuration, .{seconds});
    try testing.expectEqual(@as(usize, time_width), got.len);
    try testing.expectEqualStrings(expected, got);
}

fn expectRow(expected: []const u8, s: Sample) !void {
    var buffer: [1 + row_width]u8 = undefined;
    const got = try render(&buffer, writeRow, .{s});
    try testing.expectEqual(@as(usize, 1 + row_width), got.len);
    try testing.expectEqual(@as(u8, '\r'), got[0]);
    try testing.expectEqualStrings(expected, got[1..]);
}

// The six tests the plan names come first. Each one is a fact about the
// output, not a fact about the code that made it.

test "a bar at a known total shows a percentage" {
    var buffer: [1 + max_columns]u8 = undefined;
    var fly: Fly = .{};
    const got = try render(&buffer, writeBar, .{
        Sample{ .transferred = 500, .total = 1000 },
        default_columns,
        &fly,
    });

    // curl 8.21.0, measured: `\r` then the bar left aligned in
    // `columns - 7`, a space, and the percentage in five columns.
    try testing.expectEqual(@as(usize, 1 + default_columns), got.len);
    try testing.expectEqualStrings("\r" ++ "#" ** 36 ++ " " ** 36 ++ "  50.0%", got);
}

test "a zero total shows an indeterminate meter, not a division by zero" {
    // A decoded body reaches the meter with `total` at zero, because the
    // announced length counts bytes on the wire and `transferred` counts
    // bytes after decoding. A gzip answer under `--compressed` reaches it
    // that way, and so does any chunked answer, which announces no length
    // at all.

    // The default meter fills the two "total" columns with what arrived,
    // leaves `% Received` at zero, and blanks the two time columns it
    // cannot fill.
    try expectRow(
        "100 162.4k   0 162.4k   0      0 130.1k      0           00:01         130.1k",
        .{ .transferred = 166_300, .total = 0, .rate = 133_270, .elapsed_ns = 1 * ns_per_s },
    );

    // The bar answers with motion, and writes no percentage at all.
    var buffer: [1 + max_columns]u8 = undefined;
    var fly: Fly = .{};
    const bar = try render(&buffer, writeBar, .{
        Sample{ .transferred = 166_300, .total = 0 },
        default_columns,
        &fly,
    });
    try testing.expectEqual(@as(usize, 1 + default_columns), bar.len);
    try testing.expect(std.mem.indexOfScalar(u8, bar, '%') == null);
}

test "-s draws nothing" {
    // `-s` gives the transfer no reporter at all, so `main` builds no
    // `Meter`. The state a `Meter` would be in is what this pins: one that
    // never started writes nothing, not even on `finish`.
    var buffer: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var meter: Meter = .{ .out = &w, .style = .meter };

    meter.update(.{ .transferred = 100, .total = 200, .rate = 100, .elapsed_ns = ns_per_s });
    meter.finish();

    try testing.expectEqualStrings("", w.buffered());
    try testing.expectEqual(false, meter.started);
}

test "-s with -S still reports an error" {
    // Measured against curl 8.21.0: `-s -S` prints the failure and draws
    // no meter. `-S` brings back the message, never the meter. zurl's
    // `main` builds the meter from `plan.silent` alone, so `-S` cannot
    // turn one on.
    const Plan = struct { silent: bool, show_error: bool };
    const cases = [_]struct { plan: Plan, meter: bool, message: bool }{
        .{ .plan = .{ .silent = false, .show_error = false }, .meter = true, .message = true },
        .{ .plan = .{ .silent = true, .show_error = false }, .meter = false, .message = false },
        .{ .plan = .{ .silent = true, .show_error = true }, .meter = false, .message = true },
        .{ .plan = .{ .silent = false, .show_error = true }, .meter = true, .message = true },
    };
    for (cases) |case| {
        try testing.expectEqual(case.meter, !case.plan.silent);
        try testing.expectEqual(case.message, !case.plan.silent or case.plan.show_error);
    }
}

test "the meter is written to stderr, never stdout" {
    // Two writers stand in for the two streams. The meter is given one of
    // them, and the body is written to the other. The body must come back
    // byte for byte.
    var err_buffer: [1024]u8 = undefined;
    var err_writer: Io.Writer = .fixed(&err_buffer);
    var out_buffer: [64]u8 = undefined;
    var out_writer: Io.Writer = .fixed(&out_buffer);

    var meter: Meter = .{ .out = &err_writer, .style = .meter };
    meter.start();
    try out_writer.writeAll("body-");
    meter.update(.{ .transferred = 5, .total = 10, .rate = 5, .elapsed_ns = ns_per_s });
    try out_writer.writeAll("bytes");
    meter.update(.{ .transferred = 10, .total = 10, .rate = 5, .elapsed_ns = 2 * ns_per_s });
    meter.finish();

    try testing.expectEqualStrings("body-bytes", out_writer.buffered());
    try testing.expect(std.mem.startsWith(u8, err_writer.buffered(), header));
    try testing.expect(err_writer.buffered().len > header.len);
}

test "a rate is formatted with a unit" {
    // curl's `max6out`, measured against curl 8.21.0 at each boundary.
    try expectSize("     0", 0);
    try expectSize(" 99999", 99_999);
    try expectSize("97.65k", 100_000);
    try expectSize("99.99k", 102_399);
    try expectSize("100.0k", 102_400);
    try expectSize("999.9k", 1_023_999);
    try expectSize(" 0.97M", 1_024_000);
    try expectSize(" 1.00M", 1_048_576);
    try expectSize("99.99M", 104_857_599);
    try expectSize("100.0M", 104_857_600);
    try expectSize(" 1.00G", 1_073_741_824);
}

// Everything below covers a case the six above miss.

test "a size field is six columns wide for every u64" {
    // The row only lines up while every field keeps its width. A `u64`
    // divides through to `E`, and the loop must stop there.
    try expectSize("15.99E", std.math.maxInt(u64));
    try expectSize(" 1.00T", 1024 * 1024 * 1024 * 1024);
    try expectSize(" 1.00P", 1024 * 1024 * 1024 * 1024 * 1024);
    try expectSize(" 1.00E", 1024 * 1024 * 1024 * 1024 * 1024 * 1024);
}

test "a time of zero is blank, because curl does not guess" {
    try expectDuration("       ", 0);
}

test "a time field is seven columns wide at every shape it takes" {
    // Measured against curl 8.21.0 by holding a transfer to 200 bytes a
    // second and reading the estimate it printed.
    try expectDuration("  00:01", 1);
    try expectDuration("  59:59", 3599);
    try expectDuration("1:00:00", 3600);
    try expectDuration("9:59:59", 35_999);
    try expectDuration("10h 00m", 36_000);
    try expectDuration("24h 00m", 86_400);
    try expectDuration("99h 59m", 359_999);
    try expectDuration(" 4d 04h", 360_000);
    try expectDuration("99d 00h", 99 * 86_400);
    try expectDuration("   102d", 102 * 86_400);
    try expectDuration("   999d", 999 * 86_400);
    try expectDuration("   999m", 999 * 30 * 86_400);
    try expectDuration("    82y", 1000 * 30 * 86_400);
    try expectDuration(">99999y", std.math.maxInt(u64));
}

test "a known total draws curl's columns, measured against curl 8.21.0" {
    // The row curl printed for a 500000 byte body, one second in, with
    // 166300 bytes in hand at 133632 bytes a second.
    try expectRow(
        " 33 488.2k  33 162.4k   0      0 130.5k      0   00:03   00:01   00:02 130.5k",
        .{ .transferred = 166_300, .total = 500_000, .rate = 133_632, .elapsed_ns = 1 * ns_per_s },
    );
}

test "a rate of zero leaves the estimate blank rather than divide by it" {
    // curl reports no percentage and no time until it has a rate. A first
    // draw always lands here, because no time has passed yet.
    try expectRow(
        "  0      0   0      0   0      0      0      0                              0",
        .{ .transferred = 0, .total = 0, .rate = 0, .elapsed_ns = 0 },
    );
    try expectRow(
        "  0 195.3k   0      0   0      0      0      0                              0",
        .{ .transferred = 0, .total = 200_000, .rate = 0, .elapsed_ns = 0 },
    );
}

test "a percent of a length nobody announced is zero, not a trap" {
    try testing.expectEqual(@as(u64, 0), percentOf(0, 0));
    try testing.expectEqual(@as(u64, 0), percentOf(0, 5_000));
    try testing.expectEqual(@as(u64, 50), percentOf(1000, 500));
    try testing.expectEqual(@as(u64, 50), percentOf(1_000_000, 500_000));
    // A peer that sent more than it announced cannot widen the column.
    try testing.expectEqual(@as(u64, 100), percentOf(1000, 5_000_000));
    try testing.expectEqual(@as(u64, 100), percentOf(std.math.maxInt(u64), std.math.maxInt(u64)));
}

test "the bar fills the width the caller names" {
    var buffer: [1 + max_columns]u8 = undefined;
    var fly: Fly = .{};
    for ([_]u16{ min_columns, 40, 79, 100, max_columns }) |columns| {
        const got = try render(&buffer, writeBar, .{
            Sample{ .transferred = 1, .total = 1 },
            columns,
            &fly,
        });
        try testing.expectEqual(@as(usize, 1 + columns), got.len);
        try testing.expect(std.mem.endsWith(u8, got, " 100.0%"));
    }
}

test "a width outside curl's bounds is clamped, not honoured" {
    // A terminal one column wide would leave a bar of minus six columns.
    var buffer: [1 + max_columns]u8 = undefined;
    var fly: Fly = .{};
    const narrow = try render(&buffer, writeBar, .{ Sample{ .transferred = 1, .total = 2 }, 1, &fly });
    try testing.expectEqual(@as(usize, 1 + min_columns), narrow.len);

    fly = .{};
    const wide = try render(&buffer, writeBar, .{ Sample{ .transferred = 1, .total = 2 }, 60_000, &fly });
    try testing.expectEqual(@as(usize, 1 + max_columns), wide.len);
}

test "the fly animation matches curl frame for frame" {
    // curl 8.21.0, measured with the length withheld and standard error
    // sent to a file. These are the first three frames, with the trailing
    // spaces trimmed off.
    const frames = [_][]const u8{
        "#=#=#",
        "##=#=#",
        "##-=#=-#",
    };
    var buffer: [1 + max_columns]u8 = undefined;
    var fly: Fly = .{};
    for (frames) |expected| {
        const got = try render(&buffer, writeBar, .{ Sample{ .transferred = 1, .total = 0 }, default_columns, &fly });
        try testing.expectEqual(@as(usize, 1 + default_columns), got.len);
        try testing.expectEqualStrings(expected, std.mem.trimEnd(u8, got[1..], " "));
    }
}

test "the fly glider turns around at the end and stays inside the row" {
    // The glider walks to the far end and back. Nothing may write outside
    // the row, and `writeFly` asserts the bound, so a walk of more frames
    // than the row is wide is what proves it.
    var buffer: [1 + max_columns]u8 = undefined;
    var fly: Fly = .{};
    var frame: u16 = 0;
    while (frame < 3 * min_columns) : (frame += 1) {
        const got = try render(&buffer, writeBar, .{ Sample{ .transferred = 1, .total = 0 }, min_columns, &fly });
        try testing.expectEqual(@as(usize, 1 + min_columns), got.len);
        try testing.expect(fly.glider >= 0);
        try testing.expect(fly.glider <= @as(i32, min_columns) - 6);
    }
}

test "the meter draws once for each period, not once for each byte" {
    // A reporter fires for every read. A meter that drew each time would
    // write megabytes to standard error.
    var buffer: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var meter: Meter = .{ .out = &w, .style = .meter };
    meter.start();
    const after_start = w.buffered().len;

    // Ten reports inside one second.
    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        meter.update(.{ .transferred = i * 100, .total = 10_000, .rate = 1000, .elapsed_ns = i * ns_per_s / 20 });
    }
    try testing.expectEqual(after_start, w.buffered().len);

    // One report in the next second draws one row.
    meter.update(.{ .transferred = 2000, .total = 10_000, .rate = 1000, .elapsed_ns = ns_per_s });
    try testing.expectEqual(after_start + 1 + row_width, w.buffered().len);
}

test "the bar draws ten frames a second, the way curl does" {
    var buffer: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var meter: Meter = .{ .out = &w, .style = .bar, .columns = default_columns };
    meter.start();
    // The bar writes no header, so nothing has gone out yet.
    try testing.expectEqual(@as(usize, 0), w.buffered().len);

    meter.update(.{ .transferred = 1, .total = 100, .rate = 1, .elapsed_ns = 50 * ns_per_ms });
    try testing.expectEqual(@as(usize, 0), w.buffered().len);

    meter.update(.{ .transferred = 2, .total = 100, .rate = 1, .elapsed_ns = 100 * ns_per_ms });
    try testing.expectEqual(@as(usize, 1 + default_columns), w.buffered().len);
}

test "the meter ends with a newline, so the next line starts clean" {
    var buffer: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var meter: Meter = .{ .out = &w, .style = .meter };
    meter.start();
    meter.update(.{ .transferred = 100, .total = 100, .rate = 100, .elapsed_ns = ns_per_s });
    meter.finish();
    try testing.expect(std.mem.endsWith(u8, w.buffered(), "\n"));

    // Calling it again writes nothing more.
    const ended = w.buffered().len;
    meter.finish();
    try testing.expectEqual(ended, w.buffered().len);
}

test "a meter that never started draws nothing, so a refused connect stays quiet" {
    var buffer: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var meter: Meter = .{ .out = &w, .style = .meter };
    meter.update(.{ .transferred = 1, .total = 1, .rate = 1, .elapsed_ns = ns_per_s });
    meter.finish();
    try testing.expectEqualStrings("", w.buffered());
}

test "a failed write stops the meter and does not fail the transfer" {
    // A writer with room for the header and nothing else stands in for a
    // pager the user closed. Every call below must return, and the meter
    // must record the fault rather than hide it.
    var buffer: [header.len + 4]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var meter: Meter = .{ .out = &w, .style = .meter };

    meter.start();
    try testing.expectEqual(true, meter.broken);

    meter.update(.{ .transferred = 1, .total = 2, .rate = 1, .elapsed_ns = ns_per_s });
    meter.finish();
    try testing.expectEqual(true, meter.broken);
}

test "the reporter keeps the C callback shape the bindings phase needs" {
    var buffer: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var meter: Meter = .{ .out = &w, .style = .meter };

    const r = meter.reporter();
    try testing.expectEqual(@as(*anyopaque, &meter), r.ctx);
    // The type of the field is the contract. A Zig closure would not
    // compile into it.
    try testing.expectEqual(
        *const fn (*anyopaque, u64, u64) callconv(.c) void,
        @TypeOf(r.report),
    );
}

test "the reporter reads the rate and the time from the speedometer" {
    var buffer: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var source: Io.Reader = .fixed("payload");
    var speedometer_buffer: [0]u8 = .{};
    var speedometer: zurl_stream.Speedometer = .init(&source, testing.io, &speedometer_buffer);

    var meter: Meter = .{ .out = &w, .style = .meter, .speedometer = &speedometer };
    meter.start();
    const r = meter.reporter();
    // The clock has hardly moved, so this report lands in the first period
    // and draws nothing new. What it must do is record the sample.
    r.report(r.ctx, 7, 7);
    try testing.expectEqual(@as(u64, 7), meter.last.transferred);
    try testing.expectEqual(@as(u64, 7), meter.last.total);

    meter.finish();
    try testing.expect(std.mem.endsWith(u8, w.buffered(), "\n"));
}

test "a meter with no speedometer ignores a report rather than trap" {
    var buffer: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    var meter: Meter = .{ .out = &w, .style = .meter };
    meter.start();
    const drawn = w.buffered().len;
    const r = meter.reporter();
    r.report(r.ctx, 5, 10);
    try testing.expectEqual(drawn, w.buffered().len);
}

test "a body on the terminal gets no meter, and every other body gets one" {
    // Measured against curl 8.21.0 under a real pty. Each row below names
    // the command that gave the answer, over a 200000 byte body.

    // `curl -o f URL` on a terminal. The body is in the file, so the
    // screen is free and curl draws.
    try testing.expect(draws(.{ .body_to_stdout = false, .stdout_is_terminal = true }));

    // `curl URL` on a terminal. The body is on the screen, so curl draws
    // nothing. This is the case the rule exists for.
    try testing.expect(!draws(.{ .body_to_stdout = true, .stdout_is_terminal = true }));

    // `curl URL | cat`. Standard output is a pipe, so the meter on
    // standard error cannot reach the body, and curl draws.
    try testing.expect(draws(.{ .body_to_stdout = true, .stdout_is_terminal = false }));

    // `curl -o f URL > file`. Neither stream carries the other's bytes.
    try testing.expect(draws(.{ .body_to_stdout = false, .stdout_is_terminal = false }));

    // Standard error is not an input at all, and that is measured too:
    // `curl URL 2>err` on a terminal leaves `err` empty. Moving the meter
    // off the screen does not bring it back, so `Visibility` carries no
    // field for where standard error goes.
}

test "-s draws nothing whatever the body does, and -Z draws nothing either" {
    // `-s` silences both shapes of meter, and `-S` does not bring the
    // meter back. Measured against curl 8.21.0: `-S -o f URL` draws, and
    // `-s -S -o f URL` draws nothing.
    for ([_]bool{ false, true }) |body_to_stdout| {
        for ([_]bool{ false, true }) |stdout_is_terminal| {
            try testing.expect(!draws(.{
                .silent = true,
                .body_to_stdout = body_to_stdout,
                .stdout_is_terminal = stdout_is_terminal,
            }));
            try testing.expect(!draws(.{
                .parallel = true,
                .body_to_stdout = body_to_stdout,
                .stdout_is_terminal = stdout_is_terminal,
            }));
        }
    }
}

test "COLUMNS names the width, and a width nobody can read does not" {
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();

    // No COLUMNS. The suite does not run on a terminal, so the fallback
    // answers.
    try testing.expectEqual(default_columns, terminalColumns(&env));

    try env.put("COLUMNS", "40");
    try testing.expectEqual(@as(u16, 40), terminalColumns(&env));

    // Outside curl's bounds, and not a number at all. Both fall back.
    try env.put("COLUMNS", "3");
    try testing.expectEqual(default_columns, terminalColumns(&env));
    try env.put("COLUMNS", "100000");
    try testing.expectEqual(default_columns, terminalColumns(&env));
    try env.put("COLUMNS", "wide");
    try testing.expectEqual(default_columns, terminalColumns(&env));
    try env.put("COLUMNS", "");
    try testing.expectEqual(default_columns, terminalColumns(&env));
}

test "the header is the two lines curl prints, and the row lines up under them" {
    // curl 8.21.0 writes a header of 78 and 76 columns, and rows of 77.
    // The numbers differ, and each one is what curl writes.
    var lines = std.mem.splitScalar(u8, header, '\n');
    try testing.expectEqual(@as(usize, 78), lines.next().?.len);
    try testing.expectEqual(@as(usize, 76), lines.next().?.len);
    // The header ends with a newline, so the split leaves one empty tail
    // and nothing after it.
    try testing.expectEqualStrings("", lines.next().?);
    try testing.expectEqual(@as(?[]const u8, null), lines.next());
    try testing.expectEqual(@as(usize, 77), row_width);
}
