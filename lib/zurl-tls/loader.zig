//! Loads certificates from the sources `zurl-core.ca.resolve` names.
//!
//! `ca.resolve` decides which sources belong in the list, and in what
//! order. This module loads every source in that list, additively. Keeping
//! the two jobs apart is what lets the precedence rule in `ca.zig` stay a
//! table test with no filesystem.

const std = @import("std");
const zurl_core = @import("zurl-core");
const bundle = @import("bundle.zig");

const ca = zurl_core.ca;
const Allocator = std.mem.Allocator;
const Bundle = std.crypto.Certificate.Bundle;
const Io = std.Io;

/// The largest CA file this loader reads into memory in one go.
///
/// A `--cacert` file, `SSL_CERT_FILE`, or a file inside `--capath` /
/// `SSL_CERT_DIR` names untrusted input: the path comes from a flag or an
/// environment variable, not from zurl itself. 16 MiB leaves more than ten
/// times the room the whole embedded NSS root store needs (about 1.4 MB),
/// and still turns a file that large into a runtime error instead of an
/// unbounded allocation.
const max_ca_file_bytes: usize = 16 * 1024 * 1024;

/// The errors `load` can return.
///
/// Every kind of source contributes its own error set: a file or a
/// directory can fail to open or to read, the embedded PEM can fail to
/// decode, and the native store can fail to scan.
pub const LoadError = Io.Dir.OpenError ||
    Io.Dir.ReadFileAllocError ||
    Io.Dir.Iterator.Error ||
    Bundle.RescanError ||
    bundle.AddPemError ||
    DirError;

/// The faults that belong to a `.dir` source as a whole, and not to one
/// entry inside it.
pub const DirError = error{
    /// The directory holds no entry that zurl can read as certificates.
    ///
    /// An empty directory, and a directory where every entry was skipped,
    /// both give this. See `loadDir` for why it is a fault and not a
    /// quiet zero.
    NoUsableCertificateFile,
};

/// Everything that reading one file as certificates can report.
///
/// `loadDir` catches this whole set for one entry and keeps going, so the
/// set has to stay exactly the faults of that one file. `LoadError` is
/// wider: it also holds the faults of a directory taken together, and
/// catching those for one entry would hide them.
pub const FileError = Io.Dir.ReadFileAllocError || bundle.AddPemError;

/// The one reason an entry is skipped that no `std` call reports.
///
/// `loadDir` tests the kind of an entry before it opens the entry, so a
/// device node or a directory cannot hold up the scan. See `useDirEntry`.
const KindError = error{
    /// The entry is a directory, a device, a socket, or a pipe. Only a
    /// file and a symbolic link can hold certificates.
    NotAFile,
};

/// The record of every directory entry a `.dir` source did not use.
///
/// IronStyle says recovery is never silent. `loadDir` recovers from a bad
/// entry by skipping it, so the skip has to reach the user. The loader has
/// no output stream of its own, so it writes here instead, and the caller
/// puts the text where its own user can read it. `zurl.Client` holds one
/// of these and `zurl.Client.takeCaSkips` hands the text to the command
/// line, which prints one line to standard error.
///
/// The storage is fixed, so a directory with ten thousand bad entries
/// cannot grow this without bound. `count` still counts every skip, and
/// `truncated` says that the text holds fewer entries than `count`.
pub const Skips = struct {
    /// How many bytes of names and reasons this record holds.
    pub const text_len: usize = 512;

    /// How many entries were skipped, the ones past `storage` included.
    count: usize = 0,
    /// True when at least one skip did not fit in `storage`.
    truncated: bool = false,
    /// Owned storage behind `text`. Read it through `text`.
    storage: [text_len]u8 = undefined,
    /// How many bytes of `storage` hold text.
    len: usize = 0,

    /// Records one skipped entry of the directory at `dir_path`.
    ///
    /// Never fails. A skip that does not fit sets `truncated` and still
    /// counts, because a count that is short is worse than a name that is
    /// missing.
    pub fn add(s: *Skips, dir_path: []const u8, name: []const u8, reason: anyerror) void {
        s.count += 1;
        const parts = [_][]const u8{
            if (s.len == 0) "" else "; ",
            dir_path,
            "/",
            name,
            " (",
            @errorName(reason),
            ")",
        };
        var needed: usize = 0;
        for (parts) |part| needed += part.len;
        if (s.len + needed > text_len) {
            s.truncated = true;
            return;
        }
        for (parts) |part| {
            @memcpy(s.storage[s.len..][0..part.len], part);
            s.len += part.len;
        }
    }

    /// The names and reasons, as one line. Empty when nothing was skipped.
    pub fn text(s: *const Skips) []const u8 {
        return s.storage[0..s.len];
    }

    /// True when at least one entry was skipped.
    pub fn any(s: *const Skips) bool {
        return s.count > 0;
    }
};

/// Loads every source in `sources` into `cb`, in the order given, adding to
/// whatever `cb` already holds.
///
/// A path in `sources` comes from a `--cacert`-style flag or an environment
/// variable. A missing or unreadable file is therefore a runtime fault, and
/// this function returns the error `std` reports for it instead of
/// asserting the open succeeded.
///
/// `now` is the current time. A certificate whose validity period has ended
/// by `now` is left out, the rule `bundle.addCertsFromPem` already applies.
///
/// `.native` reads the host trust store through `Bundle.rescan`, which
/// clears whatever bundle it is given before it scans. Scanning straight
/// into `cb` would silently discard every certificate an earlier source in
/// `sources` had already added, breaking the additive contract this
/// function promises. So `.native` scans into a scratch bundle first, then
/// folds its certificates into `cb` through the same `parseCert` path every
/// other source uses, which also gives it the same de-duplication and
/// expiry check.
///
/// `skips` records every entry a `.dir` source did not use. Pass null only
/// where no user reads the result. A `.file` source records nothing here:
/// the caller named that one file, so a file that does not load is a fault
/// and not a skip.
pub fn load(
    cb: *Bundle,
    gpa: Allocator,
    io: Io,
    now: Io.Timestamp,
    sources: []const ca.Source,
    skips: ?*Skips,
) LoadError!void {
    for (sources) |source| switch (source) {
        .file => |path| try loadFile(cb, gpa, io, now, path),
        .dir => |path| try loadDir(cb, gpa, io, now, path, skips),
        .native => try loadNative(cb, gpa, io, now),
        .embedded => _ = try bundle.loadEmbedded(cb, gpa, now.toSeconds()),
    };
}

/// Reads `sub_path`, resolved against `dir`, and adds every certificate it
/// holds to `cb`, through the guard `bundle.addCertsFromPem` applies.
///
/// `std.crypto.Certificate.Bundle`'s own file loaders
/// (`addCertsFromFile*`) hand the raw file bytes straight to `parseCert`
/// with no guard, which is safe only for a bundle zurl generated itself.
/// `sub_path` here names a `--cacert`, `--capath`, `SSL_CERT_FILE`, or
/// `SSL_CERT_DIR` file, none of which zurl trusts, so this function reads
/// the file itself and routes the bytes through `addCertsFromPem` instead.
///
/// The read is bounded by `max_ca_file_bytes`, so a file larger than that
/// is a runtime error, not an unbounded allocation.
fn addFileToBundle(
    cb: *Bundle,
    gpa: Allocator,
    io: Io,
    now: Io.Timestamp,
    dir: Io.Dir,
    sub_path: []const u8,
) FileError!void {
    const pem = try dir.readFileAlloc(io, sub_path, gpa, .limited(max_ca_file_bytes));
    defer gpa.free(pem);
    _ = try bundle.addCertsFromPem(cb, gpa, pem, now.toSeconds());
}

/// Adds every certificate in the PEM file at `path` to `cb`.
///
/// `path` can be relative or absolute. `Io.Dir.cwd()` resolves either form
/// on its own, the way opening any other file does, so this function does
/// not assert `path` is one or the other.
fn loadFile(cb: *Bundle, gpa: Allocator, io: Io, now: Io.Timestamp, path: []const u8) LoadError!void {
    return addFileToBundle(cb, gpa, io, now, .cwd(), path);
}

/// Reads one directory entry into `cb`, or reports why it cannot.
///
/// **This is the one rule that decides a skipped entry: zurl uses an entry
/// only when it reads the entry as a PEM file of certificates.** The kind
/// test is that same rule, applied before the open: a directory, a device
/// node, a socket, and a pipe are not files that hold certificates, and a
/// read from a device node can hold up the whole scan, so the kind is
/// checked first. Everything else the rule covers reports itself as an
/// error from the read or from the decode: an unreadable file gives
/// `AccessDenied`, a dangling symbolic link gives `FileNotFound`, a
/// symbolic link to a directory gives `IsDir`, a file past
/// `max_ca_file_bytes` gives `StreamTooLong`, and a truncated or malformed
/// certificate gives the name `bundle.addCertsFromPem` gives it.
///
/// A file with no PEM armor at all, and an empty file, are not skips.
/// `addCertsFromPem` finds no `BEGIN CERTIFICATE` marker in either, adds
/// nothing, and returns no error. The entry was read, so the rule is
/// satisfied and the directory keeps whatever the other entries hold.
fn useDirEntry(
    cb: *Bundle,
    gpa: Allocator,
    io: Io,
    now: Io.Timestamp,
    dir: Io.Dir,
    entry: Io.Dir.Entry,
) (FileError || KindError)!void {
    switch (entry.kind) {
        .file, .sym_link => {},
        else => return error.NotAFile,
    }
    return addFileToBundle(cb, gpa, io, now, dir, entry.name);
}

/// Adds every certificate in every usable file of the directory at `path`
/// to `cb`.
///
/// **One bad entry does not take the directory down with it.** `--capath`
/// and `SSL_CERT_DIR` name a directory a machine owns, not a file zurl
/// wrote, and a stale, unreadable, or truncated entry there is ordinary.
/// An abort would then throw away every root the good entries hold and
/// leave the transfer with nothing to verify against. So each entry is
/// read on its own, and an entry that `useDirEntry` refuses is skipped
/// and recorded in `skips`. Recovery is never silent: `zurl.Client` reads
/// `skips` back and the command line prints one line naming what was
/// skipped and why.
///
/// Two faults are not the entry's fault and still stop the whole scan. A
/// failed allocation and a bundle grown past what `Bundle` can address are
/// properties of the run, not of one file, and skipping on either would
/// hide a fault the caller has to see.
///
/// **A directory with no usable entry is a fault, not a quiet zero.**
/// `zurl_core.ca.resolve` leaves `.embedded` out as soon as any source is
/// named, so a `--capath` that yields nothing yields no roots at all. A
/// quiet return there would let the run continue toward whatever another
/// source happened to add, or toward an empty bundle whose real cause was
/// several directories back. `NoUsableCertificateFile` names the cause
/// where it happened. An empty directory gives the same fault, for the
/// same reason: it holds no root either.
///
/// **zurl scans a plain directory of PEM files. curl does not.** curl's
/// `--capath` wants an OpenSSL `c_rehash` directory, where each root is
/// filed under a hash of its subject and OpenSSL opens only the one file a
/// certificate chain asks for. zurl reads every entry instead, so a plain
/// directory works and no `c_rehash` run is needed. That is a deliberate
/// difference, and it is why curl's behaviour on a bad entry says nothing
/// about what this function must do.
fn loadDir(
    cb: *Bundle,
    gpa: Allocator,
    io: Io,
    now: Io.Timestamp,
    path: []const u8,
    skips: ?*Skips,
) LoadError!void {
    var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);

    var usable: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        useDirEntry(cb, gpa, io, now, dir, entry) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.CertificateAuthorityBundleTooBig => return error.CertificateAuthorityBundleTooBig,
            else => {
                if (skips) |s| s.add(path, entry.name, err);
                continue;
            },
        };
        usable += 1;
    }

    if (usable == 0) return error.NoUsableCertificateFile;
}

/// Adds the host trust store to `cb`, without discarding what `cb` already
/// holds. See `load`'s doc comment for why this cannot call `cb.rescan`
/// directly.
fn loadNative(cb: *Bundle, gpa: Allocator, io: Io, now: Io.Timestamp) LoadError!void {
    var scratch: Bundle = .empty;
    defer scratch.deinit(gpa);
    try scratch.rescan(gpa, io, now);

    // `scratch.bytes` is a gap-free concatenation of the certificates that
    // survived rescan's own de-duplication, in the order rescan added them.
    // Sorting their start offsets recovers each one's exact byte range, so
    // each certificate can be appended and parsed on its own, the same
    // one-certificate-at-a-time pattern `addCertsFromPem` uses. That pattern
    // is what keeps `parseCert`'s rewind-on-duplicate safe: `parseCert`
    // rewinds `cb.bytes.items.len` back to the start of the one certificate
    // it was just given, and this only stays correct if that certificate's
    // bytes are the current tail of `cb.bytes` when `parseCert` runs.
    // Appending every certificate up front first, then parsing them in
    // whatever order the source hash map iterates, breaks that: a rewind
    // for one certificate would discard the bytes of every other
    // certificate already appended after it.
    var starts: std.ArrayList(u32) = .empty;
    defer starts.deinit(gpa);
    try starts.ensureTotalCapacityPrecise(gpa, scratch.map.count());
    var it = scratch.map.iterator();
    while (it.next()) |entry| starts.appendAssumeCapacity(entry.value_ptr.*);
    std.mem.sort(u32, starts.items, {}, std.sort.asc(u32));

    const now_sec = now.toSeconds();
    var covered: u32 = 0;
    for (starts.items, 0..) |start, index| {
        const end: u32 = if (index + 1 < starts.items.len)
            starts.items[index + 1]
        else
            std.math.cast(u32, scratch.bytes.items.len) orelse
                return error.CertificateAuthorityBundleTooBig;
        const decoded_start = std.math.cast(u32, cb.bytes.items.len) orelse
            return error.CertificateAuthorityBundleTooBig;
        try cb.bytes.appendSlice(gpa, scratch.bytes.items[start..end]);
        try cb.parseCert(gpa, decoded_start, now_sec);
        covered = end;
    }
    // The loop above trusts that `starts.items`, sorted, tiles
    // `scratch.bytes` with no gap: it slices up to the next certificate's
    // start, or to the end of `scratch.bytes` for the last one. That trust
    // is unenforced anywhere else. This assertion pins it: if a future
    // `std` change ever makes `scratch.bytes` not gap-free, the mismatch is
    // caught here as a programmer error, instead of silently mis-slicing a
    // certificate.
    std.debug.assert(covered == scratch.bytes.items.len);
}

fn testNow() Io.Timestamp {
    return .fromNanoseconds(1_700_000_000 * std.time.ns_per_s);
}

/// Returns the absolute path of a `std.testing.tmpDir` directory, so a test
/// can pass it to `load` as a `.dir` source.
fn tmpDirPath(tmp: *std.testing.TmpDir) ![]u8 {
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(std.testing.io, &buffer);
    return std.testing.allocator.dupe(u8, buffer[0..n]);
}

/// Returns the raw DER-encoded subject of `bundle.fixture_pem`'s one
/// certificate, freshly decoded into its own scratch bundle.
///
/// `Bundle.find` compares its argument byte-for-byte against the subject
/// bytes already stored inside the bundle being searched, so it needs the
/// exact DER encoding, not the subject's human-readable name. Decoding the
/// fixture on its own is the most direct way to get that encoding, since
/// the same PEM decodes to the same DER bytes wherever it is loaded.
fn fixtureSubject(gpa: Allocator) ![]u8 {
    var reference: Bundle = .empty;
    defer reference.deinit(gpa);
    _ = try bundle.addCertsFromPem(&reference, gpa, bundle.fixture_pem, testNow().toSeconds());
    var it = reference.map.iterator();
    const entry = it.next().?;
    return gpa.dupe(u8, reference.bytes.items[entry.key_ptr.start..entry.key_ptr.end]);
}

test "a file source loads the certificates in that file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "roots.pem", .data = bundle.test_pem });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "roots.pem", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .file = path }}, null);
    try std.testing.expectEqual(@as(usize, 2), cb.map.count());
}

test "a dir source loads the certificates in every file it holds" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "roots.pem", .data = bundle.test_pem });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "fixture.pem", .data = bundle.fixture_pem });
    const path = try tmpDirPath(&tmp);
    defer std.testing.allocator.free(path);

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .dir = path }}, null);
    try std.testing.expectEqual(@as(usize, 3), cb.map.count());
}

/// A PEM file whose armor holds a primitive DER element at the top level.
/// Reproducer I from `bundle.zig`. `std.crypto.Certificate.parse` reads
/// past the end of this one, so the guard has to refuse it first.
const malformed_der_pem = "-----BEGIN CERTIFICATE-----\nAgEA\n-----END CERTIFICATE-----\n";

/// The fixture certificate, cut in half. The `BEGIN` marker is there and
/// the `END` marker is not, which is what a file that stopped mid-write
/// looks like.
const truncated_pem = bundle.fixture_pem[0 .. bundle.fixture_pem.len / 2];

/// What `loadDir` does with one extra file beside a real bundle.
const Verdict = enum {
    /// zurl reads the entry and finds no certificate in it. Not a skip:
    /// the file was read, it simply held nothing.
    read_and_empty,
    /// zurl cannot read the entry as certificates, so it skips the entry
    /// and records why.
    skipped,
    /// The operating system decides. A process that may read anything,
    /// such as root, reads the entry. Every other process skips it.
    depends_on_the_reader,
};

/// One shape of extra file in a `--capath` directory.
const CapathShape = struct {
    /// What the shape is, for the failure message.
    name: []const u8,
    /// The name of the extra file.
    file_name: []const u8,
    /// What the extra file holds.
    data: []const u8,
    /// True when the test takes every permission off the file.
    unreadable: bool = false,
    verdict: Verdict,
};

/// Every extra-file shape measured against zurl, each with its verdict.
///
/// This is a table so that a sixth shape cannot join without a verdict
/// beside it. Every row must leave the good certificates in the bundle:
/// that is the whole point of skipping an entry instead of aborting the
/// directory.
const capath_shapes = [_]CapathShape{
    .{
        .name = "plain garbage, no PEM armor",
        .file_name = "garbage",
        .data = "this file holds no certificate at all\n",
        .verdict = .read_and_empty,
    },
    .{
        .name = "an empty file",
        .file_name = "empty.pem",
        .data = "",
        .verdict = .read_and_empty,
    },
    .{
        .name = "PEM armor wrapping malformed DER",
        .file_name = "malformed.pem",
        .data = malformed_der_pem,
        .verdict = .skipped,
    },
    .{
        .name = "a truncated certificate",
        .file_name = "truncated.pem",
        .data = truncated_pem,
        .verdict = .skipped,
    },
    .{
        .name = "a file with mode 000, unreadable",
        .file_name = "locked.pem",
        .data = bundle.fixture_pem,
        .unreadable = true,
        .verdict = .depends_on_the_reader,
    },
};

test "one bad file in a capath directory does not cost the transfer its other roots" {
    for (capath_shapes) |shape| {
        var tmp = std.testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();

        // The real roots. Two certificates, and every row must keep both.
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "roots.pem", .data = bundle.test_pem });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = shape.file_name, .data = shape.data });
        if (shape.unreadable) {
            var file = try tmp.dir.openFile(std.testing.io, shape.file_name, .{});
            defer file.close(std.testing.io);
            try file.setPermissions(std.testing.io, @enumFromInt(0));
        }

        const path = try tmpDirPath(&tmp);
        defer std.testing.allocator.free(path);

        var cb: Bundle = .empty;
        defer cb.deinit(std.testing.allocator);
        var skips: Skips = .{};
        load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .dir = path }}, &skips) catch |err| {
            std.debug.print("shape \"{s}\" failed the whole directory: {t}\n", .{ shape.name, err });
            return err;
        };

        // The roots the good file holds are still there. Before the fix,
        // three of these five rows threw all of them away.
        std.testing.expectEqual(@as(usize, 2), cb.map.count()) catch |err| {
            std.debug.print("shape \"{s}\" lost a root\n", .{shape.name});
            return err;
        };

        switch (shape.verdict) {
            .read_and_empty => try std.testing.expectEqual(@as(usize, 0), skips.count),
            .skipped => {
                try std.testing.expectEqual(@as(usize, 1), skips.count);
                // Recovery is never silent: the record names the entry.
                try std.testing.expect(std.mem.indexOf(u8, skips.text(), shape.file_name) != null);
            },
            // A test that runs as root reads the file, so both answers are
            // correct here. The row above still holds either way, which is
            // what this shape measures.
            .depends_on_the_reader => try std.testing.expect(skips.count <= 1),
        }
    }
}

test "a capath directory with no usable entry names its own fault" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bad.pem", .data = malformed_der_pem });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "cut.pem", .data = truncated_pem });
    const path = try tmpDirPath(&tmp);
    defer std.testing.allocator.free(path);

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    var skips: Skips = .{};
    // No roots came out of this directory, and `ca.resolve` leaves
    // `.embedded` out as soon as a source is named. A quiet return would
    // send the transfer on with an empty bundle and no cause named.
    try std.testing.expectError(
        error.NoUsableCertificateFile,
        load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .dir = path }}, &skips),
    );
    try std.testing.expectEqual(@as(usize, 2), skips.count);
    try std.testing.expect(std.mem.indexOf(u8, skips.text(), "bad.pem") != null);
    try std.testing.expect(std.mem.indexOf(u8, skips.text(), "cut.pem") != null);
}

test "an empty capath directory holds no root either, and says so" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpDirPath(&tmp);
    defer std.testing.allocator.free(path);

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.NoUsableCertificateFile,
        load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .dir = path }}, null),
    );
}

test "a subdirectory inside a capath directory is skipped, not read" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "roots.pem", .data = bundle.test_pem });
    try tmp.dir.createDir(std.testing.io, "nested", .default_dir);
    const path = try tmpDirPath(&tmp);
    defer std.testing.allocator.free(path);

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    var skips: Skips = .{};
    try load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .dir = path }}, &skips);
    try std.testing.expectEqual(@as(usize, 2), cb.map.count());
    try std.testing.expectEqual(@as(usize, 1), skips.count);
    try std.testing.expect(std.mem.indexOf(u8, skips.text(), "NotAFile") != null);
}

test "a dangling symbolic link inside a capath directory is skipped, not read" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "roots.pem", .data = bundle.test_pem });
    // A stale link into `/etc/ssl/certs` is the ordinary shape of this on
    // a real machine: the certificate it named was removed and the link
    // stayed.
    tmp.dir.symLink(std.testing.io, "gone.pem", "stale.pem", .{}) catch |err| switch (err) {
        // A file system with no symbolic links cannot hold this shape.
        error.AccessDenied, error.Unexpected => return error.SkipZigTest,
        else => return err,
    };
    const path = try tmpDirPath(&tmp);
    defer std.testing.allocator.free(path);

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    var skips: Skips = .{};
    try load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .dir = path }}, &skips);
    try std.testing.expectEqual(@as(usize, 2), cb.map.count());
    try std.testing.expectEqual(@as(usize, 1), skips.count);
    try std.testing.expect(std.mem.indexOf(u8, skips.text(), "stale.pem") != null);
}

test "the skip record stays inside its own storage" {
    var skips: Skips = .{};
    // Far more skips than `text_len` can name. The count must still be
    // exact, because a count that is short hides work the loader did.
    var index: usize = 0;
    while (index < 500) : (index += 1) {
        skips.add("/etc/ssl/certs", "some-fairly-long-entry-name.pem", error.AccessDenied);
    }
    try std.testing.expectEqual(@as(usize, 500), skips.count);
    try std.testing.expect(skips.truncated);
    try std.testing.expect(skips.text().len <= Skips.text_len);
    try std.testing.expect(skips.any());
}

test "the embedded source loads the built-in roots" {
    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.embedded}, null);
    try std.testing.expect(cb.map.count() > 100);
}

test "a missing file returns FileNotFound" {
    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.FileNotFound,
        load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .file = "/nonexistent/roots.pem" }}, null),
    );
}

test "a relative path loads a CA file instead of hitting the isAbsolute assertion" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "roots.pem", .data = bundle.test_pem });

    // `std.crypto.Certificate.Bundle.addCertsFromFilePathAbsolute` asserts
    // its path is absolute. `--cacert` and `SSL_CERT_FILE` accept relative
    // paths too, so `load` must not route through that assertion. Proving
    // it does not needs an actually relative path, resolved against the
    // process's real working directory, so this test moves that directory
    // into `tmp` for the call and restores it afterwards.
    var original_cwd = try Io.Dir.cwd().openDir(std.testing.io, ".", .{});
    defer original_cwd.close(std.testing.io);
    try std.process.setCurrentDir(std.testing.io, tmp.dir);
    defer std.process.setCurrentDir(std.testing.io, original_cwd) catch {};

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .file = "roots.pem" }}, null);
    try std.testing.expectEqual(@as(usize, 2), cb.map.count());
}

test "a malformed certificate in a cacert-style file is a runtime fault, not a panic" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // `AgEA` is reproducer I from `bundle.zig`: a primitive element at the
    // top level, where `std.crypto.Certificate.parse` reads at the start of
    // a constructed element's content. Unguarded, this panics; `load` must
    // route `.file` through the same guard the embedded bundle gets.
    const malformed = "-----BEGIN CERTIFICATE-----\nAgEA\n-----END CERTIFICATE-----\n";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bad.pem", .data = malformed });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "bad.pem", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.CertificateFieldHasInvalidLength,
        load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.{ .file = path }}, null),
    );
}

test "sources are additive, so a file and the embedded set both land" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "fixture.pem", .data = bundle.fixture_pem });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "fixture.pem", std.testing.allocator);
    defer std.testing.allocator.free(path);

    const fixture_subject = try fixtureSubject(std.testing.allocator);
    defer std.testing.allocator.free(fixture_subject);

    var only_embedded: Bundle = .empty;
    defer only_embedded.deinit(std.testing.allocator);
    try load(&only_embedded, std.testing.allocator, std.testing.io, testNow(), &.{.embedded}, null);

    var both: Bundle = .empty;
    defer both.deinit(std.testing.allocator);
    try load(&both, std.testing.allocator, std.testing.io, testNow(), &.{
        .{ .file = path },
        .embedded,
    }, null);

    // The embedded half: every subject the embedded set carries is still
    // there after the file source loaded first, and the fixture's subject
    // is not one of them, so the combined count is exactly one more.
    try std.testing.expectEqual(only_embedded.map.count() + 1, both.map.count());
    var it = only_embedded.map.iterator();
    while (it.next()) |entry| {
        const subject = only_embedded.bytes.items[entry.key_ptr.start..entry.key_ptr.end];
        try std.testing.expect(both.find(subject) != null);
    }

    // The file half: the fixture certificate, which no public trust store
    // carries, is present too. Without this, a `load` that silently dropped
    // every `.file` source would still pass the embedded-half check above.
    try std.testing.expect(both.find(fixture_subject) != null);
}

test "the native source does not error even when the host store is sparse or missing" {
    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{.native}, null);
}

test "a native source does not discard certificates an earlier source added" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "fixture.pem", .data = bundle.fixture_pem });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "fixture.pem", std.testing.allocator);
    defer std.testing.allocator.free(path);

    const fixture_subject = try fixtureSubject(std.testing.allocator);
    defer std.testing.allocator.free(fixture_subject);

    var cb: Bundle = .empty;
    defer cb.deinit(std.testing.allocator);
    try load(&cb, std.testing.allocator, std.testing.io, testNow(), &.{
        .{ .file = path },
        .native,
    }, null);
    // The fixture's subject is not in any public trust store, so this only
    // passes when the native scan that follows the file source keeps what
    // the file source already added. `cb.map.count() >= 2` (the previous
    // form of this test) could not tell that apart from a `.native` that
    // wipes the bundle first: the host trust store alone already clears
    // that floor. `cb.find` on a subject no host store can supply cannot.
    try std.testing.expect(cb.find(fixture_subject) != null);
}
