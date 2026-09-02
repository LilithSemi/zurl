//! Finds a private key on disk and reads it.
//!
//! What this module owns: the search order, the path building, the read,
//! and the wipe of the text afterwards. It is the only file in this
//! package that touches a directory.
//!
//! What this module does not own: it parses nothing.
//! `zurl_ssh.privatekey` reads the format. **It also reads no environment
//! variable.** `Location.home` is a value the caller supplies, the way
//! `zurl.Transfer.Options.netrc_text` is the text a caller already read. A
//! library that read `HOME` on its own would give a program that sets its
//! own home directory two answers, and it would make every test here
//! depend on the environment the test runs in.
//!
//! **The search order is curl's and OpenSSH's.** An explicit path, which
//! is curl's `--key`, is the only candidate when it is given: a path that
//! does not open is a named failure and never a quiet fall back to a key
//! the user did not ask for. With no explicit path the candidates are the
//! names under `~/.ssh` that `ssh` itself tries, in the same order, and
//! the first one that opens wins.
//!
//! **A key type this build cannot sign with is still opened and still
//! named.** `id_rsa` is in the default list on purpose. A user with only
//! an RSA key gets `PrivateKeyAlgorithmUnsupported` and the reason
//! `zurl_ssh.privatekey.refusalFor` holds, which is a better answer than
//! "no key found".
//!
//! **The text of a key file is a secret at rest.** `Opened.close` wipes
//! the whole buffer with `std.crypto.secureZero` before it frees it, and
//! `load` calls it whichever way it leaves.
//!
//! **This module reads no file mode, and that is a difference from
//! `ssh`.** OpenSSH refuses a private key the group or the world can
//! read. The permission type is a different shape on every system this
//! builds for, and the refusal belongs beside the message a user reads, so
//! the check goes in with the command line flags and not here.

const std = @import("std");

const privatekey = @import("privatekey.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// The directory the default names live in, under the user's home.
pub const default_directory = ".ssh";

/// The key file names to try, in order, when the caller names no path.
///
/// This is `ssh`'s own list with the names this build cannot sign with
/// kept in. See the module comment for why.
pub const default_names = [_][]const u8{
    "id_ed25519",
    "id_ecdsa",
    "id_rsa",
    "id_dsa",
};

/// How many bytes a path may take.
pub const max_path_bytes = Io.Dir.max_path_bytes;

/// Where to look for a key.
pub const Location = struct {
    /// The path the caller named, which is curl's `--key`. Null uses the
    /// defaults below.
    path: ?[]const u8 = null,
    /// The user's home directory, which the caller read. Null means the
    /// defaults cannot be built, and a `Location` with neither field is
    /// `error.KeyHomeUnknown`.
    home: ?[]const u8 = null,
};

/// Why a key file could not be read.
pub const ReadError = Allocator.Error || error{
    /// A candidate path is longer than `max_path_bytes`, or longer than
    /// the buffer the caller gave.
    KeyPathTooLong,
    /// The caller named no path and no home directory, so there is
    /// nothing to look in.
    KeyHomeUnknown,
    /// None of the default names opened. The user has no key under
    /// `~/.ssh`.
    KeyFileNotFound,
    /// The path the caller named did not open, or a read of it stopped.
    /// **An explicit path never falls back to a default.**
    KeyFileUnreadable,
    /// The file is longer than `zurl_ssh.privatekey.max_text_bytes`.
    KeyFileTooLong,
};

/// A key file that has been read.
///
/// **`text` holds a secret.** Call `close`, which wipes it before it frees
/// it.
pub const Opened = struct {
    /// The whole file. Owned by the allocator `read` was given.
    text: []u8,
    /// The path that opened. It points into the buffer the caller gave
    /// `read`.
    path: []const u8,

    /// Wipes the text and frees it. Safe to call more than once.
    pub fn close(o: *Opened, gpa: Allocator) void {
        std.crypto.secureZero(u8, o.text);
        gpa.free(o.text);
        o.text = &.{};
    }
};

/// Reads the key file `location` names.
///
/// `path_storage` holds the path that is tried, and it must be at least
/// `max_path_bytes` long. The path in the result points into it, so it
/// must outlive the result.
pub fn read(
    gpa: Allocator,
    io: Io,
    location: Location,
    path_storage: []u8,
) ReadError!Opened {
    // The limit is one byte over the bound, so a file exactly at the bound
    // reads and a file over it is `error.StreamTooLong` rather than a
    // silent cut.
    const limit: Io.Limit = .limited(privatekey.max_text_bytes + 1);

    if (location.path) |named| {
        const path = try copyPath(path_storage, named);
        const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, limit) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return error.KeyFileTooLong,
            // **Every other failure is one error, on purpose.** A caller
            // that named a path gets "zurl did not read this path", and
            // the operating system's own name for the fault belongs in a
            // diagnostic and not in the search.
            else => return error.KeyFileUnreadable,
        };
        return .{ .text = text, .path = path };
    }

    const home = location.home orelse return error.KeyHomeUnknown;
    for (default_names) |name| {
        const path = try buildDefaultPath(path_storage, home, name);
        const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, limit) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return error.KeyFileTooLong,
            // A name that is not there is the ordinary case, because a
            // user has one or two of these four. The next name is tried.
            //
            // **A name that is there and will not open is not skipped.**
            // A key with the wrong permissions is a thing the user must
            // be told about, and passing over it would have zurl report
            // "no key found" for a key that is plainly there.
            error.FileNotFound => continue,
            else => return error.KeyFileUnreadable,
        };
        return .{ .text = text, .path = path };
    }
    return error.KeyFileNotFound;
}

/// Why a key could not be loaded.
pub const LoadError = ReadError || privatekey.ParseError;

/// Reads the key file `location` names and parses it.
///
/// Returns the path that was read, which points into `path_storage`. A
/// caller that reports a fault names that path.
///
/// `key` is written in place. The caller calls `PrivateKey.deinit` on it.
/// **The text of the file is wiped before this returns**, whichever way it
/// leaves.
pub fn load(
    key: *privatekey.PrivateKey,
    gpa: Allocator,
    io: Io,
    location: Location,
    passphrase: ?[]const u8,
    path_storage: []u8,
) LoadError![]const u8 {
    var opened = try read(gpa, io, location, path_storage);
    defer opened.close(gpa);
    try privatekey.parse(key, gpa, opened.text, passphrase);
    return opened.path;
}

/// Copies `path` into `out`.
fn copyPath(out: []u8, path: []const u8) ReadError![]u8 {
    if (path.len > out.len or path.len > max_path_bytes) return error.KeyPathTooLong;
    @memcpy(out[0..path.len], path);
    return out[0..path.len];
}

/// Builds `home/.ssh/name` into `out`.
fn buildDefaultPath(out: []u8, home: []const u8, name: []const u8) ReadError![]u8 {
    // A home directory that already ends in a separator gets no second
    // one. A path with `//` in it works on every system this builds for,
    // and it looks wrong in a message a user reads. A home of `/` trims to
    // nothing, and the separator this function writes is the one that
    // makes the path absolute again.
    var trimmed = home;
    while (trimmed.len != 0 and trimmed[trimmed.len - 1] == '/') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    const total = trimmed.len + 1 + default_directory.len + 1 + name.len;
    if (total > out.len or total > max_path_bytes) return error.KeyPathTooLong;

    var at: usize = 0;
    @memcpy(out[at..][0..trimmed.len], trimmed);
    at += trimmed.len;
    out[at] = '/';
    at += 1;
    @memcpy(out[at..][0..default_directory.len], default_directory);
    at += default_directory.len;
    out[at] = '/';
    at += 1;
    @memcpy(out[at..][0..name.len], name);
    at += name.len;
    return out[0..at];
}

const testing = std.testing;

/// A home directory with a `.ssh` in it, and nothing else.
///
/// Every test here reads a real path, because this module is about what
/// the operating system answers. `std.testing.tmpDir` gives a directory
/// the test runner removes afterwards.
const Home = struct {
    tmp: testing.TmpDir,
    root_storage: [max_path_bytes]u8,
    root_len: usize,

    fn init(h: *Home) !void {
        h.tmp = testing.tmpDir(.{});
        errdefer h.tmp.cleanup();
        try h.tmp.dir.createDirPath(testing.io, default_directory);
        h.root_len = try h.tmp.dir.realPath(testing.io, &h.root_storage);
    }

    fn deinit(h: *Home) void {
        h.tmp.cleanup();
    }

    fn root(h: *const Home) []const u8 {
        return h.root_storage[0..h.root_len];
    }

    /// Writes `text` to `~/.ssh/name`.
    fn put(h: *Home, name: []const u8, text: []const u8) !void {
        var path_storage: [max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_storage, "{s}/{s}", .{ default_directory, name });
        try h.tmp.dir.writeFile(testing.io, .{ .sub_path = path, .data = text });
    }

    /// The path of `~/.ssh/name`.
    fn pathOf(h: *const Home, out: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(out, "{s}/{s}/{s}", .{ h.root(), default_directory, name });
    }
};

test "a default key under the home directory is found and read" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();
    try home.put("id_ed25519", privatekey.test_plain_key);

    var path_storage: [max_path_bytes]u8 = undefined;
    var key: privatekey.PrivateKey = undefined;
    const used = try load(
        &key,
        testing.allocator,
        testing.io,
        .{ .home = home.root() },
        null,
        &path_storage,
    );
    defer key.deinit();

    try testing.expectEqualStrings("plain@zurl.test", key.comment());
    var expected_storage: [max_path_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        try home.pathOf(&expected_storage, "id_ed25519"),
        used,
    );
}

test "the default names are tried in order, and the first that opens wins" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();
    // The RSA key sits under the name that comes later in the list, so a
    // search that walked the list backwards would find it first.
    try home.put("id_rsa", privatekey.test_rsa_key);
    try home.put("id_ed25519", privatekey.test_plain_key);

    var path_storage: [max_path_bytes]u8 = undefined;
    var key: privatekey.PrivateKey = undefined;
    _ = try load(
        &key,
        testing.allocator,
        testing.io,
        .{ .home = home.root() },
        null,
        &path_storage,
    );
    defer key.deinit();
    try testing.expectEqualStrings("plain@zurl.test", key.comment());
}

test "a user with only an RSA key is told which key was found and why it is refused" {
    // **This is why `id_rsa` is in the default list.** A search that only
    // named `id_ed25519` would answer "no key found" for a user whose key
    // is plainly there.
    var home: Home = undefined;
    try home.init();
    defer home.deinit();
    try home.put("id_rsa", privatekey.test_rsa_key);

    var path_storage: [max_path_bytes]u8 = undefined;
    var key: privatekey.PrivateKey = undefined;
    try testing.expectError(error.PrivateKeyAlgorithmUnsupported, load(
        &key,
        testing.allocator,
        testing.io,
        .{ .home = home.root() },
        null,
        &path_storage,
    ));
}

test "an explicit path is the only candidate, and never falls back" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();
    try home.put("id_ed25519", privatekey.test_plain_key);
    try home.put("named", privatekey.test_encrypted_key);

    var named_storage: [max_path_bytes]u8 = undefined;
    const named = try home.pathOf(&named_storage, "named");

    var path_storage: [max_path_bytes]u8 = undefined;
    var key: privatekey.PrivateKey = undefined;
    _ = try load(
        &key,
        testing.allocator,
        testing.io,
        .{ .path = named, .home = home.root() },
        privatekey.test_encrypted_passphrase,
        &path_storage,
    );
    defer key.deinit();
    try testing.expectEqualStrings("enc@zurl.test", key.comment());

    // **A named path that is not there is a failure and not a fall back.**
    // `id_ed25519` is right there, and a search that used it would sign
    // with a key the user did not name.
    var missing_storage: [max_path_bytes]u8 = undefined;
    const missing = try home.pathOf(&missing_storage, "absent");
    var other: privatekey.PrivateKey = undefined;
    try testing.expectError(error.KeyFileUnreadable, load(
        &other,
        testing.allocator,
        testing.io,
        .{ .path = missing, .home = home.root() },
        null,
        &path_storage,
    ));
}

test "a home with no key at all, and a location with no home, each say so" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();

    var path_storage: [max_path_bytes]u8 = undefined;
    var key: privatekey.PrivateKey = undefined;
    try testing.expectError(error.KeyFileNotFound, load(
        &key,
        testing.allocator,
        testing.io,
        .{ .home = home.root() },
        null,
        &path_storage,
    ));

    try testing.expectError(error.KeyHomeUnknown, load(
        &key,
        testing.allocator,
        testing.io,
        .{},
        null,
        &path_storage,
    ));
}

test "a file too long for a key is refused by its length and never parsed" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();

    const big = try testing.allocator.alloc(u8, privatekey.max_text_bytes + 1);
    defer testing.allocator.free(big);
    @memset(big, 'a');
    try home.put("id_ed25519", big);

    var path_storage: [max_path_bytes]u8 = undefined;
    var key: privatekey.PrivateKey = undefined;
    try testing.expectError(error.KeyFileTooLong, load(
        &key,
        testing.allocator,
        testing.io,
        .{ .home = home.root() },
        null,
        &path_storage,
    ));
}

test "the default path is built with one separator, however the home ends" {
    var out: [max_path_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "/home/a/.ssh/id_ed25519",
        try buildDefaultPath(&out, "/home/a", "id_ed25519"),
    );
    try testing.expectEqualStrings(
        "/home/a/.ssh/id_ed25519",
        try buildDefaultPath(&out, "/home/a/", "id_ed25519"),
    );
    // A home of `/` keeps its one separator, because taking it off would
    // give a relative path.
    try testing.expectEqualStrings(
        "/.ssh/id_rsa",
        try buildDefaultPath(&out, "/", "id_rsa"),
    );

    var tiny: [8]u8 = undefined;
    try testing.expectError(
        error.KeyPathTooLong,
        buildDefaultPath(&tiny, "/home/a", "id_ed25519"),
    );
    try testing.expectError(
        error.KeyPathTooLong,
        copyPath(&tiny, "/a/rather/long/path"),
    );
}

test "the default names are ssh's own, in ssh's order" {
    try testing.expectEqual(@as(usize, 4), default_names.len);
    try testing.expectEqualStrings("id_ed25519", default_names[0]);
    try testing.expectEqualStrings("id_ecdsa", default_names[1]);
    try testing.expectEqualStrings("id_rsa", default_names[2]);
    try testing.expectEqualStrings("id_dsa", default_names[3]);
    try testing.expectEqualStrings(".ssh", default_directory);
}
