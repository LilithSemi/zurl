//! Host key trust: `known_hosts`, and the two ways curl pins a key on the
//! command line.
//!
//! `zurl_ssh.hostkey` proves that the peer holds the private key for the
//! key it presented. **It proves nothing about whether that key belongs to
//! the host the user asked for.** This module is the answer to that
//! second question, and it is the only answer this build has.
//!
//! ## What happens for a host that is not in the file
//!
//! **The transfer stops.** OpenSSH prints the fingerprint and asks a
//! person. zurl has nobody to ask: it runs in a script, in a pipeline, and
//! with no terminal, so a prompt would either hang or be answered by the
//! next byte of the input the transfer was reading. curl makes the same
//! decision, and it is measurable: curl 8.21.0 against a host with no
//! `known_hosts` entry exits 60 with
//! `SSL peer certificate or SSH remote key was not OK`, and prints
//! `did not find host '127.0.0.1' in '/home/…/.ssh/known_hosts'`.
//!
//! So zurl refuses, and it says what to do: run `ssh-keyscan`, or pass the
//! fingerprint with `--hostpubsha256`.
//!
//! **A key that is present and different is the serious case.** That is a
//! machine that was rebuilt, or somebody in the middle. It is
//! `error.HostKeyChanged`, it says so in those words, and **nothing here
//! writes the new key to the file**. A client that quietly updated the
//! record would turn the one check that catches an interception into a
//! check that records it.
//!
//! ## What skips the check
//!
//! `-k`, and nothing else. It is the same flag that turns TLS certificate
//! verification off, and it is the same size of decision: **the connection
//! is still encrypted and it is no longer to a host anybody identified.**
//! curl 8.21.0 does the same, measured: `-k` on an `sftp` url with no
//! `known_hosts` entry logs `no knownhosts file configured` and transfers.
//! There is no zurl flag that skips only the SSH check, because a second
//! spelling for one decision is a second thing to forget.
//!
//! ## What a `known_hosts` line may say
//!
//! ```
//! [marker] host-patterns keytype base64-key [comment]
//! ```
//!
//! - **The plain form.** `example.com ssh-ed25519 AAAA…`, and
//!   `[example.com]:2222 ssh-ed25519 AAAA…` for a port that is not 22.
//!   The patterns are separated by commas and may hold `*` and `?`. A
//!   pattern with `!` in front of it takes the host out of the line.
//! - **The hashed form**, which is what `ssh-keygen -H` and OpenSSH's own
//!   `HashKnownHosts yes` write: `|1|<base64 salt>|<base64 hash>`, where
//!   the hash is `HMAC-SHA1(salt, host)`. Hashing is why a stolen file
//!   does not name the hosts a person reaches, so a build that read only
//!   the plain form would refuse every host of a careful user.
//! - **`@revoked`**, which says the key must never be trusted again. A
//!   match on one is `error.HostKeyRejected` and never a fall through to
//!   another line.
//! - **`@cert-authority`**, which names a key that signs host
//!   certificates. **This build verifies no certificate**, so such a line
//!   is skipped and counted, and `Counters.certificate_authority_lines`
//!   is what makes that visible.
//!
//! ## Every bound
//!
//! | what | bound | why |
//! | --- | --- | --- |
//! | the whole file | `max_file_bytes`, 1 MiB | a file is input, and a reader with no bound is a reader a file chooses the memory for |
//! | one line | `max_line_bytes`, 8192 | a line with no bound is the same problem one level down |
//! | patterns on one line | `max_patterns`, 64 | each one is a match to run |
//! | `*` in one pattern | `max_wildcards`, 16 | the matcher backtracks, and a pattern of nothing but `*` is what makes that expensive |
//! | a base64 key blob | `max_key_bytes`, 1024 | the same bound `Transport` puts on a host key |
//! | a salt or a hash | `Hmac.mac_length` exactly | a hashed entry with any other length is not one |

const std = @import("std");

const hostkey = @import("hostkey.zig");

const Hmac = std.crypto.auth.hmac.HmacSha1;
const Md5 = std.crypto.hash.Md5;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The largest `known_hosts` file this build reads.
pub const max_file_bytes: usize = 1024 * 1024;

/// The largest line this build reads.
pub const max_line_bytes: usize = 8192;

/// How many host patterns one line may carry.
pub const max_patterns: usize = 64;

/// How many `*` one pattern may carry.
pub const max_wildcards: usize = 16;

/// The largest key blob this build decodes out of a line.
pub const max_key_bytes: usize = 1024;

/// The largest text `--hostpubmd5` or `--hostpubsha256` may carry.
pub const max_pin_bytes: usize = 128;

/// The port a `known_hosts` entry writes with no brackets around the host.
pub const default_port: u16 = 22;

/// The marker that says a key must never be trusted again.
pub const revoked_marker = "@revoked";

/// The marker that names a key which signs host certificates.
pub const certificate_authority_marker = "@cert-authority";

/// The prefix of a hashed host field, OpenSSH's `HASH_MAGIC`.
pub const hash_magic = "|1|";

/// What the file said about one host and one key.
pub const Outcome = enum {
    /// A line named this host and carried exactly this key.
    match,
    /// A line named this host and carried a different key of the same
    /// algorithm, and no line carried this key. **An attacker between the
    /// client and the host looks like this.**
    changed,
    /// A line named this host and marked the key `@revoked`.
    revoked,
    /// A line named this host, but no line carried a key of an algorithm
    /// this build can verify. The host is known and this key is not.
    algorithm_unknown,
    /// No line named this host at all.
    unknown,
};

/// What the search did that no caller asked for.
///
/// **Recovery is never silent.** A line this build cannot read is skipped
/// so that one bad line does not stop every host in the file from being
/// found, and each kind of skip is counted here so that the reason a host
/// was not found can be said out loud.
///
/// **`zurl_sftp.Fetcher.reportClient` reads them**, and it says how many
/// lines were skipped in the message it prints for a host it did not find.
/// A user who is told nothing about a skipped line writes a second line
/// that is skipped for the same reason.
pub const Counters = struct {
    /// How many lines were read.
    lines: u64 = 0,
    /// How many were blank or a comment.
    comments: u64 = 0,
    /// How many named `@cert-authority`, which this build cannot use.
    certificate_authority_lines: u64 = 0,
    /// How many had too few fields, a key that is not base64, or a
    /// pattern list past `max_patterns`.
    malformed: u64 = 0,
    /// How many were longer than `max_line_bytes`.
    over_length: u64 = 0,
    /// How many carried a key algorithm this build cannot verify.
    other_algorithm: u64 = 0,
    /// How many named this host.
    host_matches: u64 = 0,
};

/// Why a pin could not be read.
pub const PinError = error{
    /// `--hostpubmd5` is not 32 hexadecimal digits.
    HostPubMd5Invalid,
    /// `--hostpubsha256` is not the base64 of a 32 byte digest.
    HostPubSha256Invalid,
};

/// The directory the default file lives in, under the user's home.
pub const default_directory = ".ssh";

/// The name OpenSSH gives the file.
pub const default_name = "known_hosts";

/// Where the file is.
///
/// **This module reads no environment variable.** `home` is a value the
/// caller supplies, the same shape `zurl_ssh.keyfile.Location` has and for
/// the same reason: a library that read `HOME` itself would give a program
/// that sets its own home two answers, and every test here would depend on
/// the environment it runs in.
pub const Location = struct {
    /// `--knownhosts`. When it is set it is the only candidate, and a path
    /// that does not open is a refusal and **never** a quiet fall back to
    /// the default file.
    path: ?[]const u8 = null,
    /// The user's home directory, which the caller read. Null with no
    /// `path` means there is nothing to look in.
    home: ?[]const u8 = null,
};

/// Why the file could not be read.
pub const ReadError = std.mem.Allocator.Error || error{
    /// The path is longer than `std.Io.Dir.max_path_bytes`, or longer
    /// than the buffer the caller gave.
    KnownHostsPathTooLong,
    /// The caller named no path and no home directory.
    KnownHostsHomeUnknown,
    /// The default file is not there. The user has never connected to any
    /// host, and every host is therefore unknown.
    KnownHostsNotFound,
    /// The path the caller named did not open, or a read of it stopped.
    KnownHostsUnreadable,
    /// The file is longer than `max_file_bytes`.
    KnownHostsTooLong,
};

/// A `known_hosts` file that has been read.
pub const Opened = struct {
    /// The whole file. Owned by the allocator `read` was given.
    text: []u8,
    /// The path that opened. It points into the buffer the caller gave.
    path: []const u8,

    /// Frees the text.
    pub fn close(o: *Opened, gpa: std.mem.Allocator) void {
        gpa.free(o.text);
        o.text = &.{};
    }
};

/// Reads the file `location` names.
///
/// `path_storage` holds the path that is tried, and the path in the result
/// points into it.
pub fn read(
    gpa: std.mem.Allocator,
    io: std.Io,
    location: Location,
    path_storage: []u8,
) ReadError!Opened {
    // One byte over the bound, so a file exactly at the bound reads and a
    // file over it is a named refusal rather than a silent cut. A cut
    // `known_hosts` is a file whose last entry may be half a key.
    const limit: std.Io.Limit = .limited(max_file_bytes + 1);

    if (location.path) |named| {
        const path = try copyPath(path_storage, named);
        const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, limit) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return error.KnownHostsTooLong,
            // **A named file that will not open is never a fall back.**
            // A user who wrote `--knownhosts` and mistyped the path must
            // not silently get the default file, and must not silently
            // get "no record" either.
            else => return error.KnownHostsUnreadable,
        };
        return .{ .text = text, .path = path };
    }

    const home = location.home orelse return error.KnownHostsHomeUnknown;
    const path = try buildDefaultPath(path_storage, home);
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, limit) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.KnownHostsTooLong,
        // A user who has never used `ssh` has no file, and that is the
        // ordinary first run. It is still a refusal: nothing here can say
        // the key is right. It is kept apart from `Unreadable` so that
        // the message can name `ssh-keyscan` rather than a permission.
        error.FileNotFound => return error.KnownHostsNotFound,
        else => return error.KnownHostsUnreadable,
    };
    return .{ .text = text, .path = path };
}

fn copyPath(out: []u8, path: []const u8) ReadError![]u8 {
    if (path.len > out.len or path.len > std.Io.Dir.max_path_bytes) {
        return error.KnownHostsPathTooLong;
    }
    @memcpy(out[0..path.len], path);
    return out[0..path.len];
}

/// Builds `home/.ssh/known_hosts` into `out`.
fn buildDefaultPath(out: []u8, home: []const u8) ReadError![]u8 {
    // A home directory that already ends in a separator gets no second
    // one, for the reason `zurl_ssh.keyfile` gives: a path with `//` in it
    // works and looks wrong in a message a user reads.
    var trimmed = home;
    while (trimmed.len != 0 and trimmed[trimmed.len - 1] == '/') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    const total = trimmed.len + 1 + default_directory.len + 1 + default_name.len;
    if (total > out.len or total > std.Io.Dir.max_path_bytes) {
        return error.KnownHostsPathTooLong;
    }

    var at: usize = 0;
    @memcpy(out[at..][0..trimmed.len], trimmed);
    at += trimmed.len;
    out[at] = '/';
    at += 1;
    @memcpy(out[at..][0..default_directory.len], default_directory);
    at += default_directory.len;
    out[at] = '/';
    at += 1;
    @memcpy(out[at..][0..default_name.len], default_name);
    at += default_name.len;
    return out[0..at];
}

/// What the caller decided about host key trust.
pub const Policy = struct {
    /// The text of the `known_hosts` file, or null when the caller read
    /// none. **The caller owns it.**
    known_hosts: ?[]const u8 = null,
    /// The path the text came from, for a message a person reads. It is
    /// never opened here.
    known_hosts_path: []const u8 = "",
    /// Whether the file was named and could not be read. A named file
    /// that will not open is a refusal and never a fall through to "no
    /// record", because the two have different fixes.
    known_hosts_unreadable: bool = false,
    /// `--hostpubmd5`, as the user typed it.
    md5_pin: ?[]const u8 = null,
    /// `--hostpubsha256`, as the user typed it.
    sha256_pin: ?[]const u8 = null,
    /// `-k`. **The one value here that turns a check off.**
    insecure: bool = false,
};

/// Checks a host key against a `Policy`, and remembers what it decided.
///
/// A `Checker` must not move once `verifier` has run: the verifier carries
/// its address.
pub const Checker = struct {
    policy: Policy,
    /// What the last decision was, or null before there was one.
    outcome: ?Outcome = null,
    /// Whether a pin answered, rather than the file.
    pinned: bool = false,
    counters: Counters = .{},

    /// The trust decision this `Checker` makes, as `Transport` wants it.
    pub fn verifier(c: *Checker) hostkey.Verifier {
        return .{ .ctx = c, .decide = decide };
    }

    fn decide(
        ctx: ?*anyopaque,
        peer: hostkey.Peer,
        key: hostkey.PublicKey,
        blob: []const u8,
    ) hostkey.TrustError!void {
        const c: *Checker = @ptrCast(@alignCast(ctx.?));
        return c.check(peer, key, blob);
    }

    /// Runs the decision.
    ///
    /// The order is the order curl 8.21.0 runs it in, measured: a pin
    /// answers on its own and the file is never opened, and with no pin
    /// the file decides.
    pub fn check(
        c: *Checker,
        peer: hostkey.Peer,
        key: hostkey.PublicKey,
        blob: []const u8,
    ) hostkey.TrustError!void {
        _ = key;

        if (c.policy.sha256_pin) |text| {
            c.pinned = true;
            const ok = matchSha256Pin(text, blob) catch return error.HostKeyCheckFailed;
            c.outcome = if (ok) .match else .changed;
            return if (ok) {} else error.HostKeyChanged;
        }
        if (c.policy.md5_pin) |text| {
            c.pinned = true;
            const ok = matchMd5Pin(text, blob) catch return error.HostKeyCheckFailed;
            c.outcome = if (ok) .match else .changed;
            return if (ok) {} else error.HostKeyChanged;
        }

        // **`-k` skips the whole host key check, and that is curl's own
        // behaviour and not an oversight.** It was measured again against
        // curl 8.21.0 with libssh2 1.11.1, on 2026-09-15, with a real
        // sshd and a `known_hosts` file that names no host:
        //
        // - `curl --knownhosts ./empty sftp://127.0.0.1/tmp/x` said
        //   `did not find host '127.0.0.1' in './empty'`,
        //   `knownhost check failed`, and exited 60.
        // - The same command with `-k` said
        //   `no knownhosts file configured` and went on to the login. The
        //   file the user named was dropped.
        // - `curl -k --hostpubsha256 <wrong>` still refused, with
        //   `mismatch SHA256 fingerprint`, and exited 60.
        //
        // So `-k` turns the `known_hosts` check off and leaves a pin
        // running, which is the order below. A reader who finds this
        // arm and takes it for a bypass has found curl parity, and the
        // module comment says what it costs the user.
        //
        // **`-k` is read after the pins and never before them.** A user
        // who wrote both a pin and `-k` asked for one check and asked to
        // skip everything else, and the check they named is the one that
        // runs.
        if (c.policy.insecure) {
            c.outcome = .match;
            return;
        }

        if (c.policy.known_hosts_unreadable) {
            c.outcome = .unknown;
            return error.HostKeyCheckFailed;
        }
        const text = c.policy.known_hosts orelse {
            // No file at all is the same answer as a file that names
            // another host: nothing here can say the key is right.
            c.outcome = .unknown;
            return error.HostKeyUnknown;
        };

        const found = search(text, peer, blob, &c.counters);
        c.outcome = found;
        return switch (found) {
            .match => {},
            .changed => error.HostKeyChanged,
            .revoked => error.HostKeyRejected,
            // **These two are different answers and they get different
            // errors.** `algorithm_unknown` says the host is on record,
            // and a caller that reported it as "no record" would send the
            // user to `ssh-keyscan`. See `hostkey.HostKeyAlgorithmUnknown`.
            .algorithm_unknown => error.HostKeyAlgorithmUnknown,
            .unknown => error.HostKeyUnknown,
        };
    }
};

/// Walks `text` and says what it holds about `peer` and `blob`.
///
/// **One line that carries this key is enough.** A file may name a host on
/// more than one line, and OpenSSH's `check_key_in_hostkeys` reports the
/// key as known when any line carries it. A key rotation writes two lines,
/// one name in front of two machines writes two lines, and a specific line
/// beside a `*.example.com` line is two lines, so a build that reported a
/// change whenever any line differed would raise the loudest error it has
/// on an ordinary file. A false alarm here teaches a user to reach for
/// `-k`, which turns the whole check off.
///
/// **A revocation still beats everything.** It is the one answer that no
/// later line can soften, and it stops the walk where it is found.
pub fn search(
    text: []const u8,
    peer: hostkey.Peer,
    blob: []const u8,
    counters: *Counters,
) Outcome {
    var name_storage: [max_line_bytes]u8 = undefined;
    const name = hostName(&name_storage, peer) orelse return .unknown;
    // An empty name is no name. OpenSSH's `match_maybe_hashed` refuses
    // one, and a build that passed it on would let a `*` line answer for a
    // host that was never named.
    if (name.len == 0) return .unknown;

    var best: Outcome = .unknown;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        counters.lines += 1;
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len > max_line_bytes) {
            counters.over_length += 1;
            continue;
        }
        const found = readLine(line, name, blob, counters) orelse continue;
        best = stronger(best, found);
        // A revocation is the strongest answer there is, so nothing later
        // in the file can change it.
        if (best == .revoked) return best;
    }
    return best;
}

/// Which of two outcomes a caller must act on.
///
/// **A match outranks a change**, because a change is only what a line
/// that did not carry this key can say. One line that carries it makes the
/// key known, whatever the other lines hold. See `search`.
fn stronger(a: Outcome, b: Outcome) Outcome {
    const rank = struct {
        fn of(outcome: Outcome) u8 {
            return switch (outcome) {
                .unknown => 0,
                .algorithm_unknown => 1,
                .changed => 2,
                .match => 3,
                .revoked => 4,
            };
        }
    };
    return if (rank.of(b) > rank.of(a)) b else a;
}

/// Reads one line, or null when it says nothing about this host.
fn readLine(line: []const u8, name: []const u8, blob: []const u8, counters: *Counters) ?Outcome {
    var fields = std.mem.tokenizeAny(u8, line, " \t");
    var first = fields.next() orelse {
        counters.comments += 1;
        return null;
    };
    if (first[0] == '#') {
        counters.comments += 1;
        return null;
    }

    var revoked = false;
    if (first.len != 0 and first[0] == '@') {
        if (std.mem.eql(u8, first, revoked_marker)) {
            revoked = true;
        } else if (std.mem.eql(u8, first, certificate_authority_marker)) {
            // This build verifies no host certificate, so a line that
            // names a signing key names a trust path it cannot walk. It
            // is skipped and counted, and never taken for a plain key.
            counters.certificate_authority_lines += 1;
            return null;
        } else {
            counters.malformed += 1;
            return null;
        }
        first = fields.next() orelse {
            counters.malformed += 1;
            return null;
        };
    }

    const algorithm_text = fields.next() orelse {
        counters.malformed += 1;
        return null;
    };
    const key_text = fields.next() orelse {
        counters.malformed += 1;
        return null;
    };

    if (!matchHostField(first, name, counters)) return null;
    counters.host_matches += 1;

    // The host is named. Now the key, and an algorithm this build cannot
    // verify says nothing about the key it was shown.
    if (hostkey.fromName(algorithm_text) == null) {
        counters.other_algorithm += 1;
        return .algorithm_unknown;
    }

    var key_storage: [max_key_bytes]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(key_text) catch {
        counters.malformed += 1;
        return null;
    };
    if (size > key_storage.len) {
        counters.malformed += 1;
        return null;
    }
    decoder.decode(key_storage[0..size], key_text) catch {
        counters.malformed += 1;
        return null;
    };

    if (revoked) {
        // A revocation applies to the key it names and not to the host.
        // A different key on a revoked line says nothing.
        if (equalConstantTime(key_storage[0..size], blob)) return .revoked;
        return null;
    }
    if (equalConstantTime(key_storage[0..size], blob)) return .match;
    return .changed;
}

/// Whether the host field of a line names `name`.
///
/// The field is either the hashed form or a comma-separated pattern list.
fn matchHostField(field: []const u8, name: []const u8, counters: *Counters) bool {
    if (std.mem.startsWith(u8, field, hash_magic)) {
        return matchHashed(field, name) catch {
            counters.malformed += 1;
            return false;
        };
    }

    var patterns = std.mem.splitScalar(u8, field, ',');
    var hit = false;
    var seen: usize = 0;
    while (patterns.next()) |pattern| {
        seen += 1;
        if (seen > max_patterns) {
            counters.malformed += 1;
            return false;
        }
        if (pattern.len == 0) continue;
        if (pattern[0] == '!') {
            // A negation takes the host out of the line whatever else the
            // line said, so it answers on its own.
            if (matchPattern(pattern[1..], name)) return false;
            continue;
        }
        if (matchPattern(pattern, name)) hit = true;
    }
    return hit;
}

/// Why a hashed host field could not be read.
const HashedError = error{HashedEntryMalformed};

/// Whether a hashed host field names `name`.
///
/// The form is `|1|<base64 salt>|<base64 HMAC-SHA1(salt, name)>`.
fn matchHashed(field: []const u8, name: []const u8) HashedError!bool {
    const body = field[hash_magic.len..];
    const bar = std.mem.indexOfScalar(u8, body, '|') orelse return error.HashedEntryMalformed;
    const salt_text = body[0..bar];
    const hash_text = body[bar + 1 ..];

    const decoder = std.base64.standard.Decoder;
    var salt: [Hmac.mac_length]u8 = undefined;
    var stored: [Hmac.mac_length]u8 = undefined;

    const salt_len = decoder.calcSizeForSlice(salt_text) catch return error.HashedEntryMalformed;
    const hash_len = decoder.calcSizeForSlice(hash_text) catch return error.HashedEntryMalformed;
    // OpenSSH writes exactly one digest length for each. Anything else is
    // not this format, and a shorter comparison would be a weaker one.
    if (salt_len != salt.len or hash_len != stored.len) return error.HashedEntryMalformed;
    decoder.decode(&salt, salt_text) catch return error.HashedEntryMalformed;
    decoder.decode(&stored, hash_text) catch return error.HashedEntryMalformed;

    var computed: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&computed, name, &salt);
    return equalConstantTime(&computed, &stored);
}

/// Whether `pattern` names `name`.
///
/// `*` takes any run of bytes and `?` takes exactly one, which is what
/// OpenSSH's `match_pattern` does. The comparison of the ordinary bytes is
/// case-insensitive, because a host name is.
///
/// **The matcher never recurses.** It walks forward and remembers the last
/// `*` it passed, so a pattern of many stars costs one pass and a bounded
/// number of restarts rather than a tree of calls. `max_wildcards` bounds
/// the stars all the same, because a pattern is input.
fn matchPattern(pattern: []const u8, name: []const u8) bool {
    var stars: usize = 0;
    for (pattern) |byte| {
        if (byte == '*') stars += 1;
    }
    if (stars > max_wildcards) return false;

    var p: usize = 0;
    var n: usize = 0;
    var star: ?usize = null;
    var star_at: usize = 0;

    while (n < name.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            star_at = n;
            continue;
        }
        if (p < pattern.len and (pattern[p] == '?' or
            std.ascii.toLower(pattern[p]) == std.ascii.toLower(name[n])))
        {
            p += 1;
            n += 1;
            continue;
        }
        const last_star = star orelse return false;
        // Give the star one more byte and start again after it.
        p = last_star + 1;
        star_at += 1;
        n = star_at;
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// Writes the name a `known_hosts` line uses for `peer`.
///
/// OpenSSH writes the host on its own for port 22 and `[host]:port` for
/// anything else, and `ssh-keyscan -p` writes the same. A build that wrote
/// one form for both would find nothing for a host on a port of its own.
///
/// **The name is folded to lower case here, and only here.** A host name
/// is case-insensitive. `matchPattern` folds the plain form as it
/// compares, and an HMAC folds nothing, so a build that hashed the name
/// the user typed would answer two ways for one host: `Example.com`
/// against a plain file matches and against a hashed file does not.
/// `HashKnownHosts yes` is the default on several systems, so that is the
/// ordinary file. One fold here gives the two forms one answer, which is
/// what `ssh` does before it reads either.
pub fn hostName(out: []u8, peer: hostkey.Peer) ?[]const u8 {
    const written = written: {
        if (peer.port == default_port) {
            if (peer.host.len > out.len) return null;
            @memcpy(out[0..peer.host.len], peer.host);
            break :written out[0..peer.host.len];
        }
        break :written std.fmt.bufPrint(out, "[{s}]:{d}", .{ peer.host, peer.port }) catch
            return null;
    };
    for (written) |*byte| byte.* = std.ascii.toLower(byte.*);
    return written;
}

/// Whether `--hostpubsha256` names `blob`.
///
/// curl takes the base64 of `SHA256(blob)`, with or without the padding,
/// which is the same text `ssh-keygen -l` prints after `SHA256:`.
/// Measured against curl 8.21.0: both spellings matched the same key, and
/// a one byte change was `mismatch SHA256 fingerprint` and exit 60.
pub fn matchSha256Pin(text: []const u8, blob: []const u8) PinError!bool {
    if (text.len > max_pin_bytes) return error.HostPubSha256Invalid;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(blob, &digest, .{});

    var expected: [Sha256.digest_length]u8 = undefined;
    const trimmed = std.mem.trimEnd(u8, text, "=");
    const decoder = std.base64.standard_no_pad.Decoder;
    const size = decoder.calcSizeForSlice(trimmed) catch return error.HostPubSha256Invalid;
    if (size != expected.len) return error.HostPubSha256Invalid;
    decoder.decode(&expected, trimmed) catch return error.HostPubSha256Invalid;

    return equalConstantTime(&expected, &digest);
}

/// Whether `--hostpubmd5` names `blob`.
///
/// curl takes 32 hexadecimal digits, which is `MD5(blob)` and the same
/// digest `ssh-keygen -E md5` prints with colons between the bytes.
/// Measured against curl 8.21.0.
///
/// **MD5 is not a hash anybody should pin with.** It is here because curl
/// carries the flag and a script that has one would otherwise have no
/// zurl to run it against. `--hostpubsha256` is the one to use, and the
/// help text says so.
pub fn matchMd5Pin(text: []const u8, blob: []const u8) PinError!bool {
    if (text.len != Md5.digest_length * 2) return error.HostPubMd5Invalid;
    var expected: [Md5.digest_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, text) catch return error.HostPubMd5Invalid;

    var digest: [Md5.digest_length]u8 = undefined;
    Md5.hash(blob, &digest, .{});
    return equalConstantTime(&expected, &digest);
}

/// Checks a pin's spelling with no key in hand.
///
/// The command line is read long before a socket opens, and a
/// fingerprint that was mistyped should be a usage fault then rather than
/// a trust failure after the handshake.
pub fn checkPinText(md5: ?[]const u8, sha256: ?[]const u8) PinError!void {
    if (md5) |text| _ = try matchMd5Pin(text, "");
    if (sha256) |text| _ = try matchSha256Pin(text, "");
}

/// Compares two byte strings in a time that does not depend on where they
/// first differ.
///
/// **A comparison that stops at the first different byte tells a peer how
/// much of a key it guessed right.** `std.crypto.timing_safe.eql` takes an
/// array and these are slices whose length the file chooses, so the
/// accumulate-and-compare is written here.
///
/// The lengths are compared first and in the clear. A key blob's length is
/// public: it is the algorithm name and a fixed size after it.
fn equalConstantTime(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

const testing = std.testing;

/// The `ssh-keygen` output this file's tests read, so that the format is
/// pinned against a real tool and not against this build's own idea of it.
///
/// The key, the plain line, the hashed line, and both fingerprints all
/// come from one run of `ssh-keygen` and `ssh-keyscan` against a local
/// OpenSSH 10.5p1.
const sample_blob_base64 =
    "AAAAC3NzaC1lZDI1NTE5AAAAIFzu4/7O/AmZcTgP0RyO7KzAKzQZc8nlc21X4pmVDd2y";
const sample_hashed_line =
    "|1|mlvk7Efg79IpxidxGU6S8g6p2fg=|4EnogIh/isr7yPCqP7OxqNmpep4= ssh-ed25519 " ++
    sample_blob_base64;
const sample_plain_line = "[127.0.0.1]:2222 ssh-ed25519 " ++ sample_blob_base64;
const sample_sha256 = "moRo9Xfh5TVMqzcnDMFdnp9ra8zc2Ub1k1noIrv4TYs=";
const sample_md5 = "46cccd198fb5de207e06a590d431e5d7";

fn sampleBlob(out: *[max_key_bytes]u8) []const u8 {
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(sample_blob_base64) catch unreachable;
    decoder.decode(out[0..size], sample_blob_base64) catch unreachable;
    return out[0..size];
}

test "the plain form of a line ssh-keyscan wrote is read" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    var counters: Counters = .{};
    try testing.expectEqual(Outcome.match, search(
        sample_plain_line,
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));
    try testing.expectEqual(@as(u64, 1), counters.host_matches);
}

test "the hashed form ssh-keygen -H wrote is read too" {
    // A build that read only the plain form would refuse every host of a
    // user with `HashKnownHosts yes`, which is OpenSSH's own default on
    // several distributions.
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    var counters: Counters = .{};
    try testing.expectEqual(Outcome.match, search(
        sample_hashed_line,
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));

    // And the same line says nothing about another host.
    var other: Counters = .{};
    try testing.expectEqual(Outcome.unknown, search(
        sample_hashed_line,
        .{ .host = "127.0.0.2", .port = 2222 },
        blob,
        &other,
    ));
    try testing.expectEqual(@as(u64, 0), other.host_matches);
}

test "the bracket form is the name for a port that is not 22" {
    var storage: [64]u8 = undefined;
    try testing.expectEqualStrings("example.com", hostName(&storage, .{
        .host = "example.com",
        .port = 22,
    }).?);
    try testing.expectEqualStrings("[example.com]:2222", hostName(&storage, .{
        .host = "example.com",
        .port = 2222,
    }).?);

    // The same key under the wrong port is a host this file does not name.
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    var counters: Counters = .{};
    try testing.expectEqual(Outcome.unknown, search(
        sample_plain_line,
        .{ .host = "127.0.0.1", .port = 22 },
        blob,
        &counters,
    ));
}

test "a host that is present with a different key is changed and never unknown" {
    // **The serious case.** A machine that was rebuilt and a peer in the
    // middle look the same from here, and both have to stop the transfer
    // loudly. A build that reported `unknown` would send the user to
    // `ssh-keyscan`, which would write the attacker's key into the file.
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    var changed: [max_key_bytes]u8 = undefined;
    @memcpy(changed[0..blob.len], blob);
    changed[blob.len - 1] ^= 1;

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.changed, search(
        sample_plain_line,
        .{ .host = "127.0.0.1", .port = 2222 },
        changed[0..blob.len],
        &counters,
    ));
}

test "a revoked line refuses the key it names and nothing else" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const text = "@revoked " ++ sample_plain_line;

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.revoked, search(
        text,
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));

    // A different key on the same revoked line says nothing at all, so it
    // does not become a change.
    var other: [max_key_bytes]u8 = undefined;
    @memcpy(other[0..blob.len], blob);
    other[0] ^= 0x40;
    var second: Counters = .{};
    try testing.expectEqual(Outcome.unknown, search(
        text,
        .{ .host = "127.0.0.1", .port = 2222 },
        other[0..blob.len],
        &second,
    ));
}

test "a revocation later in the file beats a match earlier in it" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const text = sample_plain_line ++ "\n@revoked " ++ sample_plain_line ++ "\n";

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.revoked, search(
        text,
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));
}

test "a match anywhere in the file beats a line that carries another key" {
    // **This is what OpenSSH does**, and a file that names one host twice
    // is an ordinary file: a key rotation writes two lines, one name in
    // front of two machines writes two lines, and a specific line beside a
    // wildcard line is two lines. `check_key_in_hostkeys` reports the key
    // as known when any line carries it. A build that reported a change
    // here would print the loudest warning it has on a good file, and the
    // only escape it offers is `-k`, which turns the check off.
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const other = "[127.0.0.1]:2222 ssh-ed25519 " ++
        "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // The order of the two lines does not change the answer.
    for ([_][]const u8{
        sample_plain_line ++ "\n" ++ other ++ "\n",
        other ++ "\n" ++ sample_plain_line ++ "\n",
    }) |text| {
        var counters: Counters = .{};
        try testing.expectEqual(Outcome.match, search(
            text,
            .{ .host = "127.0.0.1", .port = 2222 },
            blob,
            &counters,
        ));
    }

    // **A key that no line carries is still a change.** The rank moved,
    // and nothing about the serious case moved with it.
    var changed: [max_key_bytes]u8 = undefined;
    @memcpy(changed[0..blob.len], blob);
    changed[blob.len - 1] ^= 1;
    var counters: Counters = .{};
    try testing.expectEqual(Outcome.changed, search(
        sample_plain_line ++ "\n" ++ other ++ "\n",
        .{ .host = "127.0.0.1", .port = 2222 },
        changed[0..blob.len],
        &counters,
    ));
}

test "a revocation beats a match that came before it in the file" {
    // The one answer that no later line softens, and the reordering of
    // `stronger` left it where it was.
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.revoked, search(
        sample_plain_line ++ "\n@revoked " ++ sample_plain_line ++ "\n",
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));
}

test "a host on record under another key type is not an unknown host" {
    // **The wrong message here writes an attacker's key into the file.** A
    // user whose record holds an ECDSA key and who is told the host is
    // unknown runs `ssh-keyscan`, and `ssh-keyscan` appends whatever key
    // the peer in front of them presents. The host is on record, and the
    // answer has to say so.
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const ecdsa_line = "[127.0.0.1]:2222 ecdsa-sha2-nistp256 " ++
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY=";

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.algorithm_unknown, search(
        ecdsa_line,
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));
    try testing.expectEqual(@as(u64, 1), counters.other_algorithm);

    var checker: Checker = .{ .policy = .{ .known_hosts = ecdsa_line } };
    const key = try hostkey.parse(blob, .ssh_ed25519);
    try testing.expectError(
        error.HostKeyAlgorithmUnknown,
        checker.check(.{ .host = "127.0.0.1", .port = 2222 }, key, blob),
    );
    try testing.expectEqual(Outcome.algorithm_unknown, checker.outcome.?);

    // And an ed25519 line beside it settles the question, whichever way
    // round the two lines are.
    var second: Counters = .{};
    try testing.expectEqual(Outcome.match, search(
        ecdsa_line ++ "\n" ++ sample_plain_line ++ "\n",
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &second,
    ));
}

test "a hashed line matches a host name whatever case the url wrote it in" {
    // **The plain form folds case and an HMAC folds nothing**, so the fold
    // has to happen before either one reads the name. A file written with
    // `HashKnownHosts yes` is the ordinary file on several systems, and a
    // user who typed one capital letter would be told the host is not on
    // record and sent to `ssh-keyscan`.
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);

    var lower: [64]u8 = undefined;
    const lower_name = hostName(&lower, .{ .host = "Example.COM", .port = 22 }).?;
    try testing.expectEqualStrings("example.com", lower_name);

    var bracket: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "[example.com]:2222",
        hostName(&bracket, .{ .host = "Example.COM", .port = 2222 }).?,
    );

    // The same key under the plain form and under the hashed form, and
    // both are found from the name as the user typed it.
    var plain_storage: [512]u8 = undefined;
    const encoder = std.base64.standard.Encoder;
    var key_text: [512]u8 = undefined;
    const encoded = encoder.encode(&key_text, blob);
    const plain_line = try std.fmt.bufPrint(
        &plain_storage,
        "example.com ssh-ed25519 {s}",
        .{encoded},
    );

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.match, search(
        plain_line,
        .{ .host = "EXAMPLE.com", .port = 22 },
        blob,
        &counters,
    ));

    var hashed_storage: [512]u8 = undefined;
    const hashed_line = try hashedLine(&hashed_storage, "example.com", encoded);
    var second: Counters = .{};
    try testing.expectEqual(Outcome.match, search(
        hashed_line,
        .{ .host = "EXAMPLE.com", .port = 22 },
        blob,
        &second,
    ));
}

test "an empty host name never matches a wildcard line" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const encoder = std.base64.standard.Encoder;
    var key_text: [512]u8 = undefined;
    const encoded = encoder.encode(&key_text, blob);
    var line_storage: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_storage, "* ssh-ed25519 {s}", .{encoded});

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.unknown, search(
        line,
        .{ .host = "", .port = 22 },
        blob,
        &counters,
    ));
}

/// Writes a hashed `known_hosts` line for `name`, the way
/// `ssh-keygen -H` does.
fn hashedLine(out: []u8, name: []const u8, key_text: []const u8) ![]u8 {
    const salt: [Hmac.mac_length]u8 = @splat(0x2c);
    var digest: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&digest, name, &salt);

    const encoder = std.base64.standard.Encoder;
    var salt_text: [64]u8 = undefined;
    var digest_text: [64]u8 = undefined;
    return std.fmt.bufPrint(out, "|1|{s}|{s} ssh-ed25519 {s}", .{
        encoder.encode(&salt_text, &salt),
        encoder.encode(&digest_text, &digest),
        key_text,
    });
}

test "a cert-authority line is skipped and counted, and never read as a key" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const text = "@cert-authority " ++ sample_plain_line;

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.unknown, search(
        text,
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));
    // This build verifies no certificate, so trusting the signing key as
    // a host key would trust every host that authority ever signed for.
    try testing.expectEqual(@as(u64, 1), counters.certificate_authority_lines);
    try testing.expectEqual(@as(u64, 0), counters.host_matches);
}

test "a comment, a blank line, and a line with too few fields are skipped and counted" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const text =
        "# a comment\n" ++
        "\n" ++
        "   \n" ++
        "onlyonefield\n" ++
        "[127.0.0.1]:2222 ssh-ed25519 not-base64!!\n" ++
        sample_plain_line ++ "\n";

    var counters: Counters = .{};
    try testing.expectEqual(Outcome.match, search(
        text,
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));
    // One bad line must not lock a user out of every host in the file,
    // and the count is what makes the skip visible.
    try testing.expect(counters.malformed >= 2);
    // The comment, the blank line, the line of spaces, and the empty
    // line after the last newline.
    try testing.expectEqual(@as(u64, 4), counters.comments);
}

test "a key algorithm this build cannot verify names the host and not the key" {
    const text = "example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQ==";
    var counters: Counters = .{};
    try testing.expectEqual(Outcome.algorithm_unknown, search(
        text,
        .{ .host = "example.com", .port = 22 },
        "whatever",
        &counters,
    ));
    try testing.expectEqual(@as(u64, 1), counters.other_algorithm);
}

test "a pattern takes a wildcard and a negation" {
    try testing.expect(matchPattern("example.com", "example.com"));
    try testing.expect(matchPattern("EXAMPLE.com", "example.COM"));
    try testing.expect(matchPattern("*.example.com", "a.example.com"));
    try testing.expect(matchPattern("*.example.com", "a.b.example.com"));
    try testing.expect(!matchPattern("*.example.com", "example.com"));
    try testing.expect(matchPattern("host?", "host1"));
    try testing.expect(!matchPattern("host?", "host12"));
    try testing.expect(matchPattern("*", "anything"));
    try testing.expect(matchPattern("a*b*c", "axxbyyc"));
    try testing.expect(!matchPattern("a*b*c", "axxbyy"));

    // A pattern of nothing but stars is bounded, so a line cannot buy
    // itself unbounded work.
    const many = "*" ** (max_wildcards + 1);
    try testing.expect(!matchPattern(many, "anything"));
}

test "a negation takes the host out of the line" {
    var counters: Counters = .{};
    try testing.expect(matchHostField("*.example.com", "a.example.com", &counters));
    try testing.expect(!matchHostField("*.example.com,!bad.example.com", "bad.example.com", &counters));
    try testing.expect(matchHostField("*.example.com,!bad.example.com", "good.example.com", &counters));
}

test "the sha256 pin matches the text ssh-keygen prints, padded or not" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);

    try testing.expect(try matchSha256Pin(sample_sha256, blob));
    try testing.expect(try matchSha256Pin(sample_sha256[0 .. sample_sha256.len - 1], blob));

    var wrong: [64]u8 = undefined;
    @memcpy(wrong[0..sample_sha256.len], sample_sha256);
    wrong[0] = 'A';
    try testing.expect(!try matchSha256Pin(wrong[0..sample_sha256.len], blob));

    try testing.expectError(error.HostPubSha256Invalid, matchSha256Pin("not base64 at all", blob));
    try testing.expectError(error.HostPubSha256Invalid, matchSha256Pin("AAAA", blob));
}

test "the md5 pin matches the digest ssh-keygen -E md5 prints with no colons" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);

    try testing.expect(try matchMd5Pin(sample_md5, blob));
    // The colons `ssh-keygen` prints are not part of what curl takes, and
    // a build that accepted them would take a string curl refuses.
    try testing.expectError(
        error.HostPubMd5Invalid,
        matchMd5Pin("46:cc:cd:19:8f:b5:de:20:7e:06:a5:90:d4:31:e5:d7", blob),
    );
    try testing.expectError(error.HostPubMd5Invalid, matchMd5Pin("46cc", blob));
    try testing.expect(!try matchMd5Pin("00000000000000000000000000000000", blob));
}

test "a pin is checked for its spelling before a socket opens" {
    try checkPinText(null, null);
    try checkPinText(sample_md5, null);
    try checkPinText(null, sample_sha256);
    try testing.expectError(error.HostPubMd5Invalid, checkPinText("nope", null));
    try testing.expectError(error.HostPubSha256Invalid, checkPinText(null, "nope!"));
}

test "a checker refuses an unknown host and never accepts it" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const key = try hostkey.parse(blob, .ssh_ed25519);

    // No file at all.
    var empty: Checker = .{ .policy = .{} };
    try testing.expectError(error.HostKeyUnknown, empty.check(
        .{ .host = "127.0.0.1", .port = 2222 },
        key,
        blob,
    ));
    try testing.expectEqual(Outcome.unknown, empty.outcome.?);

    // A file that names another host.
    var elsewhere: Checker = .{ .policy = .{ .known_hosts = "other.example ssh-ed25519 " ++ sample_blob_base64 } };
    try testing.expectError(error.HostKeyUnknown, elsewhere.check(
        .{ .host = "127.0.0.1", .port = 2222 },
        key,
        blob,
    ));

    // A file that names it, with this key.
    var known: Checker = .{ .policy = .{ .known_hosts = sample_plain_line } };
    try known.check(.{ .host = "127.0.0.1", .port = 2222 }, key, blob);
    try testing.expectEqual(Outcome.match, known.outcome.?);
}

test "a named file that could not be read is a refusal and not a missing record" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const key = try hostkey.parse(blob, .ssh_ed25519);

    var checker: Checker = .{ .policy = .{ .known_hosts_unreadable = true } };
    // The two have different fixes: one is `ssh-keyscan`, the other is a
    // path or a permission. A build that folded them together would send
    // the user to the wrong one.
    try testing.expectError(error.HostKeyCheckFailed, checker.check(
        .{ .host = "127.0.0.1", .port = 2222 },
        key,
        blob,
    ));
}

test "a pin answers on its own and the file is never read" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const key = try hostkey.parse(blob, .ssh_ed25519);

    // A pin that matches, with a file that names nothing.
    var pinned: Checker = .{ .policy = .{ .sha256_pin = sample_sha256 } };
    try pinned.check(.{ .host = "127.0.0.1", .port = 2222 }, key, blob);
    try testing.expect(pinned.pinned);
    try testing.expectEqual(@as(u64, 0), pinned.counters.lines);

    // A pin that does not match, with a file that says the key is right.
    var conflicting: Checker = .{ .policy = .{
        .sha256_pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .known_hosts = sample_plain_line,
    } };
    try testing.expectError(error.HostKeyChanged, conflicting.check(
        .{ .host = "127.0.0.1", .port = 2222 },
        key,
        blob,
    ));
}

test "insecure skips the file and never the pin the user also named" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);
    const key = try hostkey.parse(blob, .ssh_ed25519);

    var skipped: Checker = .{ .policy = .{ .insecure = true } };
    try skipped.check(.{ .host = "127.0.0.1", .port = 2222 }, key, blob);

    // A user who wrote a pin asked for one check. `-k` does not take it
    // away, because the check they named is the one they meant.
    var both: Checker = .{ .policy = .{
        .insecure = true,
        .sha256_pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    } };
    try testing.expectError(error.HostKeyChanged, both.check(
        .{ .host = "127.0.0.1", .port = 2222 },
        key,
        blob,
    ));
}

test "a line longer than the bound is skipped and counted" {
    var blob_storage: [max_key_bytes]u8 = undefined;
    const blob = sampleBlob(&blob_storage);

    var long: [max_line_bytes + 16]u8 = @splat('x');
    var counters: Counters = .{};
    try testing.expectEqual(Outcome.unknown, search(
        &long,
        .{ .host = "127.0.0.1", .port = 2222 },
        blob,
        &counters,
    ));
    try testing.expectEqual(@as(u64, 1), counters.over_length);
}

/// A home directory with a `.ssh` in it, and nothing else.
///
/// Every test that reads a file reads a real path, because this part of
/// the module is about what the operating system answers.
/// `std.testing.tmpDir` gives a directory the test runner removes
/// afterwards, so **no test here reads the real `~/.ssh`**.
const Home = struct {
    tmp: testing.TmpDir,
    root_storage: [std.Io.Dir.max_path_bytes]u8,
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

    fn put(h: *Home, text: []const u8) !void {
        var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(
            &path_storage,
            "{s}/{s}",
            .{ default_directory, default_name },
        );
        try h.tmp.dir.writeFile(testing.io, .{ .sub_path = path, .data = text });
    }
};

test "the default file is read from under the home directory the caller gave" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();
    try home.put(sample_plain_line ++ "\n");

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var opened = try read(
        testing.allocator,
        testing.io,
        .{ .home = home.root() },
        &path_storage,
    );
    defer opened.close(testing.allocator);
    try testing.expectEqualStrings(sample_plain_line ++ "\n", opened.text);
    try testing.expect(std.mem.endsWith(u8, opened.path, "/.ssh/known_hosts"));
}

test "a home with no file is a refusal that names the first run and not a permission" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    // The two are kept apart because the fixes differ: this one is
    // `ssh-keyscan`, and `Unreadable` is a path or a permission.
    try testing.expectError(error.KnownHostsNotFound, read(
        testing.allocator,
        testing.io,
        .{ .home = home.root() },
        &path_storage,
    ));
}

test "a named path that does not open never falls back to the default file" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();
    try home.put(sample_plain_line ++ "\n");

    var named_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const missing = try std.fmt.bufPrint(
        &named_storage,
        "{s}/does-not-exist",
        .{home.root()},
    );

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    // A user who wrote `--knownhosts` and mistyped it must not silently
    // get the file they did not name.
    try testing.expectError(error.KnownHostsUnreadable, read(
        testing.allocator,
        testing.io,
        .{ .path = missing, .home = home.root() },
        &path_storage,
    ));
}

test "a file longer than the bound is a named refusal and not a cut" {
    var home: Home = undefined;
    try home.init();
    defer home.deinit();

    const long = try testing.allocator.alloc(u8, max_file_bytes + 2);
    defer testing.allocator.free(long);
    @memset(long, '\n');
    try home.put(long);

    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    // A cut `known_hosts` is a file whose last entry may be half a key,
    // and half a key compares against nothing.
    try testing.expectError(error.KnownHostsTooLong, read(
        testing.allocator,
        testing.io,
        .{ .home = home.root() },
        &path_storage,
    ));
}

test "no path and no home is its own refusal" {
    var path_storage: [std.Io.Dir.max_path_bytes]u8 = undefined;
    try testing.expectError(error.KnownHostsHomeUnknown, read(
        testing.allocator,
        testing.io,
        .{},
        &path_storage,
    ));
}

test "a home that ends in a separator gets no second one" {
    var out: [std.Io.Dir.max_path_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "/home/u/.ssh/known_hosts",
        try buildDefaultPath(&out, "/home/u"),
    );
    try testing.expectEqualStrings(
        "/home/u/.ssh/known_hosts",
        try buildDefaultPath(&out, "/home/u/"),
    );
    try testing.expectEqualStrings("/.ssh/known_hosts", try buildDefaultPath(&out, "/"));

    var tiny: [4]u8 = undefined;
    try testing.expectError(
        error.KnownHostsPathTooLong,
        buildDefaultPath(&tiny, "/home/u"),
    );
}
