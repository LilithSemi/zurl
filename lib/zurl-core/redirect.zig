//! Which protocols a transfer may speak, and which a redirect may move it
//! to.
//!
//! A redirect target is a url the **server** chose. The url the user typed
//! says which protocols they meant to speak; a `location:` header must not
//! widen that set. Without this rule any http server can answer
//! `location: file:///etc/passwd`, and a client that follows it reads a
//! local file and, under `-o`, writes the file back where the user can be
//! made to send it on.
//!
//! curl states both halves of that rule as flags: `--proto` names the
//! protocols a url may name, and `--proto-redir` names the protocols a
//! redirect may name. This file owns both. `redirect_default` is
//! `--proto-redir`'s own default, `transfer_default` is `--proto`'s, and
//! `Set.parse` reads the list syntax both flags share.
//!
//! **This lives in `zurl-core` on purpose.** Every protocol package
//! imports this package and none imports another, so a protocol that
//! grows a redirect chain of its own reads this policy rather than writing
//! a second copy of it. A second copy is how one protocol keeps the rule
//! and the next one loses it.

const std = @import("std");

/// A protocol name a `--proto` or `--proto-redir` list may hold.
///
/// This is the **vocabulary**, not the build. A name here is one zurl can
/// read in a list and answer about; it is not a promise that this build
/// speaks it. `ftp` and `ftps` are here because `redirect_default` names
/// them, and because curl accepts the name of a protocol whichever way its
/// own build was configured. A transfer that reaches one still ends with
/// `error.UnsupportedProtocol`, from the engine that cannot open it.
///
/// **This is curl's whole list, and not the list zurl speaks today.** An
/// earlier version held five names, and four protocols were then added to
/// the build without touching this one. `--proto -all,dict` therefore
/// emptied the set and reported a usage fault where curl 8.21.0 runs the
/// transfer, and `--proto-redir +gopher` changed nothing at all. A flag
/// that is silently ignored is worse than one that is refused. The whole
/// vocabulary is here now, so the next protocol the build gains needs no
/// edit here at all.
///
/// curl reads a protocol name without regard to case, so `fromName` does
/// too: `--proto -ALL,HTTP` and `--proto -all,http` are one list.
pub const Protocol = enum {
    http,
    https,
    file,
    ftp,
    ftps,
    // The four this build speaks and the five-name list did not name.
    dict,
    gopher,
    gophers,
    tftp,
    // The mail protocols, the two WebSocket schemes, and telnet. This
    // build speaks all nine.
    imap,
    imaps,
    pop3,
    pop3s,
    smtp,
    smtps,
    telnet,
    ws,
    wss,
    // The two SSH schemes, the two directory schemes, the two message
    // broker schemes, and the streaming control scheme. This build speaks
    // all seven.
    ldap,
    ldaps,
    mqtt,
    mqtts,
    rtsp,
    scp,
    sftp,
    // The rest of curl's own list. zurl speaks none of these, and a url
    // naming one still ends with `error.UnsupportedProtocol`. They are
    // here so a curl command line that names one parses, and so a user can
    // write an allowlist that mentions them.
    //
    // `smb` and `smbs` are here and nowhere else on purpose. curl speaks
    // SMBv1 alone, which is obsolete and disabled by default on every
    // current server, and this build carries no SMB at all. See
    // `.superpowers/sdd/p3-last-protocols-report.md`.
    rtmp,
    rtmps,
    smb,
    smbs,

    /// The lower-case name of `p`, as a list writes it.
    pub fn name(p: Protocol) []const u8 {
        return @tagName(p);
    }

    /// Whether a transfer over `p` hides its bytes from a network
    /// observer.
    ///
    /// This is what a user buys when they type `https` and not `http`. A
    /// credential sent over a confidential protocol reaches the peer and
    /// nobody else; the same credential sent over any other protocol on
    /// this list is readable by every machine on the path.
    ///
    /// `file` counts, because a `file` transfer crosses no network at all.
    /// `scp` and `sftp` count, because SSH encrypts the channel the same
    /// way TLS does. Every other member is the plain half of a pair, and
    /// the plain half never counts, `ws` included: `ws` is HTTP with an
    /// upgrade and it is as readable as `http`.
    ///
    /// **A protocol nobody named is not confidential.** `Set.unnamed`
    /// covers a scheme a program registered, and this file cannot know
    /// what such a scheme speaks. Answering false is the safe direction:
    /// the caller then treats the hop as one that may be read, which costs
    /// a credential that would have travelled and never spends one that
    /// would not.
    pub fn isConfidential(p: Protocol) bool {
        return switch (p) {
            .https,
            .ftps,
            .gophers,
            .imaps,
            .pop3s,
            .smtps,
            .wss,
            .ldaps,
            .mqtts,
            .rtmps,
            .smbs,
            .scp,
            .sftp,
            .file,
            => true,
            .http,
            .ftp,
            .dict,
            .gopher,
            .tftp,
            .imap,
            .pop3,
            .smtp,
            .telnet,
            .ws,
            .ldap,
            .mqtt,
            .rtsp,
            .rtmp,
            .smb,
            => false,
        };
    }

    /// The protocol `text` names, or null when no name matches.
    ///
    /// A name nobody knows is not a fault here. curl 8.21.0 skips such an
    /// entry and changes nothing: `curl --proto nosuchproto http://...`
    /// runs the transfer. `Set.parse` keeps that reading, and reports only
    /// the case the user can act on, which is a list that leaves nothing
    /// enabled.
    pub fn fromName(text: []const u8) ?Protocol {
        inline for (comptime std.enums.values(Protocol)) |p| {
            if (std.ascii.eqlIgnoreCase(@tagName(p), text)) return p;
        }
        return null;
    }
};

/// A set of protocols. One bit for each name in `Protocol`, plus one bit
/// for every scheme that has no name here, so a set costs a few bytes and
/// no allocation and a copy of one cannot alias another.
///
/// **`unnamed` is the field that keeps this honest.** `zurl.Client` lets a
/// program register a protocol of its own, under any scheme it likes, and
/// `Protocol` has no name for such a scheme. curl's `--proto` default is
/// every protocol its own build speaks, so zurl's default must be every
/// protocol *this* program speaks, registered ones included. A set of
/// named bits alone could not say that, and the default would then refuse
/// exactly the protocols a program added on purpose.
pub const Set = struct {
    bits: Bits,
    /// Whether a scheme with no name in `Protocol` is in the set.
    ///
    /// `all` sets it, `-all` and `=` clear it, and `+name` and `-name`
    /// leave it alone, because neither names a scheme this field covers.
    /// A policy written as an allowlist, such as `redirect_default`,
    /// leaves it false: a name nobody wrote down is refused.
    unnamed: bool,

    const Bits = std.EnumSet(Protocol);

    /// The set holding nothing. A transfer with this set refuses every
    /// url, which is why `parse` reports it rather than returning it.
    pub const none: Set = .{ .bits = .initEmpty(), .unnamed = false };

    /// Every protocol, named here or not. This is what `all` means in a
    /// list.
    pub const all: Set = .{ .bits = .initFull(), .unnamed = true };

    /// The set holding exactly `members`, and no scheme outside
    /// `Protocol`.
    pub fn init(members: []const Protocol) Set {
        var s: Set = .none;
        for (members) |p| s.bits.insert(p);
        return s;
    }

    /// Whether `p` is in the set.
    pub fn has(s: Set, p: Protocol) bool {
        return s.bits.contains(p);
    }

    /// Whether the set holds the protocol `scheme` names.
    ///
    /// A scheme `Protocol` has no name for is in the set only when
    /// `unnamed` is set. So `--proto -all,http` refuses a registered
    /// protocol, which is what the user asked for, and the default set
    /// permits it, which is what curl does for a protocol its own build
    /// carries.
    pub fn hasScheme(s: Set, scheme: []const u8) bool {
        const p = Protocol.fromName(scheme) orelse return s.unnamed;
        return s.has(p);
    }

    /// Whether the set holds nothing at all.
    pub fn isEmpty(s: Set) bool {
        return s.bits.count() == 0 and !s.unnamed;
    }

    /// The protocols both sets hold.
    ///
    /// **This is how the two flags meet.** A redirect target has to pass
    /// `--proto-redir` *and* `--proto`; neither list alone is the answer.
    /// Measured against curl 8.21.0, with a server answering
    /// `location: file://.../secret.txt`:
    ///
    /// ```
    /// --proto-redir +file                        reads the file
    /// --proto -all,http      --proto-redir +file refused, "(in redirect)"
    /// --proto -all,http,file --proto-redir +file reads the file
    /// --proto -file          --proto-redir +file refused
    /// --proto -all,http,file                     refused
    /// ```
    ///
    /// Only an intersection explains every row. Without it `--proto`
    /// narrows the url the user typed and nothing else, so a server could
    /// still move a transfer to a protocol the user turned off, which is
    /// the whole shape `--proto-redir` exists to stop.
    ///
    /// A scheme neither set names is in the answer only when both sets
    /// carry `unnamed`, which is the same rule each named bit follows.
    pub fn intersect(a: Set, b: Set) Set {
        return .{
            .bits = a.bits.intersectWith(b.bits),
            .unnamed = a.unnamed and b.unnamed,
        };
    }

    /// How many bytes of list text `parse` reads.
    ///
    /// A list names at most a few protocols, and each entry costs a prefix
    /// byte, a name, and a comma. This bound is far past any list a person
    /// writes, and it stops a command line or a config file from handing
    /// `parse` an argument of unbounded size. curl sets no such bound.
    pub const max_list_bytes: usize = 4096;

    /// How many entries `parse` reads from one list.
    ///
    /// A useful list holds at most one entry for each `Protocol`, plus the
    /// `all` that clears or fills the set, so this bound is far past any
    /// list a person writes. It exists because the argument is untrusted
    /// input, not because a real list ever approaches it.
    pub const max_entries: usize = 256;

    pub const ParseError = error{
        /// The list was longer than `max_list_bytes`.
        ProtocolListTooLong,
        /// The list held more than `max_entries` entries.
        ProtocolListTooManyEntries,
        /// The list left no protocol enabled, so every url would be
        /// refused. curl 8.21.0 answers the same list with exit 2 and
        /// `option --proto: is badly used here`.
        ProtocolListEmpty,
    };

    /// Reads one `--proto` or `--proto-redir` list and returns the set it
    /// describes.
    ///
    /// `base` is the set the list starts from: `transfer_default` for
    /// `--proto` and `redirect_default` for `--proto-redir`. Measured
    /// against curl 8.21.0, which starts each flag from its own default
    /// and not from a common one: with a server answering
    /// `location: gopher://...`, `curl --proto-redir -http` still reports
    /// `Protocol "gopher" is disabled (in redirect)`, so removing one name
    /// did not first widen the set to everything.
    ///
    /// The syntax, measured entry by entry against curl 8.21.0:
    ///
    /// - The list is split on `,`. An empty entry is skipped.
    /// - An entry may start with `+`, `-`, or `=`. No prefix reads as `+`.
    /// - `+name` adds, `-name` removes, and `=name` empties the set and
    ///   then adds. A later entry still applies, so `=http,https` holds
    ///   both.
    /// - `all` names every protocol, so `-all,http` is "only http".
    /// - A name is read without regard to case.
    /// - A name is **not** trimmed. curl reads ` http` as an unknown name,
    ///   so `--proto -all, http` leaves nothing enabled and fails.
    /// - A name nobody knows changes nothing and is not a fault.
    ///
    /// The one fault a list can raise, beyond the two bounds above, is a
    /// set left empty. That is the state a user can act on, and it is the
    /// one curl reports.
    pub fn parse(text: []const u8, base: Set) ParseError!Set {
        if (text.len > max_list_bytes) return error.ProtocolListTooLong;

        var out = base;
        var entries: usize = 0;
        var rest = text;
        while (true) {
            const comma = std.mem.indexOfScalar(u8, rest, ',');
            const entry = if (comma) |at| rest[0..at] else rest;
            entries += 1;
            if (entries > max_entries) return error.ProtocolListTooManyEntries;
            applyEntry(&out, entry);
            if (comma) |at| rest = rest[at + 1 ..] else break;
        }

        if (out.isEmpty()) return error.ProtocolListEmpty;
        return out;
    }

    /// Applies one entry of a list to `out`. An empty entry and an unknown
    /// name both change nothing, which is what curl 8.21.0 does with each.
    fn applyEntry(out: *Set, entry: []const u8) void {
        if (entry.len == 0) return;

        const Op = enum { add, remove, only };
        const op: Op, const name: []const u8 = switch (entry[0]) {
            '+' => .{ .add, entry[1..] },
            '-' => .{ .remove, entry[1..] },
            '=' => .{ .only, entry[1..] },
            else => .{ .add, entry },
        };

        // `=` empties the set before it adds, and it does so even when the
        // name that follows is one nobody knows. curl 8.21.0 answers
        // `--proto =nosuchproto` with exit 2, which it can only reach by
        // clearing first and finding nothing left.
        if (op == .only) out.* = .none;

        const named: Set = if (std.ascii.eqlIgnoreCase(name, "all"))
            .all
        else if (Protocol.fromName(name)) |p|
            .init(&.{p})
        else
            return;

        switch (op) {
            .add, .only => {
                out.bits.setUnion(named.bits);
                // Only `all` covers a scheme with no name here, so only
                // `all` can turn this back on.
                out.unnamed = out.unnamed or named.unnamed;
            },
            .remove => {
                out.bits = out.bits.differenceWith(named.bits);
                if (named.unnamed) out.unnamed = false;
            },
        }
    }
};

/// The protocols a url may name, with no `--proto`.
///
/// Every name zurl knows. curl starts `--proto` from every protocol its
/// own build supports, and this is zurl's answer to that: a url naming a
/// protocol this build cannot open still ends with
/// `error.UnsupportedProtocol`, so the default turns nothing off that the
/// build would have done.
pub const transfer_default: Set = .all;

/// The protocols a redirect may name, with no `--proto-redir`.
///
/// This is curl's `--proto-redir` default, name for name. `file` is absent
/// and must stay absent: a server that can move a transfer to `file` can
/// read any file the user can read.
///
/// `ftp` and `ftps` are here because curl allows them and because the list
/// must describe the policy and not the build. zurl speaks neither yet, so
/// a redirect to one gets `error.UnsupportedProtocol` from the engine that
/// cannot open it, which is the same answer with the same exit code.
pub const redirect_default: Set = .init(&.{ .http, .https, .ftp, .ftps });

/// Whether a redirect may move a transfer to `scheme`, under the default
/// policy.
///
/// This is `redirect_default` asked about one scheme. A caller that honours
/// `--proto-redir` carries its own `Set` and asks that instead; this
/// function is the answer for a caller that has no such set.
///
/// Compared without regard to case, per RFC 3986: a server writes
/// `location: FILE:///etc/passwd` as readily as the lower-case spelling,
/// and both name one scheme.
pub fn allowed(scheme: []const u8) bool {
    return redirect_default.hasScheme(scheme);
}

/// Whether a hop from `from` to `to` takes the transfer off a confidential
/// protocol and onto one a network observer reads.
///
/// **What this is for.** `--location-trusted` tells a client to carry
/// `Authorization` and `Cookie` across a redirect. The flag is about the
/// **host**: the user says they trust whatever host the chain reaches with
/// the credential they typed. It says nothing about the **transport**, and
/// a user who types `https://` has asked for one. A server that answers
/// `location: http://` on its own origin therefore turns a credential the
/// user scoped to a private channel into a credential on the wire in the
/// clear, and every machine between the two reads it once.
///
/// **curl does not stop this, measured.** curl 8.21.0 on loopback, with an
/// https listener answering `302` and `location: http://127.0.0.1:.../next`
/// and a plain listener recording what arrived:
///
/// ```
/// curl --cacert cert.pem -L --location-trusted -u bob:s3cret \
///     https://127.0.0.1:18741/start
///
/// hop 1, over TLS:  Authorization: Basic Ym9iOnMzY3JldA==
/// hop 2, cleartext: Authorization: Basic Ym9iOnMzY3JldA==
/// ```
///
/// The credential went out on the cleartext hop. So this rule is stricter
/// than curl, on purpose, and here is the argument for that.
///
/// A flag is a statement of trust, and trust is not one quantity. The user
/// who types `--location-trusted` is answering "may this credential reach
/// another host", and there is no spelling in curl or in zurl that answers
/// "may this credential leave TLS". A single flag that silently answers
/// both questions is a flag that cannot say what its user meant. The cost
/// of being stricter is a transfer that needs the user to type `http://`
/// themselves, which is one edit and which makes the choice visible. The
/// cost of curl's reading is a password on the wire that the user believed
/// they had put inside TLS, and no message tells them it happened. zurl
/// already drops secrets on **every** redirect where curl drops them only
/// on an origin change, so this is the same direction the rest of this
/// area already takes and not a new one.
///
/// **A scheme nobody named is not confidential**, on both sides, so the
/// answer is false when `from` is unknown and true when `to` is unknown
/// and `from` is confidential. See `Protocol.isConfidential` for why that
/// is the safe direction.
///
/// Compared without regard to case, per RFC 3986, because a server writes
/// `location: HTTP://...` as readily as the lower-case spelling.
/// **This engine does not gate on it, and that is deliberate.** Measured
/// against curl 8.21.0 over two loopback servers, one with TLS: under
/// `--location-trusted` curl carries `Authorization`, a `-b` cookie and a
/// `-H` header from an `https` hop to a plain `http` one, and without the
/// flag it drops all three. zurl answers the same way, because
/// `--location-trusted` is a choice the user wrote, and doing something
/// narrower than what was asked is worse than doing what was asked.
///
/// Measured for the ordinary case as well, and both tools agree: with no
/// flag, neither sends a credential to a second port on the same host.
///
/// So this is a predicate a caller of `zurl-core` may use to write its own
/// policy, and not a rule this build applies. A build that wants to refuse
/// the downgrade asks this and refuses. See `zurl_http.h1` at the
/// `trusted_secrets` branch, which records the same decision.
pub fn isDowngrade(from: []const u8, to: []const u8) bool {
    const source = Protocol.fromName(from) orelse return false;
    if (!source.isConfidential()) return false;
    const target = Protocol.fromName(to) orelse return true;
    return !target.isConfidential();
}

const testing = std.testing;

test "the default set is curl's own --proto-redir default" {
    try testing.expect(allowed("http"));
    try testing.expect(allowed("https"));
    try testing.expect(allowed("ftp"));
    try testing.expect(allowed("ftps"));
}

test "a redirect may never name file" {
    // The rule this file exists for. A server that could reach `file`
    // could read any file the user can read.
    try testing.expect(!allowed("file"));
    try testing.expect(!allowed("FILE"));
    try testing.expect(!allowed("File"));
}

test "a scheme nobody named is refused, not allowed by default" {
    // An allowlist and never a blocklist: the next protocol package to
    // arrive is refused until somebody writes it down here.
    try testing.expect(!allowed("gopher"));
    try testing.expect(!allowed("data"));
    try testing.expect(!allowed(""));
}

test "the case rule holds for every allowed scheme too" {
    try testing.expect(allowed("HTTPS"));
    try testing.expect(allowed("Http"));
}

test "a name reads the same whatever its case" {
    try testing.expectEqual(Protocol.http, Protocol.fromName("HTTP").?);
    try testing.expectEqual(Protocol.ftps, Protocol.fromName("FtPs").?);
    try testing.expectEqual(Protocol.gophers, Protocol.fromName("GOPHERS").?);
    try testing.expectEqual(@as(?Protocol, null), Protocol.fromName(""));
    try testing.expectEqual(@as(?Protocol, null), Protocol.fromName("all"));
    // `all` and `+` are list syntax, not names, and no name matches them.
    try testing.expectEqual(@as(?Protocol, null), Protocol.fromName("nosuchproto"));
}

test "every protocol this build speaks has a name a list can hold" {
    // The defect this list carried. Four protocols were registered in the
    // build and none of them was named here, so `--proto -all,dict` left
    // the set empty and reported a usage fault where curl runs the
    // transfer, and `--proto-redir +gopher` changed nothing at all.
    //
    // A scheme a program registers of its own is still covered by
    // `Set.unnamed`. This list is what a user can write down by name.
    for ([_][]const u8{
        "http",  "https",  "file",   "ftp",
        "ftps",  "dict",   "gopher", "gophers",
        "tftp",  "pop3",   "pop3s",  "imap",
        "imaps", "smtp",   "smtps",  "ws",
        "wss",   "telnet",
    }) |name| {
        try testing.expect(Protocol.fromName(name) != null);
    }

    // The rest of curl's vocabulary parses as well, so a curl command line
    // that names one is not a usage fault here.
    for ([_][]const u8{
        "ldap", "ldaps", "mqtt", "mqtts", "rtsp",
        "scp",  "sftp",  "rtmp", "rtmps", "smb",
        "smbs",
    }) |name| {
        try testing.expect(Protocol.fromName(name) != null);
    }
}

test "a list that names a protocol this build speaks leaves the set usable" {
    // Measured against curl 8.21.0:
    //   curl --proto -all,dict dict://127.0.0.1:1/d:x  -> exit 7, connects
    //   zurl --proto -all,dict dict://127.0.0.1:1/d:x  -> exit 2, before
    // `-all` emptied the set, `dict` was an unknown name and added
    // nothing, and `parse` then reported a usage fault for a working curl
    // command line.
    const dict_only = try Set.parse("-all,dict", transfer_default);
    try testing.expect(!dict_only.isEmpty());
    try testing.expect(dict_only.hasScheme("dict"));
    try testing.expect(!dict_only.hasScheme("http"));
    // `-all` clears `unnamed` as well, so a scheme nobody named stays out.
    try testing.expect(!dict_only.hasScheme("nosuchscheme"));

    // `--proto-redir +gopher` adds one name to the default, and the
    // default is what it adds to.
    const with_gopher = try Set.parse("+gopher", redirect_default);
    try testing.expect(with_gopher.hasScheme("gopher"));
    try testing.expect(with_gopher.hasScheme("http"));
    try testing.expect(!with_gopher.hasScheme("gophers"));
    try testing.expect(!with_gopher.hasScheme("file"));

    // And a user can forbid one protocol while keeping the rest.
    const no_gopher = try Set.parse("all,-gopher", redirect_default);
    try testing.expect(!no_gopher.hasScheme("gopher"));
    try testing.expect(no_gopher.hasScheme("ftp"));
}

test "a set answers about a scheme it cannot name" {
    // `all` covers every scheme, named here or not, because a program can
    // register a protocol of its own and the default must not refuse it.
    try testing.expect(Set.all.hasScheme("http"));
    try testing.expect(Set.all.hasScheme("gopher"));
    try testing.expect(!Set.none.hasScheme("http"));
    try testing.expect(!Set.none.hasScheme("gopher"));

    // An allowlist written out by name has no room for a name nobody
    // wrote down. This is the `redirect_default` shape.
    const listed: Set = .init(&.{ .http, .https });
    try testing.expect(listed.hasScheme("http"));
    try testing.expect(!listed.hasScheme("gopher"));
}

test "a registered protocol survives the default --proto set" {
    // `zurl.Client.registerProtocol` takes any scheme a program names, and
    // `Protocol` has no member for it. curl's `--proto` default is every
    // protocol its own build speaks, so this one must be in the default
    // too, and out of it the moment the user narrows the list.
    try testing.expect(transfer_default.hasScheme("zurltest"));
    try testing.expect(!(try Set.parse("-all,http", transfer_default)).hasScheme("zurltest"));
    try testing.expect(!(try Set.parse("=http", transfer_default)).hasScheme("zurltest"));

    // Taking one name out leaves every other scheme where it was.
    const no_http = try Set.parse("-http", transfer_default);
    try testing.expect(no_http.hasScheme("zurltest"));
    try testing.expect(!no_http.hasScheme("http"));
}

test "the --proto rows measured against curl 8.21.0" {
    // Each row is one of the lists the task named, with the set curl
    // 8.21.0 was measured to build from it. The probe was
    // `curl --proto LIST http://127.0.0.1:1/x`, where exit 7 says the
    // scheme was permitted and exit 1 says `Protocol "http" is disabled`.
    const base = transfer_default;

    // `-all,http`: empty the set, then add http. Only http.
    const only_http = try Set.parse("-all,http", base);
    try testing.expect(only_http.has(.http));
    try testing.expect(!only_http.has(.https));
    try testing.expect(!only_http.has(.file));

    // `=http`: the same set by the other spelling.
    const equals_http = try Set.parse("=http", base);
    try testing.expect(equals_http.has(.http));
    try testing.expect(!equals_http.has(.https));

    // `+https`: https was already in the base, so this changes nothing.
    try testing.expectEqual(base, try Set.parse("+https", base));

    // `http,https`: no prefix reads as `+`, so this changes nothing
    // either. curl runs the transfer.
    try testing.expectEqual(base, try Set.parse("http,https", base));

    // `-ftp`: one name out of the base, and http stays.
    const no_ftp = try Set.parse("-ftp", base);
    try testing.expect(!no_ftp.has(.ftp));
    try testing.expect(no_ftp.has(.http));

    // `nosuchproto`: a name nobody knows changes nothing, and is not a
    // fault. curl runs the transfer.
    try testing.expectEqual(base, try Set.parse("nosuchproto", base));
}

test "a list that leaves nothing enabled is reported, not returned" {
    // curl 8.21.0 answers each of these with exit 2 and
    // `option --proto: is badly used here`, before any transfer.
    const base = transfer_default;
    try testing.expectError(error.ProtocolListEmpty, Set.parse("-all", base));
    try testing.expectError(error.ProtocolListEmpty, Set.parse("=nosuchproto", base));
    try testing.expectError(error.ProtocolListEmpty, Set.parse("-all,nosuchproto", base));
    try testing.expectError(error.ProtocolListEmpty, Set.parse("-all,http,-http", base));
    try testing.expectError(error.ProtocolListEmpty, Set.parse("=all,-all", base));
    try testing.expectError(error.ProtocolListEmpty, Set.parse("-ftp,-all", base));

    // Naming every member of `Protocol` is **not** the same as `-all`, and
    // it must not be. `-all` says "nothing at all", and a list of names
    // says "not these". A program that registered a protocol of its own
    // still has it after the second list, which is the answer curl gives
    // for a protocol its own build carries and the list did not name.
    const named_out = try Set.parse("-http,-https,-file,-ftp,-ftps", base);
    try testing.expect(!named_out.hasScheme("http"));
    try testing.expect(named_out.hasScheme("zurltest"));
}

test "an empty list and an empty entry both change nothing" {
    // Measured: `curl --proto ''`, `--proto ,` and `--proto http,,https`
    // all run the transfer.
    const base = transfer_default;
    try testing.expectEqual(base, try Set.parse("", base));
    try testing.expectEqual(base, try Set.parse(",", base));
    try testing.expectEqual(base, try Set.parse(",,", base));
    try testing.expectEqual(base, try Set.parse("http,,https", base));
}

test "a name carries no trimming, the way curl reads one" {
    // Measured: `curl --proto '-all, http'` exits 2, so curl read ` http`
    // as a name nobody knows and left the set empty. Trimming here would
    // accept a list curl refuses.
    try testing.expectError(error.ProtocolListEmpty, Set.parse("-all, http", transfer_default));
    try testing.expectError(error.ProtocolListEmpty, Set.parse("-all,http ", transfer_default));
}

test "an entry applies in order, and a later one wins" {
    const base = transfer_default;
    // Measured: `--proto http,-http` exits 1, and `--proto -http,http`
    // exits 7.
    try testing.expect(!(try Set.parse("http,-http", base)).has(.http));
    try testing.expect((try Set.parse("-http,http", base)).has(.http));
    // `=` clears at the point it appears, and a name after it still adds.
    const two = try Set.parse("=http,https", base);
    try testing.expect(two.has(.http));
    try testing.expect(two.has(.https));
    try testing.expect(!two.has(.file));
}

test "all names every protocol, whatever the prefix" {
    const base = transfer_default;
    try testing.expectEqual(Set.all, try Set.parse("all", base));
    try testing.expectEqual(Set.all, try Set.parse("=all", base));
    try testing.expectEqual(Set.all, try Set.parse("+all", base));
    try testing.expectEqual(Set.all, try Set.parse("-all,all", base));
    try testing.expectEqual(Set.all, try Set.parse("-ALL,ALL", base));
}

test "--proto-redir starts from its own default and not from every protocol" {
    // Measured against curl 8.21.0 with a loopback server answering
    // `location: gopher://...`: `--proto-redir -http` still reports
    // `Protocol "gopher" is disabled (in redirect)`. So removing one name
    // does not first widen the set.
    const redir = try Set.parse("-http", redirect_default);
    try testing.expect(!redir.has(.http));
    try testing.expect(redir.has(.https));
    try testing.expect(!redir.has(.file));

    // And `+file` is the list that opens the hole this file exists to
    // keep shut. It is the user's own choice, and curl reads it the same
    // way: `curl -L --proto-redir +file` follows a redirect into `file`.
    try testing.expect((try Set.parse("+file", redirect_default)).has(.file));
}

test "a list past either bound is refused rather than read" {
    const long = "http," ** ((Set.max_list_bytes / 5) + 1);
    try testing.expectError(error.ProtocolListTooLong, Set.parse(long, transfer_default));

    // Short enough for the byte bound and past the entry bound: each
    // entry here is one byte plus its comma.
    const many = "," ** (Set.max_entries + 1);
    try testing.expect(many.len <= Set.max_list_bytes);
    try testing.expectError(error.ProtocolListTooManyEntries, Set.parse(many, transfer_default));
}

test "a set at either bound of the entry count is still read" {
    // The bound is checked from both sides. A parser that cut one entry
    // early would fail this.
    const at_bound = "," ** (Set.max_entries - 1);
    try testing.expectEqual(transfer_default, try Set.parse(at_bound, transfer_default));
}

test "a redirect target must pass --proto and --proto-redir together" {
    // Every row here was measured against curl 8.21.0, with a loopback
    // server answering `location: file://.../secret.txt`. See
    // `Set.intersect`.
    const redir = try Set.parse("+file", redirect_default);
    try testing.expect(redir.has(.file));

    // `--proto-redir +file` alone: the file is read.
    try testing.expect(redir.intersect(transfer_default).has(.file));

    // `--proto -all,http` beside it: refused, because `--proto` has no
    // `file` to meet.
    const only_http = try Set.parse("-all,http", transfer_default);
    try testing.expect(!redir.intersect(only_http).has(.file));
    try testing.expect(redir.intersect(only_http).has(.http));

    // `--proto -all,http,file` beside it: read again.
    const http_and_file = try Set.parse("-all,http,file", transfer_default);
    try testing.expect(redir.intersect(http_and_file).has(.file));

    // `--proto -file` beside it: refused.
    const no_file = try Set.parse("-file", transfer_default);
    try testing.expect(!redir.intersect(no_file).has(.file));

    // And `--proto` alone never widens the redirect rule. This is the
    // half that matters for safety: a list that names `file` for the url
    // the user typed still cannot let a server reach `file`.
    try testing.expect(!redirect_default.intersect(http_and_file).has(.file));
}

test "an intersection narrows a redirect that no flag named" {
    // The defect this closes. `--proto -all,http` with a server answering
    // `location: https://...` reached the https hop, because the redirect
    // rule read `--proto-redir` alone and its default holds https. curl
    // refuses the same pair with `Protocol "https" is disabled (in
    // redirect)`. Measured.
    const only_http = try Set.parse("-all,http", transfer_default);
    const rule = redirect_default.intersect(only_http);
    try testing.expect(rule.has(.http));
    try testing.expect(!rule.has(.https));
}

test "an intersection keeps a registered protocol only when both sets do" {
    // `unnamed` is the bit that covers a scheme `Protocol` cannot name.
    // `--proto`'s default carries it and `--proto-redir`'s default does
    // not, so the default pair refuses such a scheme in a redirect and
    // permits it for a url the user typed.
    try testing.expect(transfer_default.intersect(Set.all).unnamed);
    try testing.expect(!redirect_default.intersect(transfer_default).unnamed);
    try testing.expect(!Set.all.intersect(redirect_default).unnamed);
    try testing.expect(Set.all.intersect(Set.all).unnamed);
}

test "https to http is a downgrade, and the pairs that are not" {
    // **The rule this exists for.** A credential the user scoped to TLS
    // must not leave TLS because a server said so. curl 8.21.0 carries
    // `Authorization` across this hop under `--location-trusted`,
    // measured on loopback; see `isDowngrade` for the trace and for the
    // argument for being stricter than that.
    try testing.expect(isDowngrade("https", "http"));
    try testing.expect(isDowngrade("ftps", "ftp"));
    try testing.expect(isDowngrade("wss", "ws"));
    try testing.expect(isDowngrade("https", "ws"));
    try testing.expect(isDowngrade("sftp", "ftp"));

    // The other three corners are not a downgrade.
    try testing.expect(!isDowngrade("https", "https"));
    try testing.expect(!isDowngrade("http", "https"));
    try testing.expect(!isDowngrade("http", "http"));
    try testing.expect(!isDowngrade("https", "ftps"));
    try testing.expect(!isDowngrade("https", "scp"));

    // A `file` target crosses no network, so it takes nothing off TLS.
    // The redirect policy refuses it for its own reason, and this one has
    // no reason of its own to add.
    try testing.expect(!isDowngrade("https", "file"));

    // RFC 3986 reads a scheme without regard to case, and so does this.
    try testing.expect(isDowngrade("HTTPS", "HTTP"));
    try testing.expect(!isDowngrade("HTTP", "HTTPS"));
}

test "a scheme nobody named is never treated as confidential" {
    // A program may register a protocol under any scheme, and this file
    // cannot know what such a scheme speaks. Both answers go the safe
    // way: an unknown target may be read, and an unknown source has no
    // confidentiality to lose.
    try testing.expect(isDowngrade("https", "nosuch"));
    try testing.expect(!isDowngrade("nosuch", "http"));
    try testing.expect(!isDowngrade("nosuch", "nosuch"));
    try testing.expect(!isDowngrade("", ""));
}

test "every protocol name answers isConfidential, and the pairs disagree" {
    // The switch in `isConfidential` is exhaustive, so a protocol added to
    // the enum without an answer here is a compile fault and never a
    // silent false. This walks the whole list to hold that.
    inline for (comptime std.enums.values(Protocol)) |p| {
        _ = p.isConfidential();
    }

    // Each pair splits, which is the property the downgrade rule reads.
    const pairs = [_][2]Protocol{
        .{ .http, .https },
        .{ .ftp, .ftps },
        .{ .gopher, .gophers },
        .{ .imap, .imaps },
        .{ .pop3, .pop3s },
        .{ .smtp, .smtps },
        .{ .ws, .wss },
        .{ .ldap, .ldaps },
        .{ .mqtt, .mqtts },
        .{ .rtmp, .rtmps },
        .{ .smb, .smbs },
    };
    for (pairs) |pair| {
        try testing.expect(!pair[0].isConfidential());
        try testing.expect(pair[1].isConfidential());
    }
}
