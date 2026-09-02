//! The SASL mechanisms the three mail protocols share: what a server
//! offers, which one to pick, and the bytes of each exchange.
//!
//! **This is the shared half of SMTP, IMAP, and POP3 authentication.** The
//! three protocols frame the exchange differently. SMTP writes `AUTH
//! PLAIN` and reads `334 <base64>`. IMAP writes `A002 AUTHENTICATE PLAIN`
//! and reads `+ <base64>`. POP3 writes `AUTH PLAIN` and reads
//! `+ <base64>`. What travels inside that frame is the same for all
//! three, so it lives here once.
//!
//! This module does no I/O. It writes into a buffer the caller owns and
//! reads text the caller already has.
//!
//! **The rule that keeps a field inside its own field.** Every mechanism
//! here joins two or three texts with a separator byte, and then hides the
//! result in base64. A separator inside one of those texts therefore
//! forges the next field, and the base64 hides that from
//! `line.hasFramingByte`: `line.write` sees only the alphabet of base64
//! and passes it. So the check has to happen **before** the encode, and it
//! is `checkField`. The separators are:
//!
//! - `PLAIN`, RFC 4616: a NUL between the authzid, the authcid, and the
//!   password. A NUL in the password writes a field the user never named.
//! - `XOAUTH2` and `OAUTHBEARER`: a `\x01` between the parts, and
//!   `OAUTHBEARER` puts the user name inside a GS2 header where a `,` and
//!   an `=` are structure as well.
//! - `LOGIN` and `CRAM-MD5` carry one field to a message, so neither has
//!   a separator of its own. They are checked with the rest, because one
//!   rule over five mechanisms is a rule nobody has to remember to apply.
//!
//! `checkField` refuses a NUL, a CR, an LF, a `\x01`, and, for a field
//! that reaches a GS2 header, a `,` and an `=`. See `Fields.check`.
//!
//! **A challenge is the peer's own text.** `decodeChallenge` bounds the
//! encoded form and the decoded form, both before it writes a byte, so a
//! server that answers with a megabyte of base64 costs a caller a fixed
//! buffer and a refusal.
//!
//! **What this does not decide.** It does not open a socket, it does not
//! know a url, and it does not read a flag. `choose` takes what the server
//! offered and what the user asked for and answers with one mechanism or
//! with none.

const std = @import("std");

const line = @import("line.zig");

/// The mechanisms this build speaks.
///
/// Ordered by preference, strongest first, so `choose` walks the enum in
/// order. See `choose` for what each rank rests on.
pub const Mechanism = enum {
    /// RFC 7628. A bearer token, with a GS2 header and the host and port
    /// the client dialed.
    oauthbearer,
    /// Google's `XOAUTH2`, which is not an RFC. A bearer token, with the
    /// user name and nothing else.
    xoauth2,
    /// RFC 2195. HMAC-MD5 over the server's challenge, keyed with the
    /// password. **The password never reaches the wire.**
    cram_md5,
    /// RFC 4616. The authzid, the authcid, and the password, joined with
    /// NUL and encoded. One round trip.
    plain,
    /// The non-standard challenge pair. The user name and the password,
    /// each encoded on its own, each answering its own challenge.
    login,

    /// The name a server and a client write for this mechanism.
    pub fn name(m: Mechanism) []const u8 {
        return switch (m) {
            .oauthbearer => "OAUTHBEARER",
            .xoauth2 => "XOAUTH2",
            .cram_md5 => "CRAM-MD5",
            .plain => "PLAIN",
            .login => "LOGIN",
        };
    }

    /// The mechanism `text` names, or null when this build has none.
    ///
    /// Read without regard to case, because RFC 4422 section 3.1 makes a
    /// mechanism name a string of upper case letters, digits, `-`, and
    /// `_`, and a server that writes `Plain` still means `PLAIN`.
    pub fn fromName(text: []const u8) ?Mechanism {
        inline for (comptime std.enums.values(Mechanism)) |m| {
            if (std.ascii.eqlIgnoreCase(text, m.name())) return m;
        }
        return null;
    }

    /// Whether this mechanism puts a secret on the wire.
    ///
    /// True for every mechanism that sends the password or the bearer
    /// token itself, and false for `CRAM-MD5`, which sends a digest over a
    /// challenge the server chose.
    ///
    /// **This is what makes `CRAM-MD5` the first choice on a connection
    /// with no TLS**, and it is read nowhere else: zurl sends a cleartext
    /// mechanism over a cleartext connection when that is all a server
    /// offers, the way curl does. See `choose`.
    pub fn sendsSecretInClear(m: Mechanism) bool {
        return m != .cram_md5;
    }

    /// Whether this mechanism needs a bearer token rather than a password.
    pub fn needsBearerToken(m: Mechanism) bool {
        return m == .oauthbearer or m == .xoauth2;
    }

    /// Whether the client speaks first.
    ///
    /// A mechanism that speaks first can put its first message on the
    /// command line itself, which is one round trip fewer and what
    /// `--sasl-ir` asks for. `CRAM-MD5` cannot: its first message answers
    /// a challenge that has not arrived yet.
    pub fn hasInitialResponse(m: Mechanism) bool {
        return m != .cram_md5;
    }
};

/// Which mechanisms a server named.
///
/// A set and not a list, because the three protocols write the list three
/// ways and a caller only ever asks whether one mechanism is in it.
pub const Offer = struct {
    set: std.EnumSet(Mechanism) = .initEmpty(),
    /// Whether the server named a mechanism at all, this build's own
    /// included.
    ///
    /// **A server that named mechanisms and none of ours is not the same
    /// as a server that named none.** The first cannot take a login from
    /// this build and the second may take the protocol's own cleartext
    /// login. A caller reads this to tell the two apart.
    any: bool = false,

    /// An offer holding nothing.
    pub const empty: Offer = .{};

    /// Whether `m` is in this offer.
    pub fn has(o: Offer, m: Mechanism) bool {
        return o.set.contains(m);
    }

    /// Whether this offer holds a mechanism this build speaks.
    pub fn hasAny(o: Offer) bool {
        return o.set.count() != 0;
    }

    /// Adds every mechanism named in `text`, which is a run of names
    /// separated by spaces or tabs.
    ///
    /// **This is the SMTP form and the POP3 form.** RFC 4954 section 4
    /// writes `AUTH PLAIN LOGIN CRAM-MD5` on the `EHLO` line, and RFC 5034
    /// writes `SASL PLAIN LOGIN` on a `CAPA` line. The keyword is already
    /// off when this runs.
    pub fn addSpaceSeparated(o: *Offer, text: []const u8) void {
        var it = std.mem.tokenizeAny(u8, text, " \t");
        while (it.next()) |word| {
            o.any = true;
            if (Mechanism.fromName(word)) |m| o.set.insert(m);
        }
    }

    /// Adds every mechanism named by an `AUTH=` word of `text`.
    ///
    /// **This is the IMAP form.** RFC 3501 section 7.2.1 writes a
    /// capability list where a mechanism is `AUTH=PLAIN`, mixed in with
    /// capabilities that are not mechanisms at all. A word that is not an
    /// `AUTH=` word is skipped, so `IMAP4rev1` names no mechanism.
    pub fn addImapCapabilities(o: *Offer, text: []const u8) void {
        var it = std.mem.tokenizeAny(u8, text, " \t");
        while (it.next()) |word| {
            if (word.len <= auth_prefix.len) continue;
            if (!std.ascii.eqlIgnoreCase(word[0..auth_prefix.len], auth_prefix)) continue;
            o.any = true;
            if (Mechanism.fromName(word[auth_prefix.len..])) |m| o.set.insert(m);
        }
    }
};

/// The word that opens an IMAP capability naming a mechanism, and the word
/// `--login-options` writes before the one it names.
pub const auth_prefix = "AUTH=";

/// Whether an IMAP capability list refuses the `LOGIN` command.
///
/// RFC 3501 section 6.2.3 lets a server name `LOGINDISABLED`, which says
/// the cleartext `LOGIN` will be refused whatever credential it carries. A
/// client that sent it anyway would put the password on the wire for a
/// command the server already said no to.
pub fn imapLoginDisabled(text: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, text, " \t");
    while (it.next()) |word| {
        if (std.ascii.eqlIgnoreCase(word, "LOGINDISABLED")) return true;
    }
    return false;
}

/// The mechanism a `--login-options` value names, or null.
///
/// curl writes the value as `AUTH=PLAIN`, measured against curl 8.21.0:
/// `--login-options AUTH=PLAIN` on a server offering `PLAIN LOGIN
/// CRAM-MD5` sent `AUTH PLAIN` where the same command with no option sent
/// `AUTH CRAM-MD5`.
///
/// **The name is returned as it was written, and it is not matched against
/// this build's list here.** A value naming a mechanism this build does
/// not speak has to reach a user as that name, so the caller does the
/// lookup and writes the message.
pub fn loginOptionMechanism(value: []const u8) ?[]const u8 {
    const text = std.mem.trim(u8, value, " \t");
    if (text.len <= auth_prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(text[0..auth_prefix.len], auth_prefix)) return null;
    return text[auth_prefix.len..];
}

/// Why a mechanism was not chosen.
pub const ChooseError = error{
    /// `--login-options` named a mechanism this build does not speak.
    MechanismNotBuiltIn,
    /// `--login-options` named a mechanism the server did not offer.
    MechanismNotOffered,
    /// The named mechanism needs a bearer token and none was given, or it
    /// needs a password and a bearer token was given instead.
    MechanismNeedsOtherCredential,
};

/// What a caller knows when it picks a mechanism.
pub const Choice = struct {
    /// What the server named. See `Offer`.
    offer: Offer,
    /// Whether `--oauth2-bearer` gave a token.
    ///
    /// A bearer token and a password are different credentials, so a
    /// mechanism that carries one cannot carry the other.
    has_bearer_token: bool,
    /// The mechanism `--login-options` named, or null.
    wanted: ?[]const u8 = null,
};

/// The mechanism to use, or null for none.
///
/// **The order is strongest first, and it is curl's own.** Measured
/// against curl 8.21.0 on a loopback fixture, on all three protocols: a
/// server offering `PLAIN LOGIN CRAM-MD5` drew `AUTH CRAM-MD5` from curl,
/// a server offering `PLAIN LOGIN` drew `AUTH PLAIN` whichever order the
/// two were written in, and a server offering `XOAUTH2 OAUTHBEARER` drew
/// `AUTH OAUTHBEARER`. The reasoning behind each rank:
///
/// 1. `OAUTHBEARER` and `XOAUTH2` come first **because the credential
///    decides, not the strength**. A bearer token cannot go into `PLAIN`
///    as a password, so a transfer that has one has only these two.
///    `OAUTHBEARER` is the RFC and `XOAUTH2` is not, so the RFC is first.
/// 2. `CRAM-MD5` next, **because the password never crosses the wire**.
///    It is a digest over a challenge the server chose, so a listener on
///    the path learns nothing it can replay to another server. MD5 is old
///    and this is still the only mechanism here whose password stays at
///    home.
/// 3. `PLAIN` next: one round trip, an RFC, and every server takes it.
/// 4. `LOGIN` last: two round trips and no standard behind it. It is here
///    because a server that offers nothing else is common.
///
/// **A connection with no TLS changes nothing, and that is deliberate.**
/// curl sends `PLAIN` in the clear on a plain `smtp://`, measured, and so
/// does this. Refusing it here would be theatre: POP3's `USER` and `PASS`
/// and IMAP's `LOGIN` put the same password on the same wire, and zurl
/// has always sent those. `--ssl-reqd` is the flag that demands TLS
/// before any credential goes out, and `--help` says so. What the order
/// above does give is that `CRAM-MD5` wins whenever a server offers it,
/// so the password stays off an unencrypted wire whenever the server
/// lets it.
///
/// **`--login-options AUTH=<name>` outranks the order.** A user who names
/// a mechanism gets that mechanism or an error, never a different one.
pub fn choose(c: Choice) ChooseError!?Mechanism {
    if (c.wanted) |text| {
        const m = Mechanism.fromName(text) orelse return error.MechanismNotBuiltIn;
        if (!c.offer.has(m)) return error.MechanismNotOffered;
        if (m.needsBearerToken() != c.has_bearer_token) {
            return error.MechanismNeedsOtherCredential;
        }
        return m;
    }

    inline for (comptime std.enums.values(Mechanism)) |m| {
        if (c.offer.has(m) and m.needsBearerToken() == c.has_bearer_token) return m;
    }
    return null;
}

/// Why a field cannot go into a message.
pub const FieldError = error{
    /// The field holds a byte that is structure in the message it would
    /// go into. See the module comment.
    FieldHasSeparator,
};

/// Why a message was not written.
pub const WriteError = FieldError || error{
    /// The message does not fit the buffer the caller gave.
    MessageTooLong,
};

/// Why a challenge was not read.
pub const ChallengeError = error{
    /// The encoded challenge is longer than `max_challenge_text_bytes`,
    /// or its decoded form is longer than the caller's buffer.
    ChallengeTooLong,
    /// The challenge is not base64.
    ChallengeMalformed,
};

/// How many bytes of encoded challenge this reads.
///
/// RFC 2195 makes a `CRAM-MD5` challenge a message id, which is tens of
/// bytes, and RFC 4954 makes an SMTP challenge fit a 512 octet reply line.
/// This is past both, and it is a bound because a peer that writes base64
/// forever would otherwise fill a buffer. Passing it is
/// `error.ChallengeTooLong`.
pub const max_challenge_text_bytes: usize = 2048;

/// How many bytes of decoded challenge a caller needs room for.
///
/// The decoded form of `max_challenge_text_bytes` of base64. A caller
/// sizes its own buffer from this and never from the text it received.
pub const max_challenge_bytes: usize = max_challenge_text_bytes / 4 * 3;

/// The three texts a mechanism joins, and the bearer token when it has
/// one.
pub const Fields = struct {
    /// The identity to act as, from `--sasl-authzid`, or null. RFC 4616
    /// calls it the authorization identity, and an empty one means "the
    /// authcid itself", which is what almost every login wants.
    authzid: ?[]const u8 = null,
    /// The identity to log in as. This is the user half of `-u`.
    authcid: []const u8,
    /// The password half of `-u`. Empty for a bearer token login.
    password: []const u8 = "",
    /// The token `--oauth2-bearer` gave, or null.
    bearer_token: ?[]const u8 = null,
    /// The host this transfer dialed. `OAUTHBEARER` puts it in the
    /// message, RFC 7628 section 3.1.
    host: []const u8 = "",
    /// The port this transfer dialed. `OAUTHBEARER` puts it in the
    /// message too.
    port: u16 = 0,

    /// Refuses a field that holds a byte the message would read as
    /// structure.
    ///
    /// **This is the whole of the NUL rule, and it runs before any
    /// encode.** See the module comment for why the check cannot sit at
    /// the line writer: base64 hides every one of these bytes from it.
    ///
    /// `gs2` says the field reaches a GS2 header, where a `,` and an `=`
    /// are structure as well as the bytes every field refuses.
    pub fn check(text: []const u8, gs2: bool) FieldError!void {
        for (text) |byte| {
            switch (byte) {
                // NUL joins the `PLAIN` fields. CR and LF end a command
                // line, and a field that carried one out of base64 later
                // would end one.
                0, '\r', '\n' => return error.FieldHasSeparator,
                // `\x01` joins the `XOAUTH2` and `OAUTHBEARER` parts.
                0x01 => return error.FieldHasSeparator,
                ',', '=' => if (gs2) return error.FieldHasSeparator,
                else => {},
            }
        }
    }

    /// Refuses every field this value holds that `m` would put in a
    /// message.
    ///
    /// **Every field is checked, and not the ones one mechanism uses.**
    /// A rule that changed with the mechanism would be five rules, and a
    /// server that offered another mechanism would pick a different one.
    pub fn checkAll(f: Fields, m: Mechanism) FieldError!void {
        // The user name reaches a GS2 header for `OAUTHBEARER` alone.
        try check(f.authcid, m == .oauthbearer);
        try check(f.password, false);
        if (f.authzid) |text| try check(text, m == .oauthbearer);
        if (f.bearer_token) |text| try check(text, false);
        try check(f.host, false);
    }
};

/// Writes the base64 of the `PLAIN` message into `out`, and returns it.
///
/// RFC 4616 section 2: `authzid NUL authcid NUL passwd`. An absent authzid
/// is written as nothing at all, so the message opens with a NUL, which is
/// what curl sends: measured, `-u alice:s3cret` with no `--sasl-authzid`
/// put `\x00alice\x00s3cret` on the wire, and with `--sasl-authzid admin`
/// it put `admin\x00alice\x00s3cret`.
///
/// **The raw form is built at the tail of `out` and wiped before this
/// returns.** It holds the password in the clear, and the encoded form in
/// front of it never reaches the tail. `zurl_core.auth.basicValue` builds
/// an `Authorization` header the same way and for the same reason.
pub fn plainMessage(out: []u8, f: Fields) WriteError![]const u8 {
    try f.checkAll(.plain);

    const authzid = f.authzid orelse "";
    const raw_len = authzid.len + 1 + f.authcid.len + 1 + f.password.len;
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(raw_len);
    if (encoded_len + raw_len > out.len) return error.MessageTooLong;

    const raw_start = out.len - raw_len;
    const raw = out[raw_start..];
    // Wiped whichever way this leaves, because it holds the password.
    defer std.crypto.secureZero(u8, raw);

    var at: usize = 0;
    @memcpy(raw[at..][0..authzid.len], authzid);
    at += authzid.len;
    raw[at] = 0;
    at += 1;
    @memcpy(raw[at..][0..f.authcid.len], f.authcid);
    at += f.authcid.len;
    raw[at] = 0;
    at += 1;
    @memcpy(raw[at..][0..f.password.len], f.password);

    return encoder.encode(out[0..encoded_len], raw);
}

/// Writes the base64 of one `LOGIN` field into `out`, and returns it.
///
/// The mechanism has no standard behind it and no joining of its own: the
/// server writes a challenge for the user name, then one for the password,
/// and each answer is that one text encoded. curl sends the same two,
/// measured.
pub fn loginField(out: []u8, text: []const u8) WriteError![]const u8 {
    try Fields.check(text, false);
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(text.len);
    if (encoded_len > out.len) return error.MessageTooLong;
    return encoder.encode(out[0..encoded_len], text);
}

/// How many characters the hex of an HMAC-MD5 takes.
pub const cram_digest_text_len = std.crypto.auth.hmac.HmacMd5.mac_length * 2;

/// Writes the base64 of a `CRAM-MD5` response into `out`, and returns it.
///
/// RFC 2195 section 2: the response is `authcid SP hex(HMAC-MD5(challenge,
/// password))`. The password keys the HMAC and never reaches the wire.
///
/// Measured against curl 8.21.0: a challenge of
/// `<1896.697170952@fixture>` with `-u alice:s3cret` drew
/// `alice 02ffea576412acbc525e4d825146f9fc` from curl, on all three
/// protocols.
///
/// **The digest is hex, so it can carry no separator and no framing
/// byte.** Only the user name can, and `checkAll` has already refused one
/// that does.
pub fn cramMd5Message(out: []u8, challenge: []const u8, f: Fields) WriteError![]const u8 {
    try f.checkAll(.cram_md5);

    const Hmac = std.crypto.auth.hmac.HmacMd5;
    var mac: [Hmac.mac_length]u8 = undefined;
    // The mac is built from the password, so it is wiped with it.
    defer std.crypto.secureZero(u8, &mac);
    Hmac.create(&mac, challenge, f.password);

    const raw_len = f.authcid.len + 1 + cram_digest_text_len;
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(raw_len);
    if (encoded_len + raw_len > out.len) return error.MessageTooLong;

    const raw_start = out.len - raw_len;
    const raw = out[raw_start..];
    defer std.crypto.secureZero(u8, raw);

    @memcpy(raw[0..f.authcid.len], f.authcid);
    raw[f.authcid.len] = ' ';
    writeHex(raw[f.authcid.len + 1 ..][0..cram_digest_text_len], &mac);

    return encoder.encode(out[0..encoded_len], raw);
}

/// Writes the lower case hex of `bytes` into `out`.
///
/// `out` must hold exactly two characters for each byte. Lower case,
/// because RFC 2195's own example is lower case and curl writes it lower
/// case, measured.
fn writeHex(out: []u8, bytes: []const u8) void {
    std.debug.assert(out.len == bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0x0f];
    }
}

/// Writes the base64 of an `XOAUTH2` message into `out`, and returns it.
///
/// The form is `user=<authcid>\x01auth=Bearer <token>\x01\x01`. It is
/// Google's own and has no RFC. Measured against curl 8.21.0: `-u alice
/// --oauth2-bearer tok123` put `user=alice\x01auth=Bearer tok123\x01\x01`
/// on the wire, byte for byte.
pub fn xoauth2Message(out: []u8, f: Fields) WriteError![]const u8 {
    try f.checkAll(.xoauth2);
    const token = f.bearer_token orelse "";
    return joinAndEncode(out, &.{
        "user=", f.authcid, "\x01auth=Bearer ", token, "\x01\x01",
    });
}

/// Writes the base64 of an `OAUTHBEARER` message into `out`, and returns
/// it.
///
/// RFC 7628 section 3.1: a GS2 header, then the host, the port, and the
/// token, each on its own `\x01`. Measured against curl 8.21.0: `-u alice
/// --oauth2-bearer tok123` on `smtp://127.0.0.1:2545` put
/// `n,a=alice,\x01host=127.0.0.1\x01port=2545\x01auth=Bearer
/// tok123\x01\x01` on the wire, byte for byte.
///
/// **The user name sits inside the GS2 header**, where a `,` ends the
/// field and an `=` opens one. `checkAll` refuses both for this mechanism
/// and for no other. See `Fields.check`.
pub fn oauthbearerMessage(out: []u8, f: Fields) WriteError![]const u8 {
    try f.checkAll(.oauthbearer);
    const token = f.bearer_token orelse "";

    var port_digits: [5]u8 = undefined;
    const port = std.fmt.bufPrint(&port_digits, "{d}", .{f.port}) catch unreachable;

    return joinAndEncode(out, &.{
        "n,a=",      f.authcid, ",\x01host=",       f.host,
        "\x01port=", port,      "\x01auth=Bearer ", token,
        "\x01\x01",
    });
}

/// Joins `parts` at the tail of `out`, encodes them into the front, and
/// wipes the tail.
///
/// The tail holds a bearer token, which is a secret, so it is wiped the
/// way `plainMessage` wipes its own.
fn joinAndEncode(out: []u8, parts: []const []const u8) WriteError![]const u8 {
    var raw_len: usize = 0;
    for (parts) |part| raw_len += part.len;

    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(raw_len);
    if (encoded_len + raw_len > out.len) return error.MessageTooLong;

    const raw_start = out.len - raw_len;
    const raw = out[raw_start..];
    defer std.crypto.secureZero(u8, raw);

    var at: usize = 0;
    for (parts) |part| {
        @memcpy(raw[at..][0..part.len], part);
        at += part.len;
    }

    return encoder.encode(out[0..encoded_len], raw);
}

/// Reads a server challenge out of `text` into `out`, and returns it.
///
/// **A challenge is the peer's own text, and it is bounded twice.** The
/// encoded form is refused past `max_challenge_text_bytes` before any
/// decode runs, and the decoded form is refused past `out` before any byte
/// is written. So a server that answers with base64 for a megabyte costs
/// this process a comparison.
///
/// An empty challenge is a real challenge and not a fault: RFC 4954 lets a
/// server answer `334 ` with nothing after it, which is what a `PLAIN`
/// exchange with no initial response draws.
pub fn decodeChallenge(out: []u8, text: []const u8) ChallengeError![]const u8 {
    if (text.len > max_challenge_text_bytes) return error.ChallengeTooLong;
    if (text.len == 0) return out[0..0];

    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(text) catch return error.ChallengeMalformed;
    if (size > out.len) return error.ChallengeTooLong;
    decoder.decode(out[0..size], text) catch return error.ChallengeMalformed;
    return out[0..size];
}

/// How many bytes one encoded message may take.
///
/// A `PLAIN` message holds two credentials and an authzid, and an
/// `OAUTHBEARER` message holds a token and a host name. Each protocol
/// package sizes its own buffer from this, and a credential longer than
/// this meets its own bound earlier, at the package that read it.
pub const max_message_bytes: usize = 4096;

const testing = std.testing;

test "a mechanism name goes out and comes back" {
    for (comptime std.enums.values(Mechanism)) |m| {
        try testing.expectEqual(@as(?Mechanism, m), Mechanism.fromName(m.name()));
        // A server that shouts or whispers still names the same one.
        var lowered: [16]u8 = undefined;
        const text = std.ascii.lowerString(lowered[0..m.name().len], m.name());
        try testing.expectEqual(@as(?Mechanism, m), Mechanism.fromName(text));
    }
    try testing.expectEqual(@as(?Mechanism, null), Mechanism.fromName("GSSAPI"));
    try testing.expectEqual(@as(?Mechanism, null), Mechanism.fromName("NTLM"));
    try testing.expectEqual(@as(?Mechanism, null), Mechanism.fromName(""));
    // A longer word that opens with a name is another mechanism.
    try testing.expectEqual(@as(?Mechanism, null), Mechanism.fromName("PLAINTEXT"));
}

test "only CRAM-MD5 keeps the secret off the wire" {
    try testing.expect(!Mechanism.cram_md5.sendsSecretInClear());
    try testing.expect(Mechanism.plain.sendsSecretInClear());
    try testing.expect(Mechanism.login.sendsSecretInClear());
    try testing.expect(Mechanism.xoauth2.sendsSecretInClear());
    try testing.expect(Mechanism.oauthbearer.sendsSecretInClear());
    // And only CRAM-MD5 cannot speak first, for the same reason: it has
    // nothing to say until the challenge arrives.
    try testing.expect(!Mechanism.cram_md5.hasInitialResponse());
    try testing.expect(Mechanism.plain.hasInitialResponse());
}

test "an smtp AUTH line names its mechanisms" {
    var o: Offer = .empty;
    o.addSpaceSeparated("PLAIN LOGIN CRAM-MD5");
    try testing.expect(o.has(.plain));
    try testing.expect(o.has(.login));
    try testing.expect(o.has(.cram_md5));
    try testing.expect(!o.has(.xoauth2));
    try testing.expect(o.any);

    // A mechanism this build does not speak still says the server named
    // one, which is what tells a caller not to fall back.
    var other: Offer = .empty;
    other.addSpaceSeparated("GSSAPI NTLM");
    try testing.expect(!other.hasAny());
    try testing.expect(other.any);

    var none: Offer = .empty;
    none.addSpaceSeparated("");
    try testing.expect(!none.any);
}

test "an imap capability list names a mechanism only through AUTH=" {
    var o: Offer = .empty;
    o.addImapCapabilities("IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=CRAM-MD5 IDLE");
    try testing.expect(o.has(.plain));
    try testing.expect(o.has(.cram_md5));
    try testing.expect(!o.has(.login));

    // **The defect this rule exists for.** A bare `PLAIN` in the list is
    // not a mechanism, and a capability named `LOGIN` is not the `LOGIN`
    // mechanism: `LOGINDISABLED` and `LOGIN-REFERRALS` are both ordinary
    // capabilities.
    var wrong: Offer = .empty;
    wrong.addImapCapabilities("IMAP4rev1 LOGINDISABLED LOGIN-REFERRALS PLAIN");
    try testing.expect(!wrong.hasAny());
    try testing.expect(!wrong.any);

    // `AUTH=` with nothing after it names nothing.
    var bare: Offer = .empty;
    bare.addImapCapabilities("IMAP4rev1 AUTH=");
    try testing.expect(!bare.hasAny());
    try testing.expect(!bare.any);
}

test "LOGINDISABLED is read as a whole word" {
    try testing.expect(imapLoginDisabled("IMAP4rev1 LOGINDISABLED AUTH=PLAIN"));
    try testing.expect(imapLoginDisabled("logindisabled"));
    try testing.expect(!imapLoginDisabled("IMAP4rev1 AUTH=PLAIN"));
    try testing.expect(!imapLoginDisabled("XLOGINDISABLED"));
    try testing.expect(!imapLoginDisabled(""));
}

test "a login option names a mechanism only in the AUTH= form" {
    try testing.expectEqualStrings("PLAIN", loginOptionMechanism("AUTH=PLAIN").?);
    try testing.expectEqualStrings("CRAM-MD5", loginOptionMechanism("auth=CRAM-MD5").?);
    try testing.expectEqualStrings("GSSAPI", loginOptionMechanism("AUTH=GSSAPI").?);
    try testing.expectEqual(@as(?[]const u8, null), loginOptionMechanism("PLAIN"));
    try testing.expectEqual(@as(?[]const u8, null), loginOptionMechanism("AUTH="));
    try testing.expectEqual(@as(?[]const u8, null), loginOptionMechanism(""));
}

test "the strongest mechanism the server offers is the one chosen" {
    // **This is curl's own order, measured.** See `choose`.
    var all: Offer = .empty;
    all.addSpaceSeparated("PLAIN LOGIN CRAM-MD5");
    try testing.expectEqual(
        @as(?Mechanism, .cram_md5),
        try choose(.{ .offer = all, .has_bearer_token = false }),
    );

    var two: Offer = .empty;
    two.addSpaceSeparated("LOGIN PLAIN");
    try testing.expectEqual(
        @as(?Mechanism, .plain),
        try choose(.{ .offer = two, .has_bearer_token = false }),
    );

    var one: Offer = .empty;
    one.addSpaceSeparated("LOGIN");
    try testing.expectEqual(
        @as(?Mechanism, .login),
        try choose(.{ .offer = one, .has_bearer_token = false }),
    );

    var nothing: Offer = .empty;
    nothing.addSpaceSeparated("GSSAPI");
    try testing.expectEqual(
        @as(?Mechanism, null),
        try choose(.{ .offer = nothing, .has_bearer_token = false }),
    );
}

test "a bearer token picks a bearer mechanism and nothing else" {
    // **A token cannot go into PLAIN as a password.** So a transfer that
    // has one has only the two bearer mechanisms, and a transfer that has
    // none has only the other three.
    var mixed: Offer = .empty;
    mixed.addSpaceSeparated("PLAIN LOGIN CRAM-MD5 XOAUTH2 OAUTHBEARER");
    try testing.expectEqual(
        @as(?Mechanism, .oauthbearer),
        try choose(.{ .offer = mixed, .has_bearer_token = true }),
    );
    try testing.expectEqual(
        @as(?Mechanism, .cram_md5),
        try choose(.{ .offer = mixed, .has_bearer_token = false }),
    );

    var xo: Offer = .empty;
    xo.addSpaceSeparated("PLAIN XOAUTH2");
    try testing.expectEqual(
        @as(?Mechanism, .xoauth2),
        try choose(.{ .offer = xo, .has_bearer_token = true }),
    );

    // A token with no bearer mechanism offered chooses nothing, rather
    // than send the token as a password.
    var plain_only: Offer = .empty;
    plain_only.addSpaceSeparated("PLAIN LOGIN");
    try testing.expectEqual(
        @as(?Mechanism, null),
        try choose(.{ .offer = plain_only, .has_bearer_token = true }),
    );
}

test "a named mechanism outranks the order, and a bad name is refused" {
    var all: Offer = .empty;
    all.addSpaceSeparated("PLAIN LOGIN CRAM-MD5");

    // Measured: `--login-options AUTH=PLAIN` on this offer sent
    // `AUTH PLAIN` from curl where the same command with no option sent
    // `AUTH CRAM-MD5`.
    try testing.expectEqual(
        @as(?Mechanism, .plain),
        try choose(.{ .offer = all, .has_bearer_token = false, .wanted = "PLAIN" }),
    );
    try testing.expectEqual(
        @as(?Mechanism, .login),
        try choose(.{ .offer = all, .has_bearer_token = false, .wanted = "login" }),
    );

    try testing.expectError(
        error.MechanismNotBuiltIn,
        choose(.{ .offer = all, .has_bearer_token = false, .wanted = "GSSAPI" }),
    );
    try testing.expectError(
        error.MechanismNotOffered,
        choose(.{ .offer = all, .has_bearer_token = false, .wanted = "XOAUTH2" }),
    );
    try testing.expectError(
        error.MechanismNeedsOtherCredential,
        choose(.{ .offer = all, .has_bearer_token = true, .wanted = "PLAIN" }),
    );
}

test "the PLAIN message is the three fields joined with NUL" {
    // The exact bytes curl 8.21.0 put on the wire, measured on a loopback
    // SMTP fixture offering `PLAIN` alone.
    var out: [256]u8 = undefined;

    try testing.expectEqualStrings(
        "AGFsaWNlAHMzY3JldA==",
        try plainMessage(&out, .{ .authcid = "alice", .password = "s3cret" }),
    );
    // And that value decodes to the three fields with an empty authzid.
    var raw: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "\x00alice\x00s3cret",
        try decodeChallenge(&raw, "AGFsaWNlAHMzY3JldA=="),
    );

    // With `--sasl-authzid admin`, measured the same way.
    try testing.expectEqualStrings(
        "YWRtaW4AYWxpY2UAczNjcmV0",
        try plainMessage(&out, .{
            .authzid = "admin",
            .authcid = "alice",
            .password = "s3cret",
        }),
    );
}

test "a NUL in any PLAIN field forges a field, and is refused" {
    // **The proof of the NUL rule.** Each field below would move the
    // separator and hand the server a credential the user never wrote:
    // an authcid of `alice\x00evil` reaches a server as the authcid
    // `alice` and the password `evil`, and the real password lands in a
    // fourth field the mechanism has no place for.
    var out: [256]u8 = undefined;
    @memset(&out, 0xaa);

    const forged = [_][]const u8{
        "alice\x00evil",
        "\x00",
        "a\x00b\x00c",
        "s3cret\x00admin",
        "alice\x01evil",
        "alice\r\nQUIT",
        "alice\nQUIT",
        "alice\r",
    };
    for (forged) |text| {
        try testing.expectError(error.FieldHasSeparator, plainMessage(&out, .{
            .authcid = text,
            .password = "s3cret",
        }));
        try testing.expectError(error.FieldHasSeparator, plainMessage(&out, .{
            .authcid = "alice",
            .password = text,
        }));
        try testing.expectError(error.FieldHasSeparator, plainMessage(&out, .{
            .authzid = text,
            .authcid = "alice",
            .password = "s3cret",
        }));
        // The same three fields are refused for every other mechanism
        // that carries them.
        try testing.expectError(error.FieldHasSeparator, loginField(&out, text));
        try testing.expectError(error.FieldHasSeparator, cramMd5Message(&out, "<x@y>", .{
            .authcid = text,
            .password = "s3cret",
        }));
        try testing.expectError(error.FieldHasSeparator, xoauth2Message(&out, .{
            .authcid = "alice",
            .bearer_token = text,
        }));
        try testing.expectError(error.FieldHasSeparator, oauthbearerMessage(&out, .{
            .authcid = "alice",
            .bearer_token = text,
            .host = "h",
            .port = 1,
        }));
    }

    // Not one byte of the buffer moved.
    for (out) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);
}

test "a byte that is not a separator still reaches a PLAIN field" {
    // The rule refuses the structure of the message and never a byte a
    // password may hold. A space, a tab, a `,`, an `=`, and a high byte
    // are all ordinary in a password.
    var out: [256]u8 = undefined;
    var raw: [64]u8 = undefined;

    const encoded = try plainMessage(&out, .{
        .authcid = "alice",
        .password = "a b\t,=\x7f\xc3\xa9",
    });
    try testing.expectEqualStrings(
        "\x00alice\x00a b\t,=\x7f\xc3\xa9",
        try decodeChallenge(&raw, encoded),
    );
}

test "a comma or an equals in an OAUTHBEARER user name is refused" {
    // **The GS2 header is a second grammar.** `n,a=alice,` names the
    // user between an `=` and a `,`, so a name holding either would end
    // the field and open another. RFC 7628 section 3.1 asks a client to
    // escape them; refusing is the answer this project keeps for a
    // credential, because a credential changed on its way to the wire is
    // not the credential the user gave.
    var out: [256]u8 = undefined;
    try testing.expectError(error.FieldHasSeparator, oauthbearerMessage(&out, .{
        .authcid = "al,ice",
        .bearer_token = "tok",
        .host = "h",
        .port = 1,
    }));
    try testing.expectError(error.FieldHasSeparator, oauthbearerMessage(&out, .{
        .authcid = "al=ice",
        .bearer_token = "tok",
        .host = "h",
        .port = 1,
    }));

    // The same two bytes are ordinary everywhere else, `XOAUTH2`
    // included, because no other mechanism here has a GS2 header.
    _ = try xoauth2Message(&out, .{ .authcid = "al,ice", .bearer_token = "tok" });
    _ = try plainMessage(&out, .{ .authcid = "al,ice", .password = "p=w" });
}

test "the LOGIN fields are each one text, encoded" {
    // Measured from curl 8.21.0 on a fixture offering `LOGIN` alone.
    var out: [128]u8 = undefined;
    try testing.expectEqualStrings("YWxpY2U=", try loginField(&out, "alice"));
    try testing.expectEqualStrings("czNjcmV0", try loginField(&out, "s3cret"));
    try testing.expectEqualStrings("", try loginField(&out, ""));
}

test "the CRAM-MD5 response is the RFC 2195 form, and curl writes the same" {
    // **Measured against curl 8.21.0**, on all three protocols: this
    // challenge and this credential drew exactly this response.
    var out: [256]u8 = undefined;
    var raw: [128]u8 = undefined;

    const encoded = try cramMd5Message(&out, "<1896.697170952@fixture>", .{
        .authcid = "alice",
        .password = "s3cret",
    });
    try testing.expectEqualStrings(
        "YWxpY2UgMDJmZmVhNTc2NDEyYWNiYzUyNWU0ZDgyNTE0NmY5ZmM=",
        encoded,
    );
    try testing.expectEqualStrings(
        "alice 02ffea576412acbc525e4d825146f9fc",
        try decodeChallenge(&raw, encoded),
    );

    // The password itself is nowhere in the message.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, try decodeChallenge(&raw, encoded), "s3cret"),
    );
}

test "the CRAM-MD5 digest matches the RFC 2195 worked example" {
    // RFC 2195 section 2: the challenge
    // `<1896.697170952@postoffice.reston.mci.net>` with the user `tim`
    // and the password `tanstaaftanstaaf` gives this digest. A number
    // from the standard, and not a number this code produced.
    var out: [256]u8 = undefined;
    var raw: [128]u8 = undefined;
    const encoded = try cramMd5Message(
        &out,
        "<1896.697170952@postoffice.reston.mci.net>",
        .{ .authcid = "tim", .password = "tanstaaftanstaaf" },
    );
    try testing.expectEqualStrings(
        "tim b913a602c7eda7a495b4e6e7334d3890",
        try decodeChallenge(&raw, encoded),
    );
}

test "the XOAUTH2 and OAUTHBEARER messages are byte for byte curl's own" {
    var out: [512]u8 = undefined;
    var raw: [256]u8 = undefined;

    // Measured: `-u alice --oauth2-bearer tok123` on a fixture offering
    // `XOAUTH2`.
    const xo = try xoauth2Message(&out, .{
        .authcid = "alice",
        .bearer_token = "tok123",
    });
    try testing.expectEqualStrings(
        "dXNlcj1hbGljZQFhdXRoPUJlYXJlciB0b2sxMjMBAQ==",
        xo,
    );
    try testing.expectEqualStrings(
        "user=alice\x01auth=Bearer tok123\x01\x01",
        try decodeChallenge(&raw, xo),
    );

    // Measured: the same credential on `smtp://127.0.0.1:2545`.
    const ob = try oauthbearerMessage(&out, .{
        .authcid = "alice",
        .bearer_token = "tok123",
        .host = "127.0.0.1",
        .port = 2545,
    });
    try testing.expectEqualStrings(
        "bixhPWFsaWNlLAFob3N0PTEyNy4wLjAuMQFwb3J0PTI1NDUBYXV0aD1CZWFyZXIgdG9rMTIzAQE=",
        ob,
    );
    try testing.expectEqualStrings(
        "n,a=alice,\x01host=127.0.0.1\x01port=2545\x01auth=Bearer tok123\x01\x01",
        try decodeChallenge(&raw, ob),
    );
}

test "every message this module builds can carry no framing byte" {
    // **The join between this module and `line.write`.** Base64 hides a
    // NUL from the line writer, so this module refuses one. The other
    // half of the rule is that what this module hands back is always
    // safe for a command line, whatever the fields held.
    var out: [512]u8 = undefined;
    const ordinary = [_][]const u8{ "alice", "a b", "\xc3\xa9", "", "a\tb", "a,b=c" };
    for (ordinary) |text| {
        try testing.expect(!line.hasFramingByte(try plainMessage(&out, .{
            .authcid = text,
            .password = text,
        })));
        try testing.expect(!line.hasFramingByte(try loginField(&out, text)));
        try testing.expect(!line.hasFramingByte(try cramMd5Message(&out, "<x@y>", .{
            .authcid = text,
            .password = text,
        })));
        try testing.expect(!line.hasFramingByte(try xoauth2Message(&out, .{
            .authcid = text,
            .bearer_token = text,
        })));
    }
}

test "a message longer than the buffer is refused rather than overrun" {
    var out: [16]u8 = undefined;
    @memset(&out, 0xaa);
    try testing.expectError(error.MessageTooLong, plainMessage(&out, .{
        .authcid = "a-rather-long-user-name",
        .password = "and-a-longer-password",
    }));
    try testing.expectError(error.MessageTooLong, loginField(&out, "a-long-user-name"));
    try testing.expectError(error.MessageTooLong, cramMd5Message(&out, "<x@y>", .{
        .authcid = "alice",
        .password = "s3cret",
    }));
    try testing.expectError(error.MessageTooLong, xoauth2Message(&out, .{
        .authcid = "alice",
        .bearer_token = "tok",
    }));
    for (out) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);
}

test "a challenge is bounded before it is decoded and after" {
    var out: [64]u8 = undefined;

    try testing.expectEqualStrings(
        "<1896.697170952@fixture>",
        try decodeChallenge(&out, "PDE4OTYuNjk3MTcwOTUyQGZpeHR1cmU+"),
    );
    // An empty challenge is a real challenge. RFC 4954 lets a server
    // answer `334 ` with nothing after it.
    try testing.expectEqualStrings("", try decodeChallenge(&out, ""));

    // Longer than the caller's buffer, and refused before a byte is
    // written into it.
    @memset(&out, 0xaa);
    var long_text: [200]u8 = undefined;
    @memset(&long_text, 'A');
    try testing.expectError(error.ChallengeTooLong, decodeChallenge(&out, &long_text));
    for (out) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);

    // Longer than the text bound, and refused before the size is even
    // worked out. A server that writes base64 for ever costs a
    // comparison.
    var huge: [max_challenge_text_bytes + 4]u8 = undefined;
    @memset(&huge, 'A');
    var room: [max_challenge_bytes]u8 = undefined;
    try testing.expectError(error.ChallengeTooLong, decodeChallenge(&room, &huge));
}

test "a challenge that is not base64 ends the exchange" {
    var out: [64]u8 = undefined;
    try testing.expectError(error.ChallengeMalformed, decodeChallenge(&out, "not base64!"));
    try testing.expectError(error.ChallengeMalformed, decodeChallenge(&out, "A"));
    try testing.expectError(error.ChallengeMalformed, decodeChallenge(&out, "===="));
    try testing.expectError(error.ChallengeMalformed, decodeChallenge(&out, "PDE4OTYuNj=="));
}

test "the challenge bounds hold together" {
    // The decoded bound is what the text bound decodes to, so a caller
    // that sizes a buffer from one never meets the other by surprise.
    try testing.expectEqual(
        max_challenge_bytes,
        std.base64.standard.Decoder.calcSizeUpperBound(max_challenge_text_bytes) catch unreachable,
    );
}
