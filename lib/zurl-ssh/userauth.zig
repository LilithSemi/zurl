//! The messages of RFC 4252, the SSH authentication protocol. Pure bytes,
//! and testable with a table.
//!
//! What this module owns: the message numbers, the request builders, the
//! reply parsers, the blob RFC 4252 section 7 signs, and the filter that
//! makes a server banner safe to print. It also owns
//! `SSH_MSG_SERVICE_REQUEST` and `SSH_MSG_SERVICE_ACCEPT`, which RFC 4253
//! section 10 puts in the transport layer but which only this layer sends.
//!
//! What this module does not own: it opens no socket, it holds no state,
//! and it decides no order. `zurl_ssh.Authenticator` runs the exchange and
//! `zurl_ssh.privatekey` reads a key file.
//!
//! **Message number 60 means three different things.** RFC 4252
//! section 6 gives the range 60 to 79 to whichever method is in flight, so
//! a 60 is `SSH_MSG_USERAUTH_PK_OK` during a `publickey` query,
//! `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` during a `password` attempt, and
//! `SSH_MSG_USERAUTH_INFO_REQUEST` during `keyboard-interactive`. `Id`
//! names it `method_specific` for that reason, and each parser here checks
//! the number itself. A caller that reads a 60 without knowing which
//! request it answers is reading a message it cannot name.
//!
//! **Every field a parser returns came from the peer.** The banner, the
//! method list, the partial success flag, and every prompt are the
//! server's own bytes. Each one is bounded here, and the banner has a
//! filter of its own.

const std = @import("std");

const wire = @import("wire.zig");

/// The service a client asks for before it authenticates, RFC 4252
/// section 5.
pub const service_userauth = "ssh-userauth";

/// The service every request here asks to start after authentication,
/// RFC 4252 section 5. It is the connection layer, which a later task
/// writes.
pub const service_connection = "ssh-connection";

/// The message numbers of RFC 4252 section 6.
///
/// Non-exhaustive, because the peer writes this byte.
pub const Id = enum(u8) {
    /// RFC 4253 section 10. The client asks for `ssh-userauth`.
    service_request = 5,
    /// RFC 4253 section 10.
    service_accept = 6,
    request = 50,
    failure = 51,
    success = 52,
    banner = 53,
    /// 60. **This number belongs to whichever method is in flight.** See
    /// the module comment.
    method_specific = 60,
    /// 61, and it means `SSH_MSG_USERAUTH_INFO_RESPONSE` only.
    /// RFC 4256 section 3.4.
    info_response = 61,
    _,
};

/// The message number at the front of `payload`, or null for an empty
/// payload.
///
/// The same rule `zurl_ssh.messages.idOf` keeps: an empty payload carries
/// no message at all, and `@enumFromInt` on a non-exhaustive enum is
/// defined for every one of the 256 values a peer can write.
pub fn idOf(payload: []const u8) ?Id {
    if (payload.len == 0) return null;
    return @enumFromInt(payload[0]);
}

/// The bound on a user name.
///
/// OpenSSH refuses a name over 256 bytes in `sshd`, and a name longer than
/// this is a caller's own bug rather than a peer's.
pub const max_user_bytes = 255;

/// The bound on a password, and on one `keyboard-interactive` answer.
pub const max_password_bytes = 1024;

/// The bound on the method list a `SSH_MSG_USERAUTH_FAILURE` carries.
///
/// The list names the methods that can continue. OpenSSH writes well under
/// a hundred bytes, and a longer one is a peer trying to make this process
/// hold its bytes.
pub const max_method_list_bytes = 1024;

/// How many methods a peer may name in one failure.
pub const max_method_count = 32;

/// The bound on the text of one banner.
pub const max_banner_bytes = 4096;

/// How many prompts one `SSH_MSG_USERAUTH_INFO_REQUEST` may carry.
///
/// RFC 4256 section 3.2 lets a server ask for any number. A server that
/// asks for more than this is asking this process to do work it never
/// agreed to.
pub const max_prompts = 32;

/// The authentication methods this build can run.
pub const Method = enum {
    /// RFC 4252 section 5.2. It is how a client learns the list, and a
    /// server may still accept it for an account with no credential.
    none,
    /// RFC 4252 section 7.
    publickey,
    /// RFC 4252 section 8.
    password,
    /// RFC 4256.
    keyboard_interactive,

    /// The name of `m` on the wire.
    pub fn name(m: Method) []const u8 {
        return switch (m) {
            .none => "none",
            .publickey => "publickey",
            .password => "password",
            .keyboard_interactive => "keyboard-interactive",
        };
    }

    /// The method `text` names, or null.
    pub fn fromName(text: []const u8) ?Method {
        inline for (@typeInfo(Method).@"enum".fields) |field| {
            const candidate: Method = @enumFromInt(field.value);
            if (std.mem.eql(u8, text, candidate.name())) return candidate;
        }
        return null;
    }
};

/// Why this build cannot run a method a server offered, in words a user
/// can act on.
///
/// **A refusal with no reason is a bug report nobody can answer.** A
/// server that offers `gssapi-with-mic` and nothing else gets a message
/// that names the method, the way `zurl_ssh.hostkey.refusalFor` names a
/// host key algorithm.
///
/// Null for a name this build has never heard of.
pub fn refusalFor(text: []const u8) ?[]const u8 {
    const table = [_]struct { method: []const u8, reason: []const u8 }{
        .{
            .method = "hostbased",
            .reason = "zurl signs with the user's key only, and it reads no host key of its own",
        },
        .{
            .method = "gssapi-with-mic",
            .reason = "zurl carries no GSSAPI, and it will not link one",
        },
        .{
            .method = "gssapi-keyex",
            .reason = "zurl carries no GSSAPI, and it will not link one",
        },
        .{
            .method = "publickey-hostbound-v00@openssh.com",
            .reason = "zurl sends the plain publickey method, which every server also accepts",
        },
    };
    for (table) |row| {
        if (std.mem.eql(u8, text, row.method)) return row.reason;
    }
    return null;
}

/// Why a message could not be built.
pub const BuildError = wire.WriteError || error{
    /// The user name is longer than `max_user_bytes`.
    UserNameTooLong,
    /// The password, or one `keyboard-interactive` answer, is longer than
    /// `max_password_bytes`.
    PasswordTooLong,
};

/// Builds a `SSH_MSG_SERVICE_REQUEST`, RFC 4253 section 10.
pub fn writeServiceRequest(out: []u8, service: []const u8) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.service_request));
    try w.string(service);
    return w.written();
}

/// Builds a `none` request, RFC 4252 section 5.2.
///
/// **This is how a client learns which methods a server accepts.** The
/// reply is a `SSH_MSG_USERAUTH_FAILURE` whose name-list is that answer,
/// or a `SSH_MSG_USERAUTH_SUCCESS` for an account that needs no
/// credential.
pub fn writeNoneRequest(out: []u8, user: []const u8) BuildError![]u8 {
    if (user.len > max_user_bytes) return error.UserNameTooLong;
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.request));
    try w.string(user);
    try w.string(service_connection);
    try w.string(Method.none.name());
    return w.written();
}

/// What a `publickey` request names.
pub const PublicKeyParams = struct {
    user: []const u8,
    /// The public key algorithm name, which is `ssh-ed25519` here.
    algorithm: []const u8,
    /// The public key blob, in the form RFC 4253 section 6.6 gives.
    key_blob: []const u8,
};

/// Builds the first phase of a `publickey` attempt, RFC 4252 section 7.
///
/// The boolean is FALSE and there is no signature, so the request costs no
/// signing work and asks one question: would this key be accepted? The
/// answer is `SSH_MSG_USERAUTH_PK_OK` or a failure.
pub fn writePublicKeyQuery(out: []u8, p: PublicKeyParams) BuildError![]u8 {
    if (p.user.len > max_user_bytes) return error.UserNameTooLong;
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.request));
    try w.string(p.user);
    try w.string(service_connection);
    try w.string(Method.publickey.name());
    try w.boolean(false);
    try w.string(p.algorithm);
    try w.string(p.key_blob);
    return w.written();
}

/// The blob a `publickey` attempt signs, and the request inside it.
///
/// The two overlap on purpose. RFC 4252 section 7 signs the session
/// identifier and then the request, and the request that goes on the wire
/// is the same bytes with the session identifier taken off the front and a
/// signature added to the end. Building them apart would be two chances to
/// write the fields in two different orders.
pub const Signed = struct {
    /// Every byte the signature covers.
    blob: []u8,
    /// Where the `SSH_MSG_USERAUTH_REQUEST` starts inside `blob`.
    request_at: usize,

    /// The request part, which still needs its signature.
    pub fn request(s: Signed) []u8 {
        return s.blob[s.request_at..];
    }
};

/// Builds the blob RFC 4252 section 7 signs.
///
/// **The session identifier is the first field, and it is what stops a
/// replay.** Without it a signature captured from one session proves the
/// same thing in every other session with the same user, service, and
/// key, so a server that saw one attempt could log in as that user
/// anywhere. `session_id` is `H` of the first key exchange, which
/// `zurl_ssh.Transport.sessionId` holds.
///
/// The fields, in the order RFC 4252 section 7 lists them:
///
///     string    session identifier
///     byte      SSH_MSG_USERAUTH_REQUEST
///     string    user name
///     string    service name
///     string    "publickey"
///     boolean   TRUE
///     string    public key algorithm name
///     string    public key to be signed
///
/// The boolean is TRUE here and FALSE in `writePublicKeyQuery`, so a
/// signature made for a real attempt cannot be replayed as a query and a
/// query can never be mistaken for an attempt.
pub fn writeSignatureBlob(
    out: []u8,
    session_id: []const u8,
    p: PublicKeyParams,
) BuildError!Signed {
    if (p.user.len > max_user_bytes) return error.UserNameTooLong;
    var w: wire.Writer = .init(out);
    try w.string(session_id);
    const request_at = w.at;
    try w.byte(@intFromEnum(Id.request));
    try w.string(p.user);
    try w.string(service_connection);
    try w.string(Method.publickey.name());
    try w.boolean(true);
    try w.string(p.algorithm);
    try w.string(p.key_blob);
    return .{ .blob = w.written(), .request_at = request_at };
}

/// Adds the signature to the request `writeSignatureBlob` left in `out`.
///
/// `signature_blob` is the wire form of RFC 4253 section 6.6: the
/// algorithm name and then the signature, each as a string.
///
/// **`out` must be the same buffer `writeSignatureBlob` wrote into.** The
/// signature goes on the end of what is already there, so a shorter buffer
/// is refused here rather than left to arithmetic that would wrap.
///
/// The result points into `out`, and it starts where the request starts,
/// so the session identifier at the front of `out` never goes on the wire.
/// RFC 4252 section 7 signs it and does not send it.
pub fn finishPublicKeyRequest(
    out: []u8,
    signed: Signed,
    signature_blob: []const u8,
) BuildError![]u8 {
    if (signed.blob.len > out.len) return error.NoSpaceLeft;
    var w: wire.Writer = .{ .buffer = out, .at = signed.blob.len };
    try w.string(signature_blob);
    return out[signed.request_at..w.at];
}

/// Builds a `password` request, RFC 4252 section 8.
///
/// **The password goes on the wire as plaintext inside the packet.** The
/// packet is encrypted, which is the whole reason this method may only run
/// after `SSH_MSG_NEWKEYS`. The buffer `out` holds that plaintext until a
/// caller wipes it, and `zurl_ssh.Authenticator` wipes it.
pub fn writePasswordRequest(
    out: []u8,
    user: []const u8,
    password: []const u8,
) BuildError![]u8 {
    if (user.len > max_user_bytes) return error.UserNameTooLong;
    if (password.len > max_password_bytes) return error.PasswordTooLong;
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.request));
    try w.string(user);
    try w.string(service_connection);
    try w.string(Method.password.name());
    // FALSE says this request carries one password and not a change of
    // password. RFC 4252 section 8 gives TRUE the second meaning, and this
    // build never sends it. See `parsePasswordChangeRequest`.
    try w.boolean(false);
    try w.string(password);
    return w.written();
}

/// Builds a `keyboard-interactive` request, RFC 4256 section 3.1.
///
/// The language tag is empty, which RFC 4256 section 3.1 deprecates the
/// field and asks for. `submethods` is a hint and an empty string lets the
/// server choose.
pub fn writeKeyboardInteractiveRequest(
    out: []u8,
    user: []const u8,
    submethods: []const u8,
) BuildError![]u8 {
    if (user.len > max_user_bytes) return error.UserNameTooLong;
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.request));
    try w.string(user);
    try w.string(service_connection);
    try w.string(Method.keyboard_interactive.name());
    try w.string("");
    try w.string(submethods);
    return w.written();
}

/// Builds a `SSH_MSG_USERAUTH_INFO_RESPONSE`, RFC 4256 section 3.4.
///
/// **The answers are secrets**, for the same reason a password is. See
/// `writePasswordRequest`.
pub fn writeInfoResponse(out: []u8, answers: []const []const u8) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.info_response));
    try w.uint32(@intCast(answers.len));
    for (answers) |answer| {
        if (answer.len > max_password_bytes) return error.PasswordTooLong;
        try w.string(answer);
    }
    return w.written();
}

/// Why a reply could not be read.
pub const ParseError = wire.ReadError || error{
    /// The message number at the front is not the one asked for.
    WrongMessage,
    /// The method list is longer than `max_method_list_bytes`, or it names
    /// more than `max_method_count` methods.
    MethodListTooLong,
    /// The banner text is longer than `max_banner_bytes`.
    BannerTooLong,
    /// The server asked for more than `max_prompts` answers.
    TooManyPrompts,
};

/// Reads a `SSH_MSG_SERVICE_ACCEPT` and returns the service it names.
///
/// RFC 4253 section 10 puts the name in the message. Some servers write
/// nothing after the number, so a payload that ends there reads as an
/// empty name rather than as a fault, and the caller decides. A name that
/// starts and then stops short is still `error.Truncated`.
pub fn parseServiceAccept(payload: []const u8) ParseError![]const u8 {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.service_accept)) return error.WrongMessage;
    if (r.atEnd()) return "";
    return r.string();
}

/// What a `SSH_MSG_USERAUTH_FAILURE` carries, RFC 4252 section 5.1.
pub const Failure = struct {
    /// The methods that can continue. **Untrusted**: a server writes
    /// whatever it likes here, and a client that took it as an order would
    /// let a server choose which credential to ask for.
    methods: wire.NameList,
    /// Whether the attempt that just failed still counted for something.
    /// RFC 4252 section 5.1 says TRUE means the method worked and the
    /// server wants another one as well.
    ///
    /// **TRUE is never a success.** Only `SSH_MSG_USERAUTH_SUCCESS` ends
    /// the exchange.
    partial_success: bool,
};

/// Reads a `SSH_MSG_USERAUTH_FAILURE`.
pub fn parseFailure(payload: []const u8) ParseError!Failure {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.failure)) return error.WrongMessage;
    const methods = try r.nameList();
    if (methods.text.len > max_method_list_bytes) return error.MethodListTooLong;
    if (methods.count() > max_method_count) return error.MethodListTooLong;
    return .{ .methods = methods, .partial_success = try r.boolean() };
}

/// Reads a `SSH_MSG_USERAUTH_SUCCESS`, RFC 4252 section 5.1.
///
/// The message carries nothing past its number. A payload with bytes
/// behind the number is a server writing something this build cannot read,
/// so it is refused rather than ignored.
pub fn parseSuccess(payload: []const u8) ParseError!void {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.success)) return error.WrongMessage;
    if (!r.atEnd()) return error.WrongMessage;
}

/// What a `SSH_MSG_USERAUTH_BANNER` carries, RFC 4252 section 5.4.
pub const Banner = struct {
    /// **Untrusted text, and a server may send it before it has any idea
    /// who is connecting.** It can hold any byte, escape sequences
    /// included. Run it through `sanitizeBanner` before it reaches a
    /// terminal.
    message: []const u8,
    language: []const u8,
};

/// Reads a `SSH_MSG_USERAUTH_BANNER`.
pub fn parseBanner(payload: []const u8) ParseError!Banner {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.banner)) return error.WrongMessage;
    const message = try r.string();
    if (message.len > max_banner_bytes) return error.BannerTooLong;
    return .{
        .message = message,
        // Some servers leave the language tag off. A payload that ends
        // here reads as an empty tag, the way `messages.parseDisconnect`
        // reads one.
        .language = if (r.atEnd()) "" else try r.string(),
    };
}

/// What a `SSH_MSG_USERAUTH_PK_OK` carries, RFC 4252 section 7.
pub const PublicKeyOk = struct {
    algorithm: []const u8,
    key_blob: []const u8,
};

/// Reads a `SSH_MSG_USERAUTH_PK_OK`.
///
/// **The caller must check that both fields are the ones it sent.** RFC
/// 4252 section 7 says the server echoes them, and a server that echoes
/// something else is answering a question nobody asked.
pub fn parsePublicKeyOk(payload: []const u8) ParseError!PublicKeyOk {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.method_specific)) return error.WrongMessage;
    return .{ .algorithm = try r.string(), .key_blob = try r.string() };
}

/// What a `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` carries, RFC 4252
/// section 8.
pub const PasswordChangeRequest = struct {
    /// **Untrusted text.** See `Banner.message`.
    prompt: []const u8,
    language: []const u8,
};

/// Reads a `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ`.
///
/// **This build reads the message and refuses the exchange.** Changing a
/// password needs a new password from the person at the keyboard, and zurl
/// is a transfer tool with no prompt and no place to put one. The prompt
/// is read so that a caller can show the user what the server asked for,
/// and `zurl_ssh.Authenticator` answers with
/// `error.PasswordChangeRequired`.
pub fn parsePasswordChangeRequest(payload: []const u8) ParseError!PasswordChangeRequest {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.method_specific)) return error.WrongMessage;
    const prompt = try r.string();
    if (prompt.len > max_banner_bytes) return error.BannerTooLong;
    return .{
        .prompt = prompt,
        .language = if (r.atEnd()) "" else try r.string(),
    };
}

/// One question a `keyboard-interactive` server asked, RFC 4256
/// section 3.2.
pub const Prompt = struct {
    /// **Untrusted text.** See `Banner.message`.
    text: []const u8,
    /// Whether the answer may be shown as it is typed. FALSE is what a
    /// server sets for a password.
    echo: bool,
};

/// What a `SSH_MSG_USERAUTH_INFO_REQUEST` carries, RFC 4256 section 3.2.
pub const InfoRequest = struct {
    /// **Untrusted text.** See `Banner.message`.
    name: []const u8,
    /// **Untrusted text.**
    instruction: []const u8,
    language: []const u8,
    /// How many questions the server asked. Never more than
    /// `max_prompts`.
    prompt_count: u32,
    /// The bytes the prompts start at, inside the payload.
    prompt_bytes: []const u8,

    /// Walks the prompts, in the order the server wrote them.
    pub const Iterator = struct {
        reader: wire.Reader,
        left: u32,

        /// The next prompt, or null at the end.
        pub fn next(it: *Iterator) wire.ReadError!?Prompt {
            if (it.left == 0) return null;
            it.left -= 1;
            const text = try it.reader.string();
            return .{ .text = text, .echo = try it.reader.boolean() };
        }
    };

    /// Walks the prompts.
    pub fn iterator(request: InfoRequest) Iterator {
        return .{ .reader = .init(request.prompt_bytes), .left = request.prompt_count };
    }
};

/// Reads a `SSH_MSG_USERAUTH_INFO_REQUEST`.
///
/// **The count is checked before one prompt is read.** A server that
/// claims four thousand million questions costs this process one
/// comparison, and the prompts themselves stay inside the payload because
/// `wire.Reader` bounds every string.
pub fn parseInfoRequest(payload: []const u8) ParseError!InfoRequest {
    var r: wire.Reader = .init(payload);
    if (try r.byte() != @intFromEnum(Id.method_specific)) return error.WrongMessage;
    const name = try r.string();
    if (name.len > max_banner_bytes) return error.BannerTooLong;
    const instruction = try r.string();
    if (instruction.len > max_banner_bytes) return error.BannerTooLong;
    const language = try r.string();
    const count = try r.uint32();
    if (count > max_prompts) return error.TooManyPrompts;
    return .{
        .name = name,
        .instruction = instruction,
        .language = language,
        .prompt_count = count,
        .prompt_bytes = r.rest(),
    };
}

/// The byte a filtered banner puts in place of one it will not pass on.
pub const replacement_byte = '?';

/// Writes `text` into `out` with everything a terminal would act on taken
/// out.
///
/// **A banner is the first thing a server sends and the last thing a
/// client should trust.** It arrives before authentication, so any host on
/// the network that answers a connection can choose these bytes. Raw, they
/// can move a cursor, clear a screen, set a window title, or write over a
/// prompt that has already been printed. The rule here is:
///
/// - A line feed and a tab pass, because a banner is many lines of text.
/// - A carriage return, every other C0 control, and DEL become
///   `replacement_byte`.
/// - A byte over 127 passes only inside a valid UTF-8 sequence, so a
///   half-written sequence cannot join with what is printed next.
/// - A C1 control, U+0080 to U+009F, becomes `replacement_byte`. Some
///   terminals read those as escape sequences of their own.
/// - **A Unicode format character becomes `replacement_byte` too.** See
///   `isUnsafePoint`. A right-to-left override in a banner reorders the
///   text printed after it, which is the same trick the C0 rule exists to
///   stop, and a zero width character hides bytes from a person reading
///   the line.
///
/// **The filter never grows the text.** A byte it will not pass becomes
/// one `replacement_byte`, and a byte it passes is copied as it is. So an
/// `out` of `max_banner_bytes` holds any banner this build accepts. A
/// shorter `out` cuts the result, and its length says how much fitted.
pub fn sanitizeBanner(out: []u8, text: []const u8) []u8 {
    var at: usize = 0;
    var i: usize = 0;
    while (i < text.len and at < out.len) {
        const b = text[i];
        if (b < 0x80) {
            i += 1;
            if (b == '\n' or b == '\t') {
                out[at] = b;
            } else if (b < 0x20 or b == 0x7f) {
                out[at] = replacement_byte;
            } else {
                out[at] = b;
            }
            at += 1;
            continue;
        }

        // A sequence that is cut short, or that decodes to nothing, is one
        // byte of replacement and not a skipped run. Skipping a run would
        // let a peer hide bytes from this filter.
        const width = std.unicode.utf8ByteSequenceLength(b) catch {
            out[at] = replacement_byte;
            at += 1;
            i += 1;
            continue;
        };
        if (i + width > text.len) {
            out[at] = replacement_byte;
            at += 1;
            i += 1;
            continue;
        }
        const point = std.unicode.utf8Decode(text[i..][0..width]) catch {
            out[at] = replacement_byte;
            at += 1;
            i += 1;
            continue;
        };
        if (isUnsafePoint(point)) {
            out[at] = replacement_byte;
            at += 1;
            i += width;
            continue;
        }
        if (at + width > out.len) break;
        @memcpy(out[at..][0..width], text[i..][0..width]);
        at += width;
        i += width;
    }
    return out[0..at];
}

/// Whether a code point over 127 must not reach a terminal.
///
/// **A banner arrives before authentication, so any host that answers a
/// connection chooses these bytes.** Each row below can change what a
/// person sees without writing a visible character:
///
/// - U+0080 to U+009F are the C1 controls. Some terminals read them as
///   escape sequences of their own.
/// - U+00AD, U+200B to U+200F, U+2060 to U+2064, U+180E, and U+FEFF are
///   zero width or invisible. They hide bytes from a person reading the
///   line, and U+200E and U+200F also change direction.
/// - U+2028 and U+2029 are line and paragraph separators. A terminal that
///   breaks on them lets a banner write where a caller counted one line.
/// - U+202A to U+202E and U+2066 to U+2069 are the bidirectional
///   embeddings, overrides, and isolates. One of them, left open, reorders
///   the text printed after the banner. That is the whole of the "Trojan
///   Source" trick, CVE-2021-42574.
fn isUnsafePoint(point: u21) bool {
    return switch (point) {
        0x80...0x9f => true,
        0x00ad => true,
        0x180e => true,
        0x200b...0x200f => true,
        0x2028...0x2029 => true,
        0x202a...0x202e => true,
        0x2060...0x2064 => true,
        0x2066...0x2069 => true,
        0xfeff => true,
        else => false,
    };
}

const testing = std.testing;

test "the method names are the ones RFC 4252 puts on the wire" {
    try testing.expectEqualStrings("none", Method.none.name());
    try testing.expectEqualStrings("publickey", Method.publickey.name());
    try testing.expectEqualStrings("password", Method.password.name());
    try testing.expectEqualStrings("keyboard-interactive", Method.keyboard_interactive.name());

    try testing.expectEqual(Method.publickey, Method.fromName("publickey").?);
    try testing.expectEqual(Method.keyboard_interactive, Method.fromName("keyboard-interactive").?);
    try testing.expectEqual(@as(?Method, null), Method.fromName("hostbased"));
    try testing.expectEqual(@as(?Method, null), Method.fromName(""));
}

test "every method this build refuses gives a reason a user can act on" {
    const refused = [_][]const u8{
        "hostbased",
        "gssapi-with-mic",
        "gssapi-keyex",
        "publickey-hostbound-v00@openssh.com",
    };
    for (refused) |method| {
        const reason = refusalFor(method) orelse return error.TestExpectedReason;
        try testing.expect(reason.len != 0);
        try testing.expectEqual(@as(?Method, null), Method.fromName(method));
    }
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("made-up"));
    // The methods this build runs are never in the table.
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("publickey"));
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("password"));
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("keyboard-interactive"));
    try testing.expectEqual(@as(?[]const u8, null), refusalFor("none"));
}

test "a service request names the service and nothing else" {
    var storage: [64]u8 = undefined;
    const built = try writeServiceRequest(&storage, service_userauth);
    try testing.expectEqualSlices(u8, "\x05\x00\x00\x00\x0cssh-userauth", built);
}

test "a service accept reads the name, and an empty tail reads as no name" {
    try testing.expectEqualStrings(
        "ssh-userauth",
        try parseServiceAccept("\x06\x00\x00\x00\x0cssh-userauth"),
    );
    try testing.expectEqualStrings("", try parseServiceAccept("\x06"));
    try testing.expectError(error.WrongMessage, parseServiceAccept("\x05\x00\x00\x00\x00"));
    try testing.expectError(error.Truncated, parseServiceAccept("\x06\x00\x00"));
    try testing.expectError(error.LengthOutOfRange, parseServiceAccept("\x06\x00\x00\x00\x09ab"));
}

test "a none request carries the user, the service, and the method name" {
    var storage: [64]u8 = undefined;
    const built = try writeNoneRequest(&storage, "alice");
    try testing.expectEqualSlices(
        u8,
        "\x32" ++
            "\x00\x00\x00\x05alice" ++
            "\x00\x00\x00\x0essh-connection" ++
            "\x00\x00\x00\x04none",
        built,
    );

    const long: [max_user_bytes + 1]u8 = @splat('a');
    try testing.expectError(error.UserNameTooLong, writeNoneRequest(&storage, &long));

    var tiny: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, writeNoneRequest(&tiny, "alice"));
}

test "the publickey query writes FALSE and no signature" {
    var storage: [128]u8 = undefined;
    const built = try writePublicKeyQuery(&storage, .{
        .user = "alice",
        .algorithm = "ssh-ed25519",
        .key_blob = "KEY",
    });
    try testing.expectEqualSlices(
        u8,
        "\x32" ++
            "\x00\x00\x00\x05alice" ++
            "\x00\x00\x00\x0essh-connection" ++
            "\x00\x00\x00\x09publickey" ++
            "\x00" ++
            "\x00\x00\x00\x0bssh-ed25519" ++
            "\x00\x00\x00\x03KEY",
        built,
    );
}

test "the signature blob is the eight fields of RFC 4252 section 7, in order" {
    // **Built by hand from the RFC's list, and compared byte for byte.**
    // The hand-built value is what proves the field order, because the
    // builder and the test do not share a line of code.
    const session_id = "0123456789abcdef0123456789abcdef";
    const expected =
        "\x00\x00\x00\x20" ++ session_id ++
        "\x32" ++
        "\x00\x00\x00\x05alice" ++
        "\x00\x00\x00\x0essh-connection" ++
        "\x00\x00\x00\x09publickey" ++
        "\x01" ++
        "\x00\x00\x00\x0bssh-ed25519" ++
        "\x00\x00\x00\x03KEY";

    var storage: [256]u8 = undefined;
    const signed = try writeSignatureBlob(&storage, session_id, .{
        .user = "alice",
        .algorithm = "ssh-ed25519",
        .key_blob = "KEY",
    });
    try testing.expectEqualSlices(u8, expected, signed.blob);
    // The request starts right behind the session identifier, so the
    // session identifier is signed and never sent.
    try testing.expectEqual(@as(usize, 4 + session_id.len), signed.request_at);
    try testing.expectEqualSlices(u8, expected[4 + session_id.len ..], signed.request());
}

test "changing any one field of the signature blob changes the blob" {
    // **Every field on its own.** A builder that dropped a field, or that
    // wrote two of them in the wrong order, passes a test that only checks
    // the whole blob against itself. This one changes one field at a time
    // and requires a different result each time.
    const base_session = "0123456789abcdef0123456789abcdef";
    const base: PublicKeyParams = .{
        .user = "alice",
        .algorithm = "ssh-ed25519",
        .key_blob = "KEY",
    };
    var base_storage: [256]u8 = undefined;
    const original = try writeSignatureBlob(&base_storage, base_session, base);

    const Case = struct { session: []const u8, params: PublicKeyParams };
    const cases = [_]Case{
        // The session identifier, which is the field that stops a replay.
        .{ .session = "0123456789abcdef0123456789abcdeF", .params = base },
        // A shorter session identifier, so the length prefix moves too.
        .{ .session = "0123456789abcdef", .params = base },
        // The user name.
        .{ .session = base_session, .params = .{
            .user = "bob",
            .algorithm = base.algorithm,
            .key_blob = base.key_blob,
        } },
        // The algorithm name.
        .{ .session = base_session, .params = .{
            .user = base.user,
            .algorithm = "ssh-ed448",
            .key_blob = base.key_blob,
        } },
        // The key blob.
        .{ .session = base_session, .params = .{
            .user = base.user,
            .algorithm = base.algorithm,
            .key_blob = "OTHER",
        } },
    };
    for (cases) |case| {
        var storage: [256]u8 = undefined;
        const changed = try writeSignatureBlob(&storage, case.session, case.params);
        try testing.expect(!std.mem.eql(u8, original.blob, changed.blob));
    }

    // The service name and the method name are constants in this build, so
    // they cannot be varied by a caller. They are pinned by the byte
    // comparison in the test above.

    // **The query and the real attempt must never sign to the same
    // bytes.** The boolean is the only field that differs, and it has to
    // be enough.
    var query_storage: [256]u8 = undefined;
    const query = try writePublicKeyQuery(&query_storage, base);
    try testing.expect(!std.mem.eql(u8, original.request(), query));
}

test "the finished publickey request is the signed request and a signature" {
    const session_id = "0123456789abcdef0123456789abcdef";
    var storage: [512]u8 = undefined;
    const signed = try writeSignatureBlob(&storage, session_id, .{
        .user = "alice",
        .algorithm = "ssh-ed25519",
        .key_blob = "KEY",
    });
    const request = try finishPublicKeyRequest(&storage, signed, "SIGBLOB");

    try testing.expectEqualSlices(
        u8,
        "\x32" ++
            "\x00\x00\x00\x05alice" ++
            "\x00\x00\x00\x0essh-connection" ++
            "\x00\x00\x00\x09publickey" ++
            "\x01" ++
            "\x00\x00\x00\x0bssh-ed25519" ++
            "\x00\x00\x00\x03KEY" ++
            "\x00\x00\x00\x07SIGBLOB",
        request,
    );

    // The signed blob is a prefix of what went out, past the session
    // identifier, so the two cannot drift apart.
    try testing.expectEqualSlices(
        u8,
        signed.request(),
        request[0..signed.request().len],
    );

    // **A buffer that is not the one the blob was built in is refused
    // here**, and not left to arithmetic that would wrap. `room()` is
    // `buffer.len - at`, so a smaller buffer would give a length larger
    // than the buffer in a build with no overflow check.
    var small: [8]u8 = undefined;
    try testing.expectError(
        error.NoSpaceLeft,
        finishPublicKeyRequest(&small, signed, "SIGBLOB"),
    );
}

test "a password request writes FALSE and then the password" {
    var storage: [128]u8 = undefined;
    const built = try writePasswordRequest(&storage, "alice", "hunter2");
    try testing.expectEqualSlices(
        u8,
        "\x32" ++
            "\x00\x00\x00\x05alice" ++
            "\x00\x00\x00\x0essh-connection" ++
            "\x00\x00\x00\x08password" ++
            "\x00" ++
            "\x00\x00\x00\x07hunter2",
        built,
    );

    const long: [max_password_bytes + 1]u8 = @splat('x');
    try testing.expectError(error.PasswordTooLong, writePasswordRequest(&storage, "a", &long));
}

test "a keyboard-interactive request writes an empty language and the submethods" {
    var storage: [128]u8 = undefined;
    const built = try writeKeyboardInteractiveRequest(&storage, "alice", "");
    try testing.expectEqualSlices(
        u8,
        "\x32" ++
            "\x00\x00\x00\x05alice" ++
            "\x00\x00\x00\x0essh-connection" ++
            "\x00\x00\x00\x14keyboard-interactive" ++
            "\x00\x00\x00\x00" ++
            "\x00\x00\x00\x00",
        built,
    );
}

test "an info response counts its answers" {
    var storage: [128]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        "\x3d\x00\x00\x00\x00",
        try writeInfoResponse(&storage, &.{}),
    );
    try testing.expectEqualSlices(
        u8,
        "\x3d\x00\x00\x00\x01\x00\x00\x00\x02hi",
        try writeInfoResponse(&storage, &.{"hi"}),
    );

    const long: [max_password_bytes + 1]u8 = @splat('x');
    var big: [max_password_bytes + 64]u8 = undefined;
    try testing.expectError(error.PasswordTooLong, writeInfoResponse(&big, &.{&long}));
}

test "a failure reads its method list and its partial success flag" {
    const good = "\x33" ++ "\x00\x00\x00\x12publickey,password" ++ "\x00";
    const failure = try parseFailure(good);
    try testing.expectEqual(@as(usize, 2), failure.methods.count());
    try testing.expect(failure.methods.contains("publickey"));
    try testing.expect(failure.methods.contains("password"));
    try testing.expectEqual(false, failure.partial_success);

    const partial = "\x33" ++ "\x00\x00\x00\x08password" ++ "\x01";
    try testing.expectEqual(true, (try parseFailure(partial)).partial_success);

    try testing.expectError(error.WrongMessage, parseFailure("\x34\x00\x00\x00\x00\x00"));
    try testing.expectError(error.Truncated, parseFailure("\x33\x00\x00\x00\x00"));
    try testing.expectError(error.LengthOutOfRange, parseFailure("\x33\x00\x00\x01\x00ab"));
}

test "a method list past the bound is refused and never walked" {
    // **The list is the peer's bytes, and it decides how much work this
    // process does.** A list longer than the bound is one comparison.
    var storage: [max_method_list_bytes + 64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(Id.failure));
    const long: [max_method_list_bytes + 1]u8 = @splat('a');
    try w.string(&long);
    try w.boolean(false);
    try testing.expectError(error.MethodListTooLong, parseFailure(w.written()));

    // A list inside the byte bound that names too many methods is refused
    // as well, because the count is what a caller walks.
    var many: wire.Writer = .init(&storage);
    try many.byte(@intFromEnum(Id.failure));
    var text: [(max_method_count + 1) * 2 - 1]u8 = undefined;
    for (0..text.len) |i| text[i] = if (i % 2 == 1) ',' else 'a';
    try many.string(&text);
    try many.boolean(false);
    try testing.expectError(error.MethodListTooLong, parseFailure(many.written()));
}

test "a success carries nothing behind its number" {
    try parseSuccess("\x34");
    try testing.expectError(error.WrongMessage, parseSuccess("\x34\x00"));
    try testing.expectError(error.WrongMessage, parseSuccess("\x33"));
    try testing.expectError(error.Truncated, parseSuccess(""));
}

test "a banner reads its message, and a missing language tag is not a fault" {
    const payload = "\x35\x00\x00\x00\x05hello\x00\x00\x00\x02en";
    const banner = try parseBanner(payload);
    try testing.expectEqualStrings("hello", banner.message);
    try testing.expectEqualStrings("en", banner.language);

    const no_language = "\x35\x00\x00\x00\x03bye";
    try testing.expectEqualStrings("bye", (try parseBanner(no_language)).message);

    try testing.expectError(error.WrongMessage, parseBanner("\x34\x00\x00\x00\x00"));

    var storage: [max_banner_bytes + 64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(Id.banner));
    const long: [max_banner_bytes + 1]u8 = @splat('a');
    try w.string(&long);
    try testing.expectError(error.BannerTooLong, parseBanner(w.written()));
}

test "a PK_OK reads the two fields the server echoes" {
    const payload = "\x3c\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x03KEY";
    const ok = try parsePublicKeyOk(payload);
    try testing.expectEqualStrings("ssh-ed25519", ok.algorithm);
    try testing.expectEqualStrings("KEY", ok.key_blob);

    try testing.expectError(error.WrongMessage, parsePublicKeyOk("\x3d\x00\x00\x00\x00"));
    try testing.expectError(error.Truncated, parsePublicKeyOk("\x3c\x00\x00\x00\x00"));
}

test "a password change request reads its prompt" {
    const payload = "\x3c\x00\x00\x00\x06expiry\x00\x00\x00\x00";
    const change = try parsePasswordChangeRequest(payload);
    try testing.expectEqualStrings("expiry", change.prompt);
    try testing.expectEqualStrings("", change.language);

    const no_language = "\x3c\x00\x00\x00\x03old";
    try testing.expectEqualStrings("old", (try parsePasswordChangeRequest(no_language)).prompt);
}

test "an info request reads its prompts, and every one is bounded" {
    const payload =
        "\x3c" ++
        "\x00\x00\x00\x03PAM" ++
        "\x00\x00\x00\x00" ++
        "\x00\x00\x00\x00" ++
        "\x00\x00\x00\x02" ++
        "\x00\x00\x00\x09Password:\x00" ++
        "\x00\x00\x00\x06Token:\x01";
    const request = try parseInfoRequest(payload);
    try testing.expectEqualStrings("PAM", request.name);
    try testing.expectEqualStrings("", request.instruction);
    try testing.expectEqual(@as(u32, 2), request.prompt_count);

    var it = request.iterator();
    const first = (try it.next()).?;
    try testing.expectEqualStrings("Password:", first.text);
    try testing.expectEqual(false, first.echo);
    const second = (try it.next()).?;
    try testing.expectEqualStrings("Token:", second.text);
    try testing.expectEqual(true, second.echo);
    try testing.expectEqual(@as(?Prompt, null), try it.next());
}

test "an info request that claims more prompts than it holds is refused" {
    // **The count is checked before one prompt is read.** A server that
    // claims four thousand million questions costs one comparison here.
    const huge =
        "\x3c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff";
    try testing.expectError(error.TooManyPrompts, parseInfoRequest(huge));

    // A count inside the bound that the payload cannot back is caught by
    // the reader, one prompt at a time, and never past the payload.
    const lying =
        "\x3c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04" ++
        "\x00\x00\x00\x01a\x00";
    const request = try parseInfoRequest(lying);
    var it = request.iterator();
    _ = try it.next();
    try testing.expectError(error.Truncated, it.next());

    try testing.expectError(error.WrongMessage, parseInfoRequest("\x3d"));
}

test "the banner filter drops everything a terminal would act on" {
    var out: [256]u8 = undefined;

    // A line feed and a tab pass, because a banner is text with lines.
    try testing.expectEqualStrings("a\nb\tc", sanitizeBanner(&out, "a\nb\tc"));

    // **An escape sequence must not reach a terminal.** This one would
    // clear the screen and move the cursor home.
    try testing.expectEqualStrings("?[2J?[H", sanitizeBanner(&out, "\x1b[2J\x1b[H"));

    // A carriage return would let a server write over a line already
    // printed, so it goes too.
    try testing.expectEqualStrings("real?fake", sanitizeBanner(&out, "real\rfake"));

    // Every other C0 control and DEL.
    try testing.expectEqualStrings("?", sanitizeBanner(&out, "\x00"));
    try testing.expectEqualStrings("?", sanitizeBanner(&out, "\x07"));
    try testing.expectEqualStrings("?", sanitizeBanner(&out, "\x7f"));

    // Valid UTF-8 passes, because a banner may be written in any
    // language.
    try testing.expectEqualStrings("naïve 日本語", sanitizeBanner(&out, "naïve 日本語"));

    // A C1 control does not, because some terminals read it as an escape
    // of its own. U+009B is one.
    try testing.expectEqualStrings("a?b", sanitizeBanner(&out, "a\xc2\x9bb"));

    // **A right-to-left override reorders the text printed after the
    // banner**, which is the same trick the C0 rule stops. U+202E.
    try testing.expectEqualStrings("a?b", sanitizeBanner(&out, "a\xe2\x80\xaeb"));
    // And so does a left-to-right isolate that is never closed. U+2066.
    try testing.expectEqualStrings("a?b", sanitizeBanner(&out, "a\xe2\x81\xa6b"));
    // A zero width space hides bytes from a person reading the line.
    // U+200B.
    try testing.expectEqualStrings("a?b", sanitizeBanner(&out, "a\xe2\x80\x8bb"));
    // A line separator would break a line where a caller counted none.
    // U+2028.
    try testing.expectEqualStrings("a?b", sanitizeBanner(&out, "a\xe2\x80\xa8b"));
    // A byte order mark in the middle of the text. U+FEFF.
    try testing.expectEqualStrings("a?b", sanitizeBanner(&out, "a\xef\xbb\xbfb"));
    // A soft hyphen. U+00AD.
    try testing.expectEqualStrings("a?b", sanitizeBanner(&out, "a\xc2\xadb"));

    // A sequence that is cut short is one replacement and not a skipped
    // run. A filter that skipped the run would let the next byte join
    // with what is printed after it.
    try testing.expectEqualStrings("?", sanitizeBanner(&out, "\xc3"));
    try testing.expectEqualStrings("??", sanitizeBanner(&out, "\xff\xfe"));
    try testing.expectEqualStrings("?a", sanitizeBanner(&out, "\xc3a"));

    // The result is cut to fit, and nothing is written past the end.
    var small: [3]u8 = undefined;
    try testing.expectEqualStrings("abc", sanitizeBanner(&small, "abcdef"));
    var one: [1]u8 = undefined;
    // A multi-byte sequence that does not fit stops the run rather than
    // writing part of itself.
    try testing.expectEqualStrings("", sanitizeBanner(&one, "é"));
    try testing.expectEqualStrings("", sanitizeBanner(&.{}, "abc"));
}

test "a message number the peer invented is read and never used as a tag" {
    const id = idOf(&.{0xfe}).?;
    try testing.expectEqual(@as(u8, 0xfe), @intFromEnum(id));
    try testing.expectEqual(@as(?Id, null), idOf(""));
    try testing.expectEqual(Id.failure, idOf(&.{ 51, 1, 2 }).?);
    try testing.expectEqual(Id.method_specific, idOf(&.{60}).?);
}

test "the message numbers are the ones RFC 4252 section 6 gives" {
    try testing.expectEqual(@as(u8, 5), @intFromEnum(Id.service_request));
    try testing.expectEqual(@as(u8, 6), @intFromEnum(Id.service_accept));
    try testing.expectEqual(@as(u8, 50), @intFromEnum(Id.request));
    try testing.expectEqual(@as(u8, 51), @intFromEnum(Id.failure));
    try testing.expectEqual(@as(u8, 52), @intFromEnum(Id.success));
    try testing.expectEqual(@as(u8, 53), @intFromEnum(Id.banner));
    try testing.expectEqual(@as(u8, 60), @intFromEnum(Id.method_specific));
    try testing.expectEqual(@as(u8, 61), @intFromEnum(Id.info_response));
}
