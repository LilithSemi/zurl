//! RFC 4252, the SSH authentication protocol, run over one `Transport`.
//!
//! **This is the layer above the transport and below the connection
//! layer.** It asks for the `ssh-userauth` service, learns which methods
//! the server accepts, and offers what the caller gave it until one
//! works. There is no channel here and no SFTP, and `zurl_ssh` still
//! registers no url scheme, so nothing on the command line reaches this
//! yet.
//!
//! The order of the methods is fixed and it is the caller's credentials
//! that decide which of them run:
//!
//! 1. `none`, always and first. RFC 4252 section 5.2 makes it the way a
//!    client learns the server's list, and a server may accept it for an
//!    account with no credential.
//! 2. `publickey`, when the caller gave a key. Both phases run: the query
//!    with no signature, then the signed attempt.
//! 3. `password`, when the caller gave one.
//! 4. `keyboard-interactive`, with the same password, when the caller
//!    allows it. Many servers offer this where `password` is turned off.
//!
//! **A method the server did not name is never tried.** The list in a
//! `SSH_MSG_USERAUTH_FAILURE` says what can continue, and an attempt
//! outside it is a round trip that can only fail.
//!
//! **What this refuses by name.** `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` is
//! `error.PasswordChangeRequired`: a new password has to come from the
//! person at the keyboard, and zurl is a transfer tool with no prompt. A
//! `keyboard-interactive` exchange that asks anything but one hidden
//! question is `error.KeyboardInteractivePromptUnsupported`, because
//! answering a second question with the same password would send the
//! password where the server asked for something else.
//! `zurl_ssh.userauth.refusalFor` names `hostbased` and the two GSSAPI
//! methods, and this build never offers them.
//!
//! **Where the secrets are wiped.** `request_storage` holds a password in
//! the clear while the request is built, and every attempt wipes it with
//! `std.crypto.secureZero` on the way out. `deinit` wipes it again. The
//! private key belongs to the caller and
//! `zurl_ssh.privatekey.PrivateKey.deinit` wipes that.
//!
//! **There is no way to skip the host key check from here.** The
//! transport made the trust decision the caller's and this layer adds no
//! option of its own. A connection that reaches this point has already
//! had its host key accepted by a `Verifier`.
//!
//! **Everything the server sends here is untrusted.** The bounds are:
//!
//! | what | bound |
//! | --- | --- |
//! | one banner | `userauth.max_banner_bytes` |
//! | banners before one reply | `max_banner_run` |
//! | banner bytes in one run | `max_banner_total_bytes` |
//! | the accepted-method list | `userauth.max_method_list_bytes`, and `userauth.max_method_count` names |
//! | prompts in one info request | `userauth.max_prompts`, and this build answers one |
//! | info requests in one attempt | `max_info_rounds` |
//! | methods offered in one run | `Options.max_rounds` |
//!
//! **An `Authenticator` must not move once it is running.** `banner` and
//! `acceptedMethods` point into this value.

const Authenticator = @This();

const std = @import("std");

const privatekey = @import("privatekey.zig");
const signer_seam = @import("signer.zig");
const userauth = @import("userauth.zig");
const wire = @import("wire.zig");

const Signer = signer_seam.Signer;
const Transport = @import("Transport.zig");

/// How many bytes one request may take.
///
/// The largest is a signed `publickey` request: the session identifier,
/// the user name, the two constant names, the algorithm name, the public
/// key blob, and the signature. A `password` request and a
/// `keyboard-interactive` answer are both smaller.
pub const max_request_bytes = 2048;

/// How many banners may arrive before one reply.
pub const max_banner_run = 8;

/// How many bytes of banner one run of `authenticate` accepts.
pub const max_banner_total_bytes = 16384;

/// How many `SSH_MSG_USERAUTH_INFO_REQUEST` messages one
/// `keyboard-interactive` attempt answers.
pub const max_info_rounds = 8;

/// Where a banner goes.
///
/// **The text is already filtered.** `zurl_ssh.userauth.sanitizeBanner`
/// has run on it, so nothing a terminal acts on is left. It is still the
/// server's words and not this build's.
pub const BannerSink = struct {
    /// Passed back to `show`.
    ctx: ?*anyopaque = null,
    show: *const fn (ctx: ?*anyopaque, text: []const u8) void,
};

/// What one run of authentication needs.
pub const Options = struct {
    /// The account to log in as. Never empty, and never longer than
    /// `zurl_ssh.userauth.max_user_bytes`.
    user: []const u8,
    /// The key a `publickey` attempt signs with, or null for no
    /// `publickey` attempt. The caller owns it and wipes it.
    ///
    /// This is `signer` with the `zurl_ssh.signer.Signer` made for the
    /// caller. Set one field or the other and never both: two answers to
    /// one question is `error.TwoPublicKeySigners`.
    key: ?*const privatekey.PrivateKey = null,
    /// Whatever holds the private key, for a `publickey` attempt whose
    /// key is not in this process.
    ///
    /// **This is how a login through an agent works.**
    /// `zurl_ssh.AgentClient.signer` gives one, and the private key stays
    /// in the agent: this process asks for a signature and never reads a
    /// key file. See `zurl_ssh.signer`, which is the seam both sides meet
    /// at.
    signer: ?Signer = null,
    /// The password a `password` or `keyboard-interactive` attempt sends,
    /// or null. **The caller owns it and wipes it.**
    password: ?[]const u8 = null,
    /// Whether the password may also go out through
    /// `keyboard-interactive`. Many servers offer that method where
    /// `password` is turned off, and OpenSSH's client does the same.
    allow_keyboard_interactive: bool = true,
    /// Where a banner goes. Null drops it, and the counters still show it
    /// arrived.
    banner: ?BannerSink = null,
    /// How many methods one run may offer.
    max_rounds: usize = 16,
};

/// What the exchange did that no caller asked for.
///
/// **Recovery is never silent.** A banner that goes nowhere, a method that
/// failed, and a public key the server would not take are all counted
/// here.
pub const Counters = struct {
    /// How many banners arrived.
    banners: u64 = 0,
    /// How many bytes of banner arrived, before filtering.
    banner_bytes: u64 = 0,
    /// How many requests went out, the `none` request counted.
    attempts: u64 = 0,
    /// How many `SSH_MSG_USERAUTH_FAILURE` messages came back.
    failures: u64 = 0,
    /// How many of those said the method worked and more is needed.
    partial_successes: u64 = 0,
    /// How many times a `publickey` query was answered with a failure, so
    /// no signature was ever made.
    public_key_queries_refused: u64 = 0,
    /// How many times a `publickey` query was answered with
    /// `SSH_MSG_USERAUTH_SUCCESS`, which RFC 4252 section 7 does not
    /// allow and this build refuses. See `attemptPublicKey`.
    public_key_unproven: u64 = 0,
    /// How many `SSH_MSG_USERAUTH_INFO_REQUEST` messages were answered.
    info_requests: u64 = 0,
};

/// Why authentication stopped.
pub const Error =
    Transport.SendError ||
    Transport.ReceiveError ||
    userauth.BuildError ||
    userauth.ParseError ||
    signer_seam.Error ||
    error{
        /// `Options.key` and `Options.signer` were both set, so the run
        /// has two answers to one question. A caller's own bug, and an
        /// error rather than an assert because a caller outside this
        /// package can reach it.
        ///
        /// **Picking one silently is what this refuses to do.** The two
        /// can name two different keys, and a login with the wrong one
        /// would fail at the server with nothing said about why.
        TwoPublicKeySigners,
        /// `authenticate` ran before the transport had a session
        /// identifier. A caller's own bug, and it is an error rather than
        /// an assert because a caller outside this package can reach it.
        SessionNotEstablished,
        /// `Options.user` is empty.
        UserNameEmpty,
        /// The server would not start `ssh-userauth`.
        ServiceRefused,
        /// The server accepted a service that is not the one asked for.
        ServiceMismatch,
        /// A message arrived that belongs to no request this build sent.
        UnexpectedAuthMessage,
        /// A packet carried no payload, so it names no message.
        EmptyAuthPayload,
        /// Every method the caller could offer was tried and every one
        /// failed.
        AuthenticationFailed,
        /// The server named no method this build can run with the
        /// credentials the caller gave. `acceptedMethods` says what the
        /// server wanted.
        NoUsableAuthMethod,
        /// The server answered a `publickey` query with a key or an
        /// algorithm that is not the one this build sent.
        PublicKeyOkMismatch,
        /// The server answered a `publickey` query with
        /// `SSH_MSG_USERAUTH_SUCCESS`, so it logged this client in
        /// without ever asking it to prove it holds the private key. See
        /// `attemptPublicKey`.
        PublicKeyAcceptedUnproven,
        /// The server wants the password changed. See the module comment.
        PasswordChangeRequired,
        /// The server asked a `keyboard-interactive` question this build
        /// cannot answer. See the module comment.
        KeyboardInteractivePromptUnsupported,
        /// `Options.max_rounds`, `max_info_rounds`, or `max_banner_run`
        /// was reached.
        TooManyAuthRounds,
        /// More banner arrived than `max_banner_total_bytes`, or more
        /// than `max_banner_run` banners came before one reply.
        TooManyBanners,
    };

transport: *Transport,
options: Options,

/// Holds one request as it is built. **It holds a password in the clear
/// while a `password` request is built**, and every attempt wipes it.
request_storage: [max_request_bytes]u8,

/// The methods the last failure said can continue.
methods_storage: [userauth.max_method_list_bytes]u8,
methods_len: usize,

/// The last banner, filtered.
banner_storage: [userauth.max_banner_bytes]u8,
banner_len: usize,

/// Which methods have been offered already. A method is offered once,
/// because this build has one key and one password.
tried: std.EnumSet(userauth.Method),

/// Whether the last failure said the method worked and more is needed.
partial_success: bool,
/// Whether a `SSH_MSG_USERAUTH_SUCCESS` has arrived.
succeeded: bool,

counters: Counters,

/// Starts an authenticator over `transport`.
///
/// Initializes `a` in place, and not as a returned value, because
/// `banner` and `acceptedMethods` point into this value and because the
/// struct is kilobytes.
///
/// This writes nothing to the peer. `authenticate` does that.
pub fn init(a: *Authenticator, transport: *Transport, options: Options) void {
    a.transport = transport;
    a.options = options;
    a.methods_len = 0;
    a.banner_len = 0;
    a.tried = .initEmpty();
    a.partial_success = false;
    a.succeeded = false;
    a.counters = .{};
}

/// Wipes the request buffer.
///
/// **A `password` request passed through it in the clear.** Each attempt
/// wipes it as it leaves, and this wipes it again so that a caller who
/// stops part way through still leaves nothing behind.
pub fn deinit(a: *Authenticator) void {
    std.crypto.secureZero(u8, &a.request_storage);
    a.* = undefined;
}

/// Whether the server said yes.
pub fn authenticated(a: *const Authenticator) bool {
    return a.succeeded;
}

/// The methods the server's last failure named, as a name-list.
///
/// **Untrusted.** It is the server's own text. Empty before the first
/// failure.
pub fn acceptedMethods(a: *const Authenticator) []const u8 {
    return a.methods_storage[0..a.methods_len];
}

/// The last banner the server sent, filtered and safe to print.
///
/// Empty when no banner arrived. See `zurl_ssh.userauth.sanitizeBanner`
/// for what the filter takes out.
pub fn banner(a: *const Authenticator) []const u8 {
    return a.banner_storage[0..a.banner_len];
}

/// Whether the last failure said the method worked and the server wants
/// another one as well, RFC 4252 section 5.1.
pub fn partialSuccess(a: *const Authenticator) bool {
    return a.partial_success;
}

/// Runs the exchange.
///
/// On return the server has accepted the caller and the connection is
/// ready for the `ssh-connection` service, which a later task writes.
pub fn authenticate(a: *Authenticator) Error!void {
    if (a.options.user.len == 0) return error.UserNameEmpty;
    if (a.options.user.len > userauth.max_user_bytes) return error.UserNameTooLong;
    if (a.options.key != null and a.options.signer != null) return error.TwoPublicKeySigners;
    if (a.transport.sessionId() == null) return error.SessionNotEstablished;

    try a.requestService();

    // **`none` first, and always.** It is how the list of methods
    // arrives, and a server may answer it with a success for an account
    // that needs no credential.
    if (try a.attemptNone()) return;

    var rounds: usize = 0;
    while (a.nextMethod()) |method| {
        // **The bound is checked with a method in hand.** A run that
        // offered everything it had and was refused is
        // `AuthenticationFailed`, and only a run that still had something
        // to try is `TooManyAuthRounds`.
        if (rounds >= a.options.max_rounds) return error.TooManyAuthRounds;
        rounds += 1;
        a.tried.insert(method);
        const accepted = switch (method) {
            // `nextMethod` never names `none`. It is already sent, above,
            // and this build has one of each credential.
            .none => unreachable,
            .publickey => try a.attemptPublicKey(),
            .password => try a.attemptPassword(),
            .keyboard_interactive => try a.attemptKeyboardInteractive(),
        };
        if (accepted) return;
    }

    // **The two answers are not the same.** A caller with no credential
    // the server wants has something to fix, and a caller whose
    // credentials were refused has something else to fix.
    if (rounds == 0) return error.NoUsableAuthMethod;
    return error.AuthenticationFailed;
}

/// Asks the server to start `ssh-userauth`, RFC 4253 section 10.
fn requestService(a: *Authenticator) Error!void {
    const request = try userauth.writeServiceRequest(
        &a.request_storage,
        userauth.service_userauth,
    );
    try a.transport.send(request);

    const payload = try a.readReply();
    const id = userauth.idOf(payload) orelse return error.EmptyAuthPayload;
    if (id != .service_accept) return error.ServiceRefused;
    const service = try userauth.parseServiceAccept(payload);
    // An empty name is what a server that writes no name gives, and
    // `parseServiceAccept` says why that is allowed. A name that is
    // present and wrong is a server answering a question nobody asked.
    if (service.len != 0 and !std.mem.eql(u8, service, userauth.service_userauth)) {
        return error.ServiceMismatch;
    }
}

/// Sends the `none` request and reads the answer.
///
/// Returns true when the server accepted it.
fn attemptNone(a: *Authenticator) Error!bool {
    const request = try userauth.writeNoneRequest(&a.request_storage, a.options.user);
    a.counters.attempts += 1;
    try a.transport.send(request);
    a.tried.insert(.none);
    return a.readOutcome(.none);
}

/// The next method to offer, or null when there is none left.
///
/// **The server's list decides what is worth sending, and the caller's
/// credentials decide what can be sent.** A method that is on neither
/// side is a round trip that can only fail.
fn nextMethod(a: *const Authenticator) ?userauth.Method {
    const list: wire.NameList = .{ .text = a.acceptedMethods() };

    if (a.publicKeySigner() != null and
        !a.tried.contains(.publickey) and
        list.contains(userauth.Method.publickey.name()))
    {
        return .publickey;
    }
    if (a.options.password != null and
        !a.tried.contains(.password) and
        list.contains(userauth.Method.password.name()))
    {
        return .password;
    }
    if (a.options.password != null and
        a.options.allow_keyboard_interactive and
        !a.tried.contains(.keyboard_interactive) and
        list.contains(userauth.Method.keyboard_interactive.name()))
    {
        return .keyboard_interactive;
    }
    return null;
}

/// What signs a `publickey` attempt, or null when the caller gave
/// nothing to sign with.
///
/// `Options.key` is turned into a signer here, so the rest of this file
/// has one shape to read and never asks where the key lives.
/// `authenticate` has already refused a caller that set both fields.
fn publicKeySigner(a: *const Authenticator) ?Signer {
    if (a.options.signer) |held| return held;
    if (a.options.key) |key| return key.signer();
    return null;
}

/// Runs both phases of a `publickey` attempt, RFC 4252 section 7.
///
/// Returns true when the server accepted the signature.
fn attemptPublicKey(a: *Authenticator) Error!bool {
    // Nothing here is a secret: the session identifier, the public key,
    // and the signature all go on the wire. The buffer is wiped anyway, so
    // that one rule covers every attempt and nobody has to work out which
    // of them left a password behind.
    defer std.crypto.secureZero(u8, &a.request_storage);

    const signer = a.publicKeySigner().?;
    const params: userauth.PublicKeyParams = .{
        .user = a.options.user,
        .algorithm = signer.algorithm,
        .key_blob = signer.public_blob,
    };

    // **Phase one asks whether the key would be taken, and signs
    // nothing.** A server with a long list of keys to check answers this
    // with a failure and no signing work is wasted. RFC 4252 section 7
    // calls it the query.
    const query = try userauth.writePublicKeyQuery(&a.request_storage, params);
    a.counters.attempts += 1;
    try a.transport.send(query);

    const payload = try a.readReply();
    const id = userauth.idOf(payload) orelse return error.EmptyAuthPayload;
    switch (id) {
        .success => {
            // **A query is a question, and this is a yes to a question
            // nobody proved the answer to.** RFC 4252 section 7 gives
            // the server two answers to a query: a failure, or
            // `SSH_MSG_USERAUTH_PK_OK`. A success is neither.
            //
            // The server is the party that loses by taking a key with no
            // signature, and it has already decided, so this costs the
            // client nothing it can measure. It is refused anyway. The
            // cost of taking it is a path where `succeeded` is true and
            // no signature was ever made, and a rule that says yes to
            // something it never proved is how the next defect gets in.
            // A broken or hostile server is also caught here rather than
            // three messages later.
            a.counters.public_key_unproven += 1;
            return error.PublicKeyAcceptedUnproven;
        },
        .failure => {
            try a.recordFailure(payload);
            a.counters.public_key_queries_refused += 1;
            return false;
        },
        .method_specific => {
            const ok = try userauth.parsePublicKeyOk(payload);
            // **The server must echo what it was sent.** A server that
            // names another key is answering about a key this build did
            // not offer, and signing after that would prove nothing about
            // this exchange.
            if (!std.mem.eql(u8, ok.algorithm, params.algorithm)) {
                return error.PublicKeyOkMismatch;
            }
            if (!std.mem.eql(u8, ok.key_blob, params.key_blob)) {
                return error.PublicKeyOkMismatch;
            }
        },
        else => return error.UnexpectedAuthMessage,
    }

    // Phase two: the signature over the session identifier and the
    // request. See `zurl_ssh.userauth.writeSignatureBlob`.
    const session_id = a.transport.sessionId() orelse return error.SessionNotEstablished;
    const signed = try userauth.writeSignatureBlob(&a.request_storage, session_id, params);

    var signature_storage: [privatekey.max_signature_bytes]u8 = undefined;
    const signature = try signer.sign(signer.ctx, signed.blob, &signature_storage);
    const request = try userauth.finishPublicKeyRequest(&a.request_storage, signed, signature);

    a.counters.attempts += 1;
    try a.transport.send(request);
    return a.readOutcome(.publickey);
}

/// Runs a `password` attempt, RFC 4252 section 8.
fn attemptPassword(a: *Authenticator) Error!bool {
    const password = a.options.password.?;
    // **The request holds the password in the clear until it is
    // encrypted.** The packet goes out under the transport's cipher, and
    // this buffer is wiped whichever way this function leaves.
    defer std.crypto.secureZero(u8, &a.request_storage);

    const request = try userauth.writePasswordRequest(
        &a.request_storage,
        a.options.user,
        password,
    );
    a.counters.attempts += 1;
    try a.transport.send(request);
    return a.readOutcome(.password);
}

/// Runs a `keyboard-interactive` attempt, RFC 4256.
///
/// **This build answers one hidden question with the password, and
/// nothing else.** A server that asks two questions wants two different
/// answers, and sending the password twice would put it where the server
/// asked for something else. A request with no question at all is
/// answered with no answers, which is what RFC 4256 section 3.3 says an
/// informational message gets.
fn attemptKeyboardInteractive(a: *Authenticator) Error!bool {
    const password = a.options.password.?;
    defer std.crypto.secureZero(u8, &a.request_storage);

    const request = try userauth.writeKeyboardInteractiveRequest(
        &a.request_storage,
        a.options.user,
        "",
    );
    a.counters.attempts += 1;
    try a.transport.send(request);

    var rounds: usize = 0;
    while (rounds < max_info_rounds) : (rounds += 1) {
        const payload = try a.readReply();
        const id = userauth.idOf(payload) orelse return error.EmptyAuthPayload;
        switch (id) {
            .success => {
                try userauth.parseSuccess(payload);
                a.succeeded = true;
                return true;
            },
            .failure => {
                try a.recordFailure(payload);
                return false;
            },
            .method_specific => {
                const info = try userauth.parseInfoRequest(payload);
                a.counters.info_requests += 1;
                const answer = try a.answerInfoRequest(info, password);
                try a.transport.send(answer);
            },
            else => return error.UnexpectedAuthMessage,
        }
    }
    return error.TooManyAuthRounds;
}

/// Builds the answer to one `SSH_MSG_USERAUTH_INFO_REQUEST`.
///
/// The result points into `request_storage`, which `attemptKeyboardInteractive`
/// wipes.
fn answerInfoRequest(
    a: *Authenticator,
    info: userauth.InfoRequest,
    password: []const u8,
) Error![]u8 {
    if (info.prompt_count == 0) {
        return userauth.writeInfoResponse(&a.request_storage, &.{});
    }
    if (info.prompt_count != 1) return error.KeyboardInteractivePromptUnsupported;

    var it = info.iterator();
    const prompt = (try it.next()) orelse return error.KeyboardInteractivePromptUnsupported;
    // A question the server wants echoed is not a password. It is a token,
    // a one time code, or a yes or no, and this build has none of them.
    if (prompt.echo) return error.KeyboardInteractivePromptUnsupported;
    return userauth.writeInfoResponse(&a.request_storage, &.{password});
}

/// Reads the answer to one request and says whether it was a success.
fn readOutcome(a: *Authenticator, method: userauth.Method) Error!bool {
    const payload = try a.readReply();
    const id = userauth.idOf(payload) orelse return error.EmptyAuthPayload;
    switch (id) {
        .success => {
            try userauth.parseSuccess(payload);
            a.succeeded = true;
            return true;
        },
        .failure => {
            try a.recordFailure(payload);
            return false;
        },
        .method_specific => {
            // **Message 60 belongs to whichever method is in flight**, so
            // the method decides what this is. See
            // `zurl_ssh.userauth.Id`.
            if (method == .password) {
                // `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ`. It is read so that
                // a malformed one is still a named fault, and then it is
                // refused. See the module comment.
                _ = try userauth.parsePasswordChangeRequest(payload);
                return error.PasswordChangeRequired;
            }
            return error.UnexpectedAuthMessage;
        },
        else => return error.UnexpectedAuthMessage,
    }
}

/// Reads until a message that is not a banner arrives.
///
/// **A banner may arrive at any moment**, RFC 4252 section 5.4, so every
/// read here has to expect one. It is filtered, counted, and handed to the
/// caller's sink.
fn readReply(a: *Authenticator) Error![]const u8 {
    var run: usize = 0;
    while (run < max_banner_run) : (run += 1) {
        const payload = try a.transport.receive();
        const id = userauth.idOf(payload) orelse return error.EmptyAuthPayload;
        if (id == .banner) {
            try a.recordBanner(payload);
            continue;
        }
        return payload;
    }
    return error.TooManyBanners;
}

/// Filters one banner, keeps it, and hands it to the caller's sink.
fn recordBanner(a: *Authenticator, payload: []const u8) Error!void {
    const parsed = try userauth.parseBanner(payload);
    a.counters.banners += 1;
    a.counters.banner_bytes += parsed.message.len;
    // **A server that writes banners forever is bounded by the total.**
    // The count in one run and the bytes in the whole exchange are two
    // different ways to spend this process's time, and both are closed.
    if (a.counters.banner_bytes > max_banner_total_bytes) return error.TooManyBanners;

    // The filter never grows the text: a byte it will not pass becomes one
    // replacement byte, and a byte it passes is copied as it is. So the
    // storage is the same size as the bound on one banner.
    const safe = userauth.sanitizeBanner(&a.banner_storage, parsed.message);
    a.banner_len = safe.len;
    if (a.options.banner) |sink| sink.show(sink.ctx, safe);
}

/// Keeps what a `SSH_MSG_USERAUTH_FAILURE` said.
fn recordFailure(a: *Authenticator, payload: []const u8) Error!void {
    const failure = try userauth.parseFailure(payload);
    // `parseFailure` refuses a list longer than the storage, so this is an
    // invariant of this package and not a claim about the peer.
    std.debug.assert(failure.methods.text.len <= a.methods_storage.len);

    @memcpy(a.methods_storage[0..failure.methods.text.len], failure.methods.text);
    a.methods_len = failure.methods.text.len;
    a.partial_success = failure.partial_success;
    a.counters.failures += 1;
    if (failure.partial_success) a.counters.partial_successes += 1;
}

const testing = std.testing;

test "the request buffer holds the largest request this build sends" {
    // The signed `publickey` request is the largest, and it is the one
    // that must fit. A bound that was too small would show up as
    // `error.NoSpaceLeft` against a real server and never in a fixture.
    const largest =
        4 + 64 + // the session identifier, with room for a longer hash
        1 + // the message number
        4 + userauth.max_user_bytes +
        4 + userauth.service_connection.len +
        4 + userauth.Method.keyboard_interactive.name().len +
        1 + // the boolean
        4 + "ssh-ed25519".len +
        4 + privatekey.max_public_blob_bytes +
        4 + privatekey.max_signature_bytes;
    try testing.expect(largest <= max_request_bytes);

    // And a `password` request, which is the other long one.
    const password_request =
        1 +
        4 + userauth.max_user_bytes +
        4 + userauth.service_connection.len +
        4 + userauth.Method.password.name().len +
        1 +
        4 + userauth.max_password_bytes;
    try testing.expect(password_request <= max_request_bytes);
}

test "the banner storage holds a whole banner after the filter" {
    // The filter never grows the text, so one bound covers both.
    var out: [userauth.max_banner_bytes]u8 = undefined;
    const input: [userauth.max_banner_bytes]u8 = @splat(0x1b);
    const safe = userauth.sanitizeBanner(&out, &input);
    try testing.expectEqual(input.len, safe.len);
}
