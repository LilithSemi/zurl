//! One connection to an SSH agent, over a unix domain socket.
//!
//! **This is what lets a program authenticate without ever reading a key
//! file.** The agent holds the private key. This process asks it what keys
//! it has, picks one it can use, and asks for a signature over the bytes
//! RFC 4252 section 7 covers. No secret crosses the socket in either
//! direction, and nothing here can wipe a key because nothing here holds
//! one.
//!
//! `zurl_ssh.agent` owns the bytes, `zurl_net.unix` owns the dial, and
//! this file is the two together plus the state one exchange needs. The
//! signature it gets back reaches `zurl_ssh.Authenticator` through
//! `zurl_ssh.signer.Signer`, so the authenticator runs the same code for
//! an agent key and for a key on disk.
//!
//! A caller wires one up like this:
//!
//!     var client: zurl_ssh.AgentClient = undefined;
//!     try client.connect(io, socket_path, .{});
//!     defer client.close();
//!     _ = try client.selectIdentity();
//!     authenticator.init(transport, .{
//!         .user = "git",
//!         .signer = client.signer(),
//!     });
//!
//! **The caller passes the socket path, and this file reads no environment
//! variable.** `SSH_AUTH_SOCK` is the convention and
//! `zurl_ssh.agent.auth_socket_variable` names it, but the read belongs to
//! the program. `zurl_core.proxy.Env` and `zurl.proxyFromEnv` divide the
//! proxy variables the same way and for the same reason: a library that
//! read the environment itself would reach past a development shell that
//! curated it.
//!
//! **RSA is not a limit here.** The agent signs, so a login through an
//! agent needs no RSA signer from `std.crypto`, and an RSA key in the
//! agent would work if `zurl_ssh.agent.Identity.usable` were widened to
//! name it. RSA remains a limit on **host key verification**, which is the
//! different and still unsolved problem in `zurl_ssh.hostkey`.
//!
//! **An `AgentClient` must not move once `connect` has run**, and it is
//! tens of kilobytes, so it belongs on the heap or in a static. The
//! reader and the writer hold pointers into it, and so does every slice
//! `identity` and `signer` give back. `zurl_ssh.Authenticator` keeps the
//! same two rules.

const AgentClient = @This();

const std = @import("std");
const zurl_net = @import("zurl-net");

const agent = @import("agent.zig");
const signer_seam = @import("signer.zig");

const Signer = signer_seam.Signer;

/// How many bytes of one answer this client will hold.
///
/// **This is smaller than `zurl_ssh.agent.max_message_bytes`**, which is
/// what the protocol and OpenSSH's own agent allow. The larger bound is
/// what an answer may claim; this is what this client keeps a buffer for,
/// and an answer over it is `error.AgentAnswerTooLong` rather than a read
/// that goes somewhere it should not. It holds several hundred
/// `ssh-ed25519` identities, and far more than any agent a person runs.
pub const max_answer_bytes = 32 * 1024;

/// How many bytes of data one signature request may carry.
///
/// The data is the blob of RFC 4252 section 7, which
/// `zurl_ssh.Authenticator` builds inside its own
/// `max_request_bytes` of 2048, so no caller in this package can reach
/// this.
pub const max_sign_data_bytes = 4096;

/// How many bytes of key blob this client keeps for the identity it chose.
///
/// An `ssh-ed25519` blob is 51 bytes. A blob larger than this belongs to
/// a key this build cannot use anyway, and the filter walks past it inside
/// the answer buffer, so it never needs room here.
pub const max_key_blob_bytes = 1024;

/// How many bytes one request may be, the length field counted.
const max_request_bytes = 4 + 1 + 4 + max_key_blob_bytes + 4 + max_sign_data_bytes + 4;

/// How many bytes the socket reader and the socket writer each buffer.
const stream_buffer_bytes = 4096;

/// How long one read waits with no byte arriving, unless the caller says
/// otherwise.
///
/// **A minute is long because an agent may be waiting for a person.**
/// OpenSSH adds a key with `ssh-add -c`, and every signature with that key
/// puts a confirmation prompt in front of the user. The agent writes
/// nothing until the user answers, and a bound of a few seconds would turn
/// a slow answer into a failed login.
pub const default_stall: std.Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(60), .clock = .awake },
};

/// What one agent connection needs.
pub const Options = struct {
    /// How long one read waits with no byte arriving. See
    /// `default_stall`.
    stall: std.Io.Timeout = default_stall,
};

/// What the exchange did that no caller asked for.
///
/// **Recovery is never silent.** The filter walks past keys, and this is
/// where a caller sees how many and why.
pub const Counters = struct {
    /// How many times the list of identities was asked for.
    identity_requests: u64 = 0,
    /// How many identities the agent listed, over every request.
    identities_seen: u64 = 0,
    /// How many of those this build cannot sign with, so the filter
    /// walked past them.
    ///
    /// **A key of another type is not a fault**, and this counter is what
    /// keeps that from being silent. A login that failed with an agent
    /// full of RSA keys reads here.
    identities_skipped: u64 = 0,
    /// How many signatures were asked for.
    sign_requests: u64 = 0,
    /// How many of those the agent refused.
    sign_refusals: u64 = 0,
};

/// Why an exchange with the agent stopped.
pub const Error =
    std.Io.Writer.Error ||
    zurl_net.bounded.ExactError ||
    agent.BuildError ||
    agent.ParseError ||
    error{
        /// A request was made before `connect`, or after `close`.
        AgentNotConnected,
        /// A signature was asked for before `selectIdentity` picked a
        /// key.
        AgentIdentityNotSelected,
        /// The agent's answer is longer than `max_answer_bytes`. **No
        /// byte of it is read**: the length field says so before the
        /// body arrives.
        AgentAnswerTooLong,
        /// The agent wrote a length of zero, so the answer names no
        /// message at all.
        EmptyAgentAnswer,
        /// The key blob of the identity the filter chose is longer than
        /// `max_key_blob_bytes`.
        KeyBlobTooLongToKeep,
    };

io: std.Io,
stream: std.Io.net.Stream,
connected: bool,
stall: std.Io.Timeout,

reader: std.Io.net.Stream.Reader,
writer: std.Io.net.Stream.Writer,
read_storage: [stream_buffer_bytes]u8,
write_storage: [stream_buffer_bytes]u8,

request_storage: [max_request_bytes]u8,
answer_storage: [max_answer_bytes]u8,

/// The blob of the identity `selectIdentity` chose. Empty until it runs.
key_blob_storage: [max_key_blob_bytes]u8,
key_blob_len: usize,
/// How many bytes of `key_blob_storage` the algorithm name takes, and
/// where inside the blob it starts. RFC 4253 section 6.6 puts it first, as
/// a string, so the name is the four length bytes in and this long.
algorithm_len: usize,

/// The last fault an exchange hit, by its own name, or null.
///
/// **This is where the detail goes that `zurl_ssh.signer.Error` has no
/// room for.** That set has three names, because an authenticator has
/// three things to do about a signature that did not happen. A caller that
/// reports a fault to a person reads this instead, the way a caller reads
/// `zurl_net.tcp.DialOptions.no_delay_error`.
///
/// Nothing clears it but `connect`, so a fault of one exchange stays
/// readable through the next.
fault: ?Error,

counters: Counters,

/// Opens a connection to the agent listening at `path`.
///
/// Initializes `c` in place, and not as a returned value, because the
/// reader and the writer hold pointers into it and because the struct is
/// tens of kilobytes.
///
/// `path` is the caller's to find. `zurl_ssh.agent.auth_socket_variable`
/// names the variable that holds it by convention, and this function reads
/// no environment.
pub fn connect(
    c: *AgentClient,
    io: std.Io,
    path: []const u8,
    options: Options,
) zurl_net.unix.DialError!void {
    c.stream = try zurl_net.unix.dial(io, path);
    c.io = io;
    c.connected = true;
    c.stall = options.stall;
    c.reader = .init(c.stream, io, &c.read_storage);
    c.writer = .init(c.stream, io, &c.write_storage);
    c.key_blob_len = 0;
    c.algorithm_len = 0;
    c.fault = null;
    c.counters = .{};
}

/// Closes the connection.
///
/// **Safe to call twice**, so a caller may `defer` it beside a path that
/// closes early. Nothing here is wiped, because nothing here is a secret:
/// the buffers held public keys, a signature, and the blob of RFC 4252
/// section 7, all of which go on the wire in the clear inside the SSH
/// packet stream.
pub fn close(c: *AgentClient) void {
    if (!c.connected) return;
    c.stream.close(c.io);
    c.connected = false;
}

/// The public key blob of the identity `selectIdentity` chose, or null
/// before it runs.
///
/// The slice points into this value, so it lives for as long as this value
/// does and until the next `selectIdentity`.
///
/// **The comment is not kept and this does not give one back.** It points
/// into the answer buffer, which the next exchange writes over, so
/// `selectIdentity` hands it to a caller that wants it and nothing holds
/// it after that.
pub fn publicBlob(c: *const AgentClient) ?[]const u8 {
    if (c.key_blob_len == 0) return null;
    return c.keyBlob();
}

/// This client as the signer `zurl_ssh.Authenticator` takes, or null
/// before `selectIdentity` has chosen a key.
///
/// **Null is the answer and not an assert**, because a caller that offers
/// a signer with no key behind it would get a refusal from the server and
/// no idea why. `Authenticator.Options.signer` takes the optional
/// straight, so a caller writes `.signer = client.signer()` and a client
/// with no usable key offers no `publickey` attempt at all.
///
/// The client must outlive the signer, and `selectIdentity` must not run
/// again while one is in use: the two slices point into this value.
pub fn signer(c: *AgentClient) ?Signer {
    if (c.key_blob_len == 0) return null;
    return .{
        .ctx = c,
        .algorithm = c.algorithmName(),
        .public_blob = c.keyBlob(),
        .sign = signForSigner,
    };
}

/// Asks the agent for its keys and keeps the first one this build can sign
/// with.
///
/// **A key of another type is walked past and never refused.** An agent
/// commonly holds an RSA key beside an `ssh-ed25519` one, and a client
/// that stopped at the first name it did not know would fail for a user
/// whose agent is set up correctly. `Counters.identities_skipped` counts
/// what was walked past, so the recovery is not silent.
///
/// An agent holding no key this build can use is
/// `error.NoUsableIdentity`, which is its own name and never an empty
/// success.
pub fn selectIdentity(c: *AgentClient) Error!agent.Identity {
    return c.selectIdentityFallible() catch |err| {
        c.fault = err;
        return err;
    };
}

fn selectIdentityFallible(c: *AgentClient) Error!agent.Identity {
    if (!c.connected) return error.AgentNotConnected;

    const request = try agent.writeRequestIdentities(&c.request_storage);
    c.counters.identity_requests += 1;
    try c.send(request);

    const answer = try c.receive();
    var it = try agent.parseIdentitiesAnswer(answer);
    while (try it.next()) |candidate| {
        c.counters.identities_seen += 1;
        if (!candidate.usable()) {
            c.counters.identities_skipped += 1;
            continue;
        }
        // The blob is copied out of the answer buffer, because the next
        // exchange writes over that buffer and the signer hands this
        // slice to a `publickey` request long after.
        if (candidate.key_blob.len > max_key_blob_bytes) return error.KeyBlobTooLongToKeep;
        @memcpy(c.key_blob_storage[0..candidate.key_blob.len], candidate.key_blob);
        c.key_blob_len = candidate.key_blob.len;
        // `usable` already read the name, so this cannot fail. It is read
        // again rather than asserted, because the answer came from the
        // agent and no byte of it is this build's own business to be sure
        // about.
        const name = (agent.Identity{
            .key_blob = c.keyBlob(),
            .comment = "",
        }).algorithm() orelse return error.UnexpectedAgentMessage;
        c.algorithm_len = name.len;
        return .{ .key_blob = c.keyBlob(), .comment = candidate.comment };
    }
    return error.NoUsableIdentity;
}

/// Asks the agent to sign `message` with the identity `selectIdentity`
/// chose, and writes the signature blob into `out`.
///
/// The blob is the wire form of RFC 4253 section 6.6, which is what
/// `zurl_ssh.userauth.finishPublicKeyRequest` puts on the wire. The answer
/// points into `out`.
///
/// **`message` is every byte RFC 4252 section 7 covers**, the session
/// identifier at the front included.
///
/// The flags are `zurl_ssh.agent.Flags.none`, which is what an
/// `ssh-ed25519` key takes. Both flags
/// draft-miller-ssh-agent-04 section 4.5.1 defines are for `ssh-rsa` keys,
/// and this build offers no RSA key to sign with.
pub fn sign(c: *AgentClient, message: []const u8, out: []u8) Error![]u8 {
    return c.signFallible(message, out) catch |err| {
        c.fault = err;
        return err;
    };
}

fn signFallible(c: *AgentClient, message: []const u8, out: []u8) Error![]u8 {
    if (!c.connected) return error.AgentNotConnected;
    if (c.key_blob_len == 0) return error.AgentIdentityNotSelected;
    if (message.len > max_sign_data_bytes) return error.SignDataTooLong;

    const request = try agent.writeSignRequest(
        &c.request_storage,
        c.keyBlob(),
        message,
        agent.Flags.none,
    );
    c.counters.sign_requests += 1;
    try c.send(request);

    const answer = try c.receive();
    const signature = agent.parseSignResponse(answer) catch |err| {
        if (err == error.AgentRefused) c.counters.sign_refusals += 1;
        return err;
    };
    if (signature.len > out.len) return error.NoSpaceLeft;
    @memcpy(out[0..signature.len], signature);
    return out[0..signature.len];
}

/// The blob of the identity that was chosen.
fn keyBlob(c: *const AgentClient) []const u8 {
    return c.key_blob_storage[0..c.key_blob_len];
}

/// The algorithm name inside that blob. RFC 4253 section 6.6 puts it
/// first, as a string, so it starts four bytes in.
fn algorithmName(c: *const AgentClient) []const u8 {
    return c.key_blob_storage[4..][0..c.algorithm_len];
}

/// Writes one whole message and pushes it out of this process.
fn send(c: *AgentClient, message: []const u8) std.Io.Writer.Error!void {
    try c.writer.interface.writeAll(message);
    return c.writer.interface.flush();
}

/// Reads one whole message and returns its body: the type byte and
/// everything after it, with the length field of
/// draft-miller-ssh-agent-04 section 3 taken off.
///
/// **The length is checked against `max_answer_bytes` before one byte of
/// the body is read.** An agent that claims four thousand million bytes
/// costs this process one comparison and no memory at all. Every length
/// inside the body is the business of `zurl_ssh.agent`, which checks each
/// one against what is left.
///
/// The answer points into this value and the next call writes over it.
fn receive(c: *AgentClient) Error![]const u8 {
    var header: [4]u8 = undefined;
    try zurl_net.bounded.readExact(&c.reader.interface, c.io, &header, c.stall);
    const declared = std.mem.readInt(u32, &header, .big);
    if (declared == 0) return error.EmptyAgentAnswer;
    if (declared > max_answer_bytes) return error.AgentAnswerTooLong;

    const body = c.answer_storage[0..declared];
    try zurl_net.bounded.readExact(&c.reader.interface, c.io, body, c.stall);
    return body;
}

/// `sign` behind the function pointer a `Signer` carries.
///
/// **The detail is kept and not thrown away.** `zurl_ssh.signer.Error` has
/// three names because an authenticator has three things to do, and the
/// name of what actually happened goes in `fault` on the way past.
fn signForSigner(ctx: ?*anyopaque, message: []const u8, out: []u8) signer_seam.Error![]u8 {
    const c: *AgentClient = @ptrCast(@alignCast(ctx.?));
    return c.sign(message, out) catch |err| switch (err) {
        // The agent has the key and said no. Section 4.5 gives this for
        // a key it does not hold, for flags it does not support, and for
        // a user who would not confirm.
        error.AgentRefused => error.SignerRefused,
        // The caller's buffer is too small for the blob that came back.
        error.NoSpaceLeft => error.NoSpaceLeft,
        // Everything else is the agent not answering in a way this build
        // can use: a socket that closed, a read that stalled, an answer
        // that did not parse.
        else => error.SignerUnavailable,
    };
}
