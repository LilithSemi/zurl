//! The SSH agent protocol, draft-miller-ssh-agent-04. Pure bytes, and
//! testable with a table.
//!
//! An agent holds private keys and signs on their behalf. A client that
//! talks to one never reads a key file, never holds a private key in its
//! own memory, and needs no signer for the key's algorithm, because the
//! agent does the signing. `zurl_ssh.AgentClient` carries this module over
//! a unix domain socket.
//!
//! What this module owns: the message numbers, the two request builders,
//! the two answer parsers, and the filter that picks a key this build can
//! use out of everything an agent holds.
//!
//! What this module does not own: it opens no socket, it holds no state,
//! and it reads no environment variable. `zurl_ssh.AgentClient` does the
//! I/O, and `auth_socket_variable` names the variable a caller reads for
//! itself.
//!
//! **This protocol reuses the wire types of RFC 4251 section 5**, which
//! draft-miller-ssh-agent-04 section 3 says in as many words, so
//! `zurl_ssh.wire` reads and writes every field here.
//!
//! **Every byte an answer carries came from the agent.** The agent is a
//! separate program on the far side of a socket, and every length in its
//! answer was written by something that is not this process. So each
//! parser here is a `wire.Reader` walk with a bound in front of it, and
//! nothing in this file asserts on what an answer holds. A malformed
//! answer is a named refusal.
//!
//! **RSA is not a limit on this path.** The agent signs, so a client
//! authenticating through an agent needs no RSA signer from `std.crypto`,
//! and an RSA key in the agent would work if the filter here were widened
//! to name it. RSA is still a limit on **host key verification**, which is
//! a different problem in `zurl_ssh.hostkey` and stays unsolved. The two
//! must not be read as one.

const std = @import("std");

const privatekey = @import("privatekey.zig");
const wire = @import("wire.zig");

/// The environment variable that names the agent's socket, by the
/// convention OpenSSH set.
///
/// **This module reads no environment variable, and neither does
/// `zurl_ssh.AgentClient`.** The name is here so that a caller has one
/// spelling to read and no reason to invent a second. The read itself
/// belongs to the program, which is the same division
/// `zurl_core.proxy.Env` keeps for the proxy variables: that type names
/// them and documents the precedence, and `zurl.proxyFromEnv` and the CLI
/// do the reading.
///
/// A library that read the environment itself would reach past whatever
/// its caller set up, and a curated development shell that names one agent
/// could not stop it.
pub const auth_socket_variable = "SSH_AUTH_SOCK";

/// The message numbers of draft-miller-ssh-agent-04 section 5.1.
///
/// Only the numbers this build sends or reads are named. The agent writes
/// this byte, so the enum is non-exhaustive: `@enumFromInt` on a
/// non-exhaustive enum is defined for every one of the 256 values an agent
/// can write, and `zurl_ssh.messages.Id` keeps the same rule for the same
/// reason.
pub const Id = enum(u8) {
    /// A refusal, and a legal answer to every request in this file.
    /// Section 4.1 also gives it to a request whose type the agent does
    /// not know.
    failure = 5,
    /// A generic yes. No request this build sends is answered with it.
    success = 6,
    /// Section 4.4. The client asks what keys the agent holds.
    request_identities = 11,
    /// Section 4.4. The answer to `request_identities`.
    identities_answer = 12,
    /// Section 4.5. The client asks the agent to sign.
    sign_request = 13,
    /// Section 4.5. The answer to `sign_request`.
    sign_response = 14,
    _,
};

/// The signature flags of draft-miller-ssh-agent-04 section 5.3.
///
/// **This build sends `none`.** Both named flags are valid for `ssh-rsa`
/// keys only, and section 4.5.1 says so, so a flag on an `ssh-ed25519`
/// request asks the agent for something that does not exist. Section 5.3
/// also reserves the value 1 for historical implementations, and nothing
/// here sends it.
pub const Flags = struct {
    /// No flag at all, which is what an `ssh-ed25519` request carries.
    pub const none: u32 = 0;
    /// Ask an `ssh-rsa` key for an `rsa-sha2-256` signature.
    pub const rsa_sha2_256: u32 = 2;
    /// Ask an `ssh-rsa` key for an `rsa-sha2-512` signature.
    pub const rsa_sha2_512: u32 = 4;
};

/// How many bytes the length field in front of a message counts, at most.
///
/// Section 3 puts a `uint32` in front of every message, so an agent may
/// claim any of four thousand million bytes. **The claim is checked
/// against this before one byte of the body is read**, so an agent that
/// lies about a size costs this process one comparison and never a read.
///
/// OpenSSH's own agent refuses a message over 256 kilobytes, and this is
/// that bound. An answer larger than it is `error.AgentMessageTooLong`.
pub const max_message_bytes = 256 * 1024;

/// How many identities one answer may list.
///
/// Section 4.4 lets an agent write any `nkeys` a `uint32` holds. Each key
/// costs a walk over two strings, so a count this build will not walk is
/// refused by name instead of looped over. OpenSSH's agent holds far fewer
/// than this in practice.
pub const max_identities = 2048;

/// How many bytes of key blob this build will take from an agent.
///
/// An `ssh-ed25519` blob is 51 bytes. This is much larger, because an
/// agent lists every key it holds and the filter has to walk past an RSA
/// key and a certificate to find the one it wants.
pub const max_key_blob_bytes = 8192;

/// How many bytes of data one signature request may carry.
///
/// The data is the blob RFC 4252 section 7 signs, which
/// `zurl_ssh.userauth.writeSignatureBlob` builds inside
/// `zurl_ssh.Authenticator.max_request_bytes`. This is larger than that,
/// so no caller in this package can reach it.
pub const max_sign_data_bytes = 8192;

/// How many bytes a signature blob may carry.
///
/// The blob is the form of RFC 4253 section 6.6: the algorithm name and
/// then the signature, each as a string. An `ssh-ed25519` blob is 83
/// bytes. An RSA-4096 one is near 530.
pub const max_signature_bytes = 2048;

/// Why a request could not be built.
pub const BuildError = wire.WriteError || error{
    /// The key blob is longer than `max_key_blob_bytes`.
    KeyBlobTooLong,
    /// The data to sign is longer than `max_sign_data_bytes`.
    SignDataTooLong,
    /// The message is longer than `max_message_bytes`, so the length
    /// field of section 3 cannot carry it to an agent that keeps the same
    /// bound. No caller in this package can reach it, because
    /// `max_key_blob_bytes` and `max_sign_data_bytes` together are far
    /// under it, and it is checked anyway.
    MessageTooLong,
};

/// How many bytes `writeRequestIdentities` writes.
///
/// The length field, and one byte of message. Section 3 counts the type
/// byte inside the length and not the length field itself.
pub const request_identities_bytes = 4 + 1;

/// Builds `SSH_AGENTC_REQUEST_IDENTITIES`, section 4.4, framed as section 3
/// frames every message.
///
///     uint32                  message length
///     byte                    SSH_AGENTC_REQUEST_IDENTITIES
///
/// The length counts the type byte and everything after it, which is one
/// byte here.
pub fn writeRequestIdentities(out: []u8) BuildError![]u8 {
    var w: wire.Writer = .init(out);
    try w.uint32(1);
    try w.byte(@intFromEnum(Id.request_identities));
    return w.written();
}

/// Builds `SSH_AGENTC_SIGN_REQUEST`, section 4.5, framed as section 3
/// frames every message.
///
///     uint32                  message length
///     byte                    SSH_AGENTC_SIGN_REQUEST
///     string                  key blob
///     string                  data
///     uint32                  flags
///
/// `key_blob` names which key signs, and it is the blob the agent listed
/// in its identities answer. `data` is what the agent signs, which for a
/// login is the blob of RFC 4252 section 7. `flags` is
/// `Flags.none` for an `ssh-ed25519` key.
///
/// **The length is written last, over the four bytes left for it**, so it
/// counts what was actually written rather than what the caller thought
/// it would be.
pub fn writeSignRequest(
    out: []u8,
    key_blob: []const u8,
    data: []const u8,
    flags: u32,
) BuildError![]u8 {
    if (key_blob.len > max_key_blob_bytes) return error.KeyBlobTooLong;
    if (data.len > max_sign_data_bytes) return error.SignDataTooLong;

    var w: wire.Writer = .init(out);
    try w.uint32(0);
    const body_at = w.at;
    try w.byte(@intFromEnum(Id.sign_request));
    try w.string(key_blob);
    try w.string(data);
    try w.uint32(flags);

    const written = w.written();
    const body_len = written.len - body_at;
    if (body_len > max_message_bytes) return error.MessageTooLong;
    std.mem.writeInt(u32, written[0..4], @intCast(body_len), .big);
    return written;
}

/// Why an answer could not be read.
pub const ParseError = wire.ReadError || error{
    /// The agent answered `SSH_AGENT_FAILURE`. Section 4.5 lists the
    /// reasons for a signature: the agent does not hold the key, it does
    /// not support the flags, or the user refused to confirm a
    /// constrained key.
    ///
    /// **This is the agent saying no, and it is not a protocol fault.** A
    /// caller reports it as a refusal and never retries it as a transient
    /// error.
    AgentRefused,
    /// The first byte names a message this build did not ask for.
    UnexpectedAgentMessage,
    /// The answer says it holds more than `max_identities` keys.
    TooManyIdentities,
    /// A key blob is longer than `max_key_blob_bytes`.
    KeyBlobTooLong,
    /// A signature blob is longer than `max_signature_bytes`.
    SignatureTooLong,
    /// The agent holds no key with an algorithm this build can use.
    ///
    /// **This is its own name, and it is never an empty success.** An
    /// agent with no usable key and an agent that was never asked look the
    /// same to a caller that gets back an empty list, and the second one
    /// is a bug in this file. See `firstUsableIdentity`.
    NoUsableIdentity,
};

/// One key an agent holds, section 4.4.
///
/// Both slices point into the answer buffer they were read from, so they
/// are valid for only as long as that buffer holds the answer. A caller
/// that keeps one past the next request copies it first.
pub const Identity = struct {
    /// The wire encoding of the public key, RFC 4253 section 6.6: the
    /// algorithm name as a string, and then the algorithm's own fields.
    key_blob: []const u8,
    /// A human readable comment, which section 4.4 says is UTF-8.
    ///
    /// **Untrusted, and not filtered.** It is text the agent chose, and a
    /// caller that prints it filters it first. `zurl_ssh.userauth.
    /// sanitizeBanner` is the filter this package already keeps for text
    /// a peer wrote.
    comment: []const u8,

    /// The algorithm name inside `key_blob`, or null when the blob does
    /// not start with a string.
    ///
    /// A blob that does not parse is null rather than an error, because
    /// the walk that calls this is a filter. See `Iterator`.
    pub fn algorithm(identity: Identity) ?[]const u8 {
        var r: wire.Reader = .init(identity.key_blob);
        return r.string() catch null;
    }

    /// Whether this build can sign with a key of this type.
    ///
    /// True for `ssh-ed25519` and nothing else, which is the one host key
    /// and client key algorithm this build carries. See
    /// `zurl_ssh.privatekey.Algorithm`, which holds that list, so widening
    /// it there widens it here as well.
    pub fn usable(identity: Identity) bool {
        const name = identity.algorithm() orelse return false;
        return privatekey.Algorithm.fromName(name) != null;
    }
};

/// Walks the identities in one `SSH_AGENT_IDENTITIES_ANSWER`.
///
/// `next` returns null at the end of the list and an error for an answer
/// that stops in the middle of a key. **The two are not the same**: a list
/// that ends is an agent with nothing more to say, and a list that stops
/// short is an agent whose answer did not arrive whole.
pub const Iterator = struct {
    reader: wire.Reader,
    left: u32,

    /// The next identity, or null at the end of the list.
    pub fn next(it: *Iterator) ParseError!?Identity {
        if (it.left == 0) return null;
        it.left -= 1;
        const key_blob = try it.reader.string();
        if (key_blob.len > max_key_blob_bytes) return error.KeyBlobTooLong;
        const comment = try it.reader.string();
        return .{ .key_blob = key_blob, .comment = comment };
    }

    /// The first identity this build can sign with.
    ///
    /// **A key of another type is walked past and never refused.** An
    /// agent commonly holds an RSA key beside an `ssh-ed25519` one, and a
    /// client that stopped at the first name it did not know would fail
    /// for a user whose agent is set up correctly. A blob that does not
    /// parse is walked past for the same reason: this build was never
    /// going to use it.
    ///
    /// Returns `error.NoUsableIdentity` when the walk ends with none, so
    /// an empty answer and a full answer of unusable keys both reach a
    /// caller by name. A truncated answer is still the truncation error,
    /// because that agent may have held a usable key in the part that
    /// never arrived.
    pub fn firstUsable(it: *Iterator) ParseError!Identity {
        while (try it.next()) |identity| {
            if (identity.usable()) return identity;
        }
        return error.NoUsableIdentity;
    }
};

/// Reads the preamble of a `SSH_AGENT_IDENTITIES_ANSWER`, section 4.4.
///
///     byte                    SSH_AGENT_IDENTITIES_ANSWER
///     uint32                  nkeys
///
/// `payload` is the message body: the type byte and everything after it,
/// with the length field of section 3 already taken off.
///
/// **`nkeys` is checked against `max_identities` and against the bytes
/// that are left.** Each key costs at least two length fields, so an
/// answer claiming more keys than `payload` could hold is refused here
/// rather than walked until it runs out.
pub fn parseIdentitiesAnswer(payload: []const u8) ParseError!Iterator {
    var r: wire.Reader = .init(payload);
    switch (@as(Id, @enumFromInt(try r.byte()))) {
        .identities_answer => {},
        .failure => return error.AgentRefused,
        else => return error.UnexpectedAgentMessage,
    }
    const count = try r.uint32();
    if (count > max_identities) return error.TooManyIdentities;
    // Two empty strings are the smallest a key can be, so a count larger
    // than this could never be walked whole.
    if (count > r.left() / 8) return error.LengthOutOfRange;
    return .{ .reader = r, .left = count };
}

/// Reads a `SSH_AGENT_SIGN_RESPONSE` and returns the signature, section 4.5.
///
///     byte                    SSH_AGENT_SIGN_RESPONSE
///     string                  signature
///
/// The answer is the blob of RFC 4253 section 6.6, which is exactly what
/// `zurl_ssh.userauth.finishPublicKeyRequest` puts on the wire. Nothing
/// here opens it: the algorithm inside it is the agent's word, and the
/// server is the party that checks the signature against the key it was
/// offered.
///
/// `SSH_AGENT_FAILURE` is `error.AgentRefused`, which section 4.5 names as
/// the answer to a key the agent does not hold, to flags it does not
/// support, and to a user who would not confirm.
///
/// **Bytes after the signature are left alone and not read.** A future
/// draft may add a field, and a client that refused the whole answer over
/// one it does not know would stop working against a newer agent.
pub fn parseSignResponse(payload: []const u8) ParseError![]const u8 {
    var r: wire.Reader = .init(payload);
    switch (@as(Id, @enumFromInt(try r.byte()))) {
        .sign_response => {},
        .failure => return error.AgentRefused,
        else => return error.UnexpectedAgentMessage,
    }
    const signature = try r.string();
    if (signature.len > max_signature_bytes) return error.SignatureTooLong;
    return signature;
}

const testing = std.testing;

/// Fails unless `err` is one of the two names a read that ran out of bytes
/// gives. Either one proves the reader stopped inside its own buffer.
fn expectReadRefusal(err: anyerror) !void {
    switch (err) {
        error.Truncated, error.LengthOutOfRange => {},
        else => {
            std.debug.print("\nexpected a read refusal, got {s}\n", .{@errorName(err)});
            return error.TestUnexpectedError;
        },
    }
}

/// The blob of an `ssh-ed25519` public key whose bytes are `filler`.
fn ed25519Blob(out: []u8, filler: u8) ![]u8 {
    var w: wire.Writer = .init(out);
    try w.string("ssh-ed25519");
    var key: [32]u8 = undefined;
    @memset(&key, filler);
    try w.string(&key);
    return w.written();
}

/// The blob of an `ssh-rsa` public key, short enough for a test and shaped
/// the way RFC 4253 section 6.6 shapes one.
fn rsaBlob(out: []u8) ![]u8 {
    var w: wire.Writer = .init(out);
    try w.string("ssh-rsa");
    try w.mpint(&.{ 0x01, 0x00, 0x01 });
    try w.mpint(&.{ 0xc0, 0xff, 0xee });
    return w.written();
}

/// Writes one `SSH_AGENT_IDENTITIES_ANSWER` body, without the length field
/// of section 3.
fn identitiesAnswer(out: []u8, blobs: []const []const u8) ![]u8 {
    var w: wire.Writer = .init(out);
    try w.byte(@intFromEnum(Id.identities_answer));
    try w.uint32(@intCast(blobs.len));
    for (blobs) |blob| {
        try w.string(blob);
        try w.string("a comment");
    }
    return w.written();
}

test "a request for identities is the two fields section 4.4 and section 3 give" {
    var storage: [16]u8 = undefined;
    const message = try writeRequestIdentities(&storage);
    try testing.expectEqual(request_identities_bytes, message.len);

    // Read back with the reader and never against the builder's own
    // output, so the two would have to be wrong the same way to agree.
    var r: wire.Reader = .init(message);
    const declared = try r.uint32();
    try testing.expectEqual(@as(u32, 1), declared);
    try testing.expectEqual(@as(usize, declared), r.left());
    try testing.expectEqual(@intFromEnum(Id.request_identities), try r.byte());
    try testing.expect(r.atEnd());
}

test "a sign request carries the key, the data, and the flags section 4.5 gives" {
    var blob_storage: [64]u8 = undefined;
    const blob = try ed25519Blob(&blob_storage, 0x11);

    var storage: [256]u8 = undefined;
    const message = try writeSignRequest(&storage, blob, "the blob RFC 4252 signs", Flags.none);

    var r: wire.Reader = .init(message);
    const declared = try r.uint32();
    // **The length counts the body and not itself**, which is the one
    // thing a framing bug gets wrong. Section 3 says
    // `byte[message length - 1]` follows the type byte.
    try testing.expectEqual(@as(usize, declared), r.left());
    try testing.expectEqual(@intFromEnum(Id.sign_request), try r.byte());
    try testing.expectEqualSlices(u8, blob, try r.string());
    try testing.expectEqualStrings("the blob RFC 4252 signs", try r.string());
    try testing.expectEqual(Flags.none, try r.uint32());
    try testing.expect(r.atEnd());
}

test "a key blob or a payload past its bound is refused and nothing is built" {
    var storage: [64]u8 = undefined;
    var long: [max_key_blob_bytes + 1]u8 = undefined;
    @memset(&long, 0);
    try testing.expectError(
        error.KeyBlobTooLong,
        writeSignRequest(&storage, &long, "data", Flags.none),
    );
    try testing.expectError(
        error.SignDataTooLong,
        writeSignRequest(&storage, "blob", &long, Flags.none),
    );
}

test "an answer holding an RSA key and an ed25519 key gives back the ed25519 one" {
    // **The whole reason the filter exists.** A person whose agent holds
    // an RSA key beside an `ssh-ed25519` one still logs in, and a client
    // that refused at the first name it did not know would not.
    var rsa_storage: [64]u8 = undefined;
    const rsa = try rsaBlob(&rsa_storage);
    var ed_storage: [64]u8 = undefined;
    const ed = try ed25519Blob(&ed_storage, 0x22);

    var answer_storage: [256]u8 = undefined;
    const answer = try identitiesAnswer(&answer_storage, &.{ rsa, ed });

    var it = try parseIdentitiesAnswer(answer);
    const chosen = try it.firstUsable();
    try testing.expectEqualSlices(u8, ed, chosen.key_blob);
    try testing.expectEqualStrings("ssh-ed25519", chosen.algorithm().?);
    try testing.expectEqualStrings("a comment", chosen.comment);
}

test "an answer holding no usable key is a named refusal and not an empty success" {
    var rsa_storage: [64]u8 = undefined;
    const rsa = try rsaBlob(&rsa_storage);

    var answer_storage: [256]u8 = undefined;
    const answer = try identitiesAnswer(&answer_storage, &.{rsa});
    var it = try parseIdentitiesAnswer(answer);
    try testing.expectError(error.NoUsableIdentity, it.firstUsable());

    // An agent holding nothing at all reaches the caller by the same
    // name, and neither one reads as a key that was found.
    const empty = try identitiesAnswer(&answer_storage, &.{});
    var none = try parseIdentitiesAnswer(empty);
    try testing.expectError(error.NoUsableIdentity, none.firstUsable());
}

test "a key blob that is not a string at all is walked past and stops nothing" {
    var ed_storage: [64]u8 = undefined;
    const ed = try ed25519Blob(&ed_storage, 0x33);

    var answer_storage: [256]u8 = undefined;
    const answer = try identitiesAnswer(&answer_storage, &.{ "\xff\xff", ed });
    var it = try parseIdentitiesAnswer(answer);
    const chosen = try it.firstUsable();
    try testing.expectEqualSlices(u8, ed, chosen.key_blob);
}

test "SSH_AGENT_FAILURE is a named refusal for both requests" {
    const failure = [_]u8{@intFromEnum(Id.failure)};
    try testing.expectError(error.AgentRefused, parseSignResponse(&failure));
    try testing.expectError(error.AgentRefused, parseIdentitiesAnswer(&failure));

    // A message this build never asked for is apart from a refusal,
    // because the two say different things about the agent.
    const success = [_]u8{@intFromEnum(Id.success)};
    try testing.expectError(error.UnexpectedAgentMessage, parseSignResponse(&success));
    try testing.expectError(error.UnexpectedAgentMessage, parseIdentitiesAnswer(&success));

    // An empty answer names no message at all.
    try testing.expectError(error.Truncated, parseSignResponse(""));
    try testing.expectError(error.Truncated, parseIdentitiesAnswer(""));
}

test "a sign response gives back the signature blob and never opens it" {
    var storage: [128]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(Id.sign_response));
    var blob_storage: [96]u8 = undefined;
    var blob: wire.Writer = .init(&blob_storage);
    try blob.string("ssh-ed25519");
    var signature: [64]u8 = undefined;
    @memset(&signature, 0x44);
    try blob.string(&signature);
    try w.string(blob.written());

    const answer = try parseSignResponse(w.written());
    try testing.expectEqualSlices(u8, blob.written(), answer);
}

test "an answer that stops in the middle of a key is refused rather than read past" {
    var ed_storage: [64]u8 = undefined;
    const ed = try ed25519Blob(&ed_storage, 0x55);

    var answer_storage: [256]u8 = undefined;
    const answer = try identitiesAnswer(&answer_storage, &.{ed});

    // Every prefix of a well formed answer must refuse. **None of them
    // may read a byte that is not there**, and a prefix that ends inside
    // the preamble must not even give back an iterator.
    var end = answer.len - 1;
    while (end > 0) : (end -= 1) {
        const cut = answer[0..end];
        var it = parseIdentitiesAnswer(cut) catch |err| {
            try expectReadRefusal(err);
            continue;
        };
        if (it.firstUsable()) |_| {
            std.debug.print("\na prefix of {d} bytes gave back a key\n", .{end});
            return error.TestExpectedRefusal;
        } else |err| try expectReadRefusal(err);
    }
}

test "a length that runs past the buffer is refused and no key is returned" {
    // The agent says one key and writes a blob length of four thousand
    // million. **The cost of that claim is one comparison.**
    var storage: [32]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(Id.identities_answer));
    try w.uint32(1);
    try w.bytes("\xff\xff\xff\xff\x00\x00\x00\x00");

    var it = try parseIdentitiesAnswer(w.written());
    try testing.expectError(error.LengthOutOfRange, it.firstUsable());

    // A signature that claims more than the answer holds lands the same
    // way.
    var signature_storage: [16]u8 = undefined;
    var signature: wire.Writer = .init(&signature_storage);
    try signature.byte(@intFromEnum(Id.sign_response));
    try signature.bytes("\xff\xff\xff\xff\x01");
    try testing.expectError(error.LengthOutOfRange, parseSignResponse(signature.written()));
}

test "a count larger than the answer could hold is refused before the walk" {
    // **This is the bound that stops a small answer claiming many keys.**
    // Without it an agent writes nine bytes and this process walks a
    // loop two thousand times to find that out.
    var storage: [16]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(Id.identities_answer));
    try w.uint32(max_identities);
    try testing.expectError(error.LengthOutOfRange, parseIdentitiesAnswer(w.written()));

    var too_many: wire.Writer = .init(&storage);
    try too_many.byte(@intFromEnum(Id.identities_answer));
    try too_many.uint32(max_identities + 1);
    try testing.expectError(error.TooManyIdentities, parseIdentitiesAnswer(too_many.written()));
}

test "a signature blob longer than the bound is refused by its own name" {
    var storage: [max_signature_bytes + 64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(Id.sign_response));
    var long: [max_signature_bytes + 1]u8 = undefined;
    @memset(&long, 0x66);
    try w.string(&long);
    try testing.expectError(error.SignatureTooLong, parseSignResponse(w.written()));
}

test "the socket variable is named here and read nowhere in this package" {
    try testing.expectEqualStrings("SSH_AUTH_SOCK", auth_socket_variable);
}
