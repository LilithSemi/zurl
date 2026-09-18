//! Whatever holds the private key for a `publickey` attempt.
//!
//! **The builder and the signer are two different things, and this is the
//! line between them.** `zurl_ssh.userauth.writeSignatureBlob` builds every
//! byte RFC 4252 section 7 covers, and
//! `zurl_ssh.userauth.finishPublicKeyRequest` adds a signature to it.
//! Neither one knows where the signature came from. This file names what
//! sits in between, so a key in this process and a key in an agent reach
//! `zurl_ssh.Authenticator` the same way.
//!
//! Two things implement it today:
//!
//! - `zurl_ssh.privatekey.PrivateKey.signer`, for a key this process read
//!   off disk and holds in its own memory.
//! - `zurl_ssh.AgentClient.signer`, for a key an agent holds and this
//!   process never sees.
//!
//! **The error set is small on purpose.** A signature either happened or
//! it did not, and an authenticator has the same three things to say about
//! it whichever side of the socket the key is on. A signer with more to
//! report keeps the detail itself: `AgentClient.fault` holds the agent
//! fault by name, the way `zurl_net.tcp.DialOptions.no_delay_error` holds
//! a fault the dial does not stop for.

const std = @import("std");

/// Why a signature was not made.
pub const Error = error{
    /// The signer holds the key and the signature itself did not come
    /// out.
    SignatureFailed,
    /// The signer has the key and would not use it. An agent that
    /// answered `SSH_AGENT_FAILURE` lands here, which
    /// draft-miller-ssh-agent-04 section 4.5 gives for a key the agent
    /// does not hold, for flags it does not support, and for a user who
    /// would not confirm.
    ///
    /// **A refusal, and never a fault to retry.**
    SignerRefused,
    /// The signer could not be reached at all, or it answered something
    /// this build could not read. A socket that closed lands here.
    SignerUnavailable,
    /// The buffer the caller gave is too small for the signature blob.
    /// A caller's own bug, and an error rather than an assert because a
    /// caller outside this package can reach it.
    NoSpaceLeft,
};

/// One thing that can sign for one key.
///
/// `algorithm` and `public_blob` are what a `publickey` request names, so
/// they must be the key `sign` will use and not another one. A server
/// checks the signature against the key the request offered, so a signer
/// whose three fields do not agree fails at the server with nothing said
/// about why.
///
/// Both slices must outlive the signer. A `PrivateKey` owns its own, and
/// an `AgentClient` keeps the blob it chose in its own storage.
pub const Signer = struct {
    /// Passed back to `sign`.
    ctx: ?*anyopaque = null,
    /// The public key algorithm name, `ssh-ed25519` in this build.
    algorithm: []const u8,
    /// The public key blob, in the form RFC 4253 section 6.6 gives.
    public_blob: []const u8,
    /// Signs `message` and writes the signature blob into `out`.
    ///
    /// The blob is the wire form of RFC 4253 section 6.6: the algorithm
    /// name and then the signature, each as a string. The answer points
    /// into `out`.
    ///
    /// **`message` is every byte RFC 4252 section 7 covers**, the session
    /// identifier at the front included, and a signer signs all of it and
    /// none of it twice.
    sign: *const fn (ctx: ?*anyopaque, message: []const u8, out: []u8) Error![]u8,
};
