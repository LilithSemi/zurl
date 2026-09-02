//! zurl's `sftp://` protocol: the SSH file transfer protocol, version 3.
//!
//! One protocol, one module. A build that does not want SFTP leaves this
//! module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, `zurl-net`, and `zurl-ssh`
//! and gets `sftp://` with no other part of zurl.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead.
//!
//! A caller wires it in three lines:
//!
//!     var fetcher: zurl_sftp.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!
//! **Version 3 and no other.** Version 3 is `draft-ietf-secsh-filexfer-02`
//! and it is what OpenSSH speaks: `sftp-server.c` answers
//! `SSH2_FILEXFER_VERSION 3` and nothing else. A client that offered a
//! later version would negotiate down to 3 against every server it will
//! ever meet.
//!
//! **What a transfer does.** `SSH_FXP_INIT`, then `SSH_FXP_OPEN`,
//! `SSH_FXP_FSTAT`, a run of `SSH_FXP_READ`, and `SSH_FXP_CLOSE` for a
//! download. `SSH_FXP_OPENDIR` and `SSH_FXP_READDIR` for a url that ends
//! in a slash, which is a directory listing and which is what curl does
//! with the same url. `SSH_FXP_WRITE` for `-T`.
//!
//! **Host key trust is not skipped and it is not guessed.** A host with no
//! `known_hosts` entry is `error.PeerFailedVerification`, exit 60, which
//! is what curl 8.21.0 answers for the same url, measured. A host whose
//! key is on record and different is the same exit code with a different
//! sentence, and **the record is never updated**. `--hostpubsha256` and
//! `--hostpubmd5` pin a key on the command line, `--knownhosts` names the
//! file, and `-k` skips the check the way it skips a TLS certificate
//! check. See `zurl_ssh.knownhosts`.
//!
//! What this does not do: no `--pubkey`, so the public half of a key file
//! is not read separately. No passphrase prompt, so an encrypted private
//! key with no passphrase given is a refusal by name. No `-Q` quote
//! commands, so `chmod`, `rename`, and `rm` on a server are not reachable.
//! No resume of an upload, so `-C` reaches a download and not a `-T`.

const std = @import("std");

/// Runs one `sftp://` transfer, and builds the dispatch entry that
/// registers it.
pub const Fetcher = @import("zurl-sftp/Fetcher.zig");

/// The SFTP wire format, version 3. Pure bytes.
pub const protocol = @import("zurl-sftp/protocol.zig");

/// The subsystem over one SSH channel: the framing, the request ids, and
/// the file operations.
pub const Session = @import("zurl-sftp/Session.zig");

/// The url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The port a url of this scheme uses when it names none.
pub const default_port = Fetcher.default_port;

test {
    _ = Fetcher;
    _ = protocol;
    _ = Session;
    _ = @import("zurl-sftp/session_test.zig");
}

test "the package names the scheme and the port RFC 4253 assigns" {
    try std.testing.expectEqualStrings("sftp", scheme);
    try std.testing.expectEqual(@as(?u16, 22), default_port);
}

test "the package speaks the one version OpenSSH speaks" {
    try std.testing.expectEqual(@as(u32, 3), protocol.version);
    try std.testing.expectEqualStrings("sftp", protocol.subsystem_name);
}
