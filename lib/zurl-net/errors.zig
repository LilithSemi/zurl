//! Maps a `zurl-net` setup fault onto the zurl error taxonomy.
//!
//! This file owns one table and the two lookups over it. It records
//! nothing: a `zurl_core.Diagnostics` belongs to whoever knows which url
//! failed, and that is the engine above, not this package.
//!
//! The table covers dialing and the TLS handshake. It does not cover the
//! data phase, because a read or a write on an open connection reports
//! through `Connection.readError` and `Connection.writeError`, and the
//! engine that owns the protocol decides what a fault there means for the
//! transfer.
//!
//! **There is no catch-all.** A comptime check proves every member of
//! `SetupError` has a row, so a name cannot fall through and reach a user
//! as some other fault. zurl removed a catch-all from
//! `zurl-http/errors.zig` for exactly this reason: it turned a precise
//! fault into `CouldNotConnect`, exit 7, whatever the fault really was.
//!
//! The distinction this table exists to keep is the one between exit 35
//! and exit 60. `std.http.Client` collapses every TLS fault into one name,
//! so zurl answers an expired certificate, a wrong host name, and an
//! untrusted root with `CURLE_SSL_CONNECT_ERROR`, 35, where curl answers
//! `CURLE_PEER_FAILED_VERIFICATION`, 60. Every row below that names a
//! certificate maps to `PeerFailedVerification`.

const std = @import("std");
const zurl_core = @import("zurl-core");

const tcp = @import("tcp.zig");
const Connection = @import("Connection.zig");

const Error = zurl_core.Error;

/// Every fault a protocol's own step between the dial and the handshake
/// can report.
///
/// One name, because only the protocol package knows what its step does
/// and why it stopped. `bounded.Setup.upgrade` says how the reason gets
/// back to that package: the step records it, because a task that loses
/// the connect race returns nothing at all.
pub const UpgradeError = error{
    /// The protocol ran a step on the open stream and that step failed.
    /// The connection is not brought up and no handshake starts.
    UpgradeFailed,
};

/// Every fault opening a connection can report: the dial, a protocol's own
/// step on the open stream, and the handshake together.
pub const SetupError = tcp.DialError || UpgradeError || Connection.InitError;

/// What one fault means to a user: the zurl error it maps to, and the
/// sentence that says why it happened.
///
/// `message` is null only where the error name alone says it, which is
/// the dial: `CouldNotResolveHost` needs no sentence.
///
/// Every fault that comes from the peer carries one. Those are the rows
/// that map to `SslConnectError` and to `PeerFailedVerification`, and the
/// name alone says nothing a user can act on for any of them:
/// `TlsBadRecordMac` and `TlsRecordOverflow` name a layer, not a cause,
/// and a user reads only the mapped name and the sentence. The test
/// *"every fault the peer can cause carries a message"* holds that rule
/// over the whole table.
pub const Mapping = struct {
    err: Error,
    message: ?[]const u8 = null,
};

/// One row of the table. `err` is `anyerror` so one table can hold names
/// from four different error sets.
const Row = struct { err: anyerror, mapped: Error, message: ?[]const u8 = null };

const rows = [_]Row{
    // ---- The dial. See `tcp.DialError`. ----
    .{ .err = error.CouldNotResolveHost, .mapped = error.CouldNotResolveHost },
    .{ .err = error.CouldNotConnect, .mapped = error.CouldNotConnect },
    .{ .err = error.OperationTimedOut, .mapped = error.OperationTimedOut },
    .{
        .err = error.ConnectTimeoutUnsupported,
        .mapped = error.CouldNotConnect,
        .message = "this build has no concurrency, so the connect timeout cannot be enforced",
    },
    // A cancel is how something outside the transfer stops it early, the
    // same shape as a callback that answers "stop".
    .{ .err = error.Canceled, .mapped = error.AbortedByCallback },
    .{
        .err = error.Unexpected,
        .mapped = error.CouldNotConnect,
        .message = "the operating system returned a fault zurl cannot name",
    },
    // The three below are refusals over `/etc/resolv.conf`, and each one
    // carries a sentence because the name of the fault alone does not say
    // which line of the file to look at. All three mean the same thing to
    // a script, exit 6, because the name did not resolve. See
    // `zurl-net/resolv.zig`.
    .{
        .err = error.ResolverSearchListTooLong,
        .mapped = error.CouldNotResolveHost,
        .message = "the search line of /etc/resolv.conf is longer than the resolver of this build can hold",
    },
    .{
        .err = error.ResolverAttemptsZero,
        .mapped = error.CouldNotResolveHost,
        .message = "/etc/resolv.conf sets attempts to 0, and the resolver of this build divides by that value",
    },
    .{
        .err = error.ResolverSearchNameTooLong,
        .mapped = error.CouldNotResolveHost,
        .message = "the host name and a search domain of /etc/resolv.conf are together longer than the resolver can hold",
    },

    // ---- The protocol's own step on the open stream. ----
    //
    // The sentence here is a fallback and a protocol package normally
    // replaces it. Only that package knows what its step asked the peer
    // for, so it records its own reason and reads it back instead of this
    // row. See `bounded.Setup.upgrade` and `zurl_ftp.Fetcher.upgrade`.
    .{
        .err = error.UpgradeFailed,
        .mapped = error.SslConnectError,
        .message = "the step this protocol runs before its TLS handshake did not finish",
    },

    // ---- Getting ready to hand shake. ----
    .{ .err = error.OutOfMemory, .mapped = error.OutOfMemory },
    .{
        .err = error.EntropyUnavailable,
        .mapped = error.SslConnectError,
        .message = "the system gave no entropy, so the TLS client random cannot be trusted",
    },
    .{
        .err = error.InsufficientEntropy,
        .mapped = error.SslConnectError,
        .message = "the system gave too little entropy to key the TLS handshake",
    },
    .{
        .err = error.TlsVersionTooLow,
        .mapped = error.SslConnectError,
        .message = "the peer offered a TLS version below the one --tlsv1.x asked for",
    },
    .{
        .err = error.TlsVersionTooHigh,
        .mapped = error.SslConnectError,
        .message = "the peer answered with a TLS version above the one --tls-max allows",
    },
    .{
        .err = error.TlsVersionRangeEmpty,
        .mapped = error.SslConnectError,
        .message = "--tls-max is below the TLS 1.2 floor of this build, so no version is left",
    },
    // The ALPN offer is built inside zurl and never from a command line, so
    // this row answers a build fault and not a user one. It is a named
    // fault and not an assert, because an assert disappears in ReleaseFast
    // and a hello with a broken length would go out instead.
    .{
        .err = error.TlsAlpnOfferInvalid,
        .mapped = error.SslConnectError,
        .message = "the ALPN protocol list this build offers has no form the TLS handshake can send",
    },
    .{
        .err = error.TlsAlpnProtocolNotOffered,
        .mapped = error.SslConnectError,
        .message = "the peer chose an ALPN protocol that the client hello did not offer",
    },
    // The host reaches the TLS client from a url, and a url can reach zurl
    // from a `Location` header, so this count is not always the user's. It
    // is a named refusal and not a cast, because an `@intCast` that does
    // not fit is undefined behaviour in the build a user runs.
    .{
        .err = error.TlsHostNameTooLong,
        .mapped = error.SslConnectError,
        .message = "the host name is longer than the 255 octets a TLS server name extension carries",
    },

    // ---- The peer certificate did not verify. These are exit 60. ----
    //
    // Each name says which check refused the certificate. A user answers
    // an expired certificate and a wrong host name differently, so the
    // two must not share a name here either.
    .{
        .err = error.CertificateExpired,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate is past its expiry date",
    },
    .{
        .err = error.CertificateNotYetValid,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate is not valid yet",
    },
    .{
        .err = error.CertificateHostMismatch,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate does not carry the host name that was asked for",
    },
    .{
        .err = error.TlsCertificateNotVerified,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate chain reaches no trusted root",
    },
    .{
        .err = error.CertificateIssuerMismatch,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain does not name the issuer above it",
    },
    .{
        .err = error.CertificateSignatureInvalid,
        .mapped = error.PeerFailedVerification,
        .message = "a signature in the peer certificate chain does not check out",
    },
    .{
        .err = error.CertificateIssuerNotCa,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain signed the one below it and is not a certificate authority",
    },
    .{
        .err = error.CertificateIssuerCannotSignCertificates,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate authority in the chain does not allow its key to sign a certificate",
    },
    .{
        .err = error.CertificateNotForServerAuth,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain carries an extended key usage that does not allow it to stand for a TLS server",
    },
    .{
        .err = error.CertificateNameNotPermitted,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate authority in the chain is not allowed to answer for this host name",
    },
    .{
        .err = error.CertificatePathLengthExceeded,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate authority in the chain sits above more certificates than it allows",
    },
    .{
        .err = error.CertificateChainTooLong,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate chain holds more certificates than zurl walks",
    },
    .{
        .err = error.CertificateSignatureInvalidLength,
        .mapped = error.PeerFailedVerification,
        .message = "a signature in the peer certificate chain has the wrong length for its algorithm",
    },
    .{
        .err = error.CertificateSignatureAlgorithmMismatch,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain names one signature algorithm in two places, and the two disagree",
    },
    .{
        .err = error.CertificateSignatureAlgorithmUnsupported,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain is signed with an algorithm zurl cannot check",
    },
    .{
        .err = error.CertificateSignatureNamedCurveUnsupported,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain uses an elliptic curve zurl cannot check",
    },
    .{
        .err = error.CertificateSignatureUnsupportedBitCount,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain carries a key size zurl cannot check",
    },
    .{
        .err = error.CertificatePublicKeyInvalid,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain carries a public key that does not decode",
    },
    // The cryptographic floor. Both of these say the certificate reads
    // correctly and that zurl will not trust the mathematics under it, so
    // the sentence names the algorithm and not the format.
    .{
        .err = error.CertificateSignatureAlgorithmWeak,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain is signed with SHA-1 or MD5, whose collision resistance is broken",
    },
    .{
        .err = error.CertificatePublicKeyTooWeak,
        .mapped = error.PeerFailedVerification,
        .message = "a certificate in the chain carries an RSA key below the 2048 bit floor",
    },
    .{
        .err = error.CertificateHasDuplicateExtension,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate carries one extension twice, so its meaning is not decided",
    },
    .{
        .err = error.CertificateFieldHasInvalidLength,
        .mapped = error.PeerFailedVerification,
        .message = "a field of the peer certificate names a length that does not fit the certificate",
    },
    .{
        .err = error.CertificateFieldHasWrongDataType,
        .mapped = error.PeerFailedVerification,
        .message = "a field of the peer certificate holds a data type the standard does not allow there",
    },
    .{
        .err = error.CertificateTimeInvalid,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate carries a validity date that does not parse",
    },
    .{
        .err = error.CertificateHasUnrecognizedObjectId,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate names an object identifier zurl does not know",
    },
    .{
        .err = error.CertificateHasInvalidBitString,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate holds a bit string that does not decode",
    },
    .{
        .err = error.UnsupportedCertificateVersion,
        .mapped = error.PeerFailedVerification,
        .message = "the peer certificate is not an X.509 version zurl reads",
    },

    // The crypto primitives that check the peer's signatures report by
    // their own names. Every one of them is reached from verifying what
    // the peer sent, so the peer is what failed verification, and a user
    // reads exit 60 for the same reason as the rows above.
    .{
        .err = error.SignatureVerificationFailed,
        .mapped = error.PeerFailedVerification,
        .message = "a signature the peer sent does not check out against the key that must have made it",
    },
    .{
        .err = error.InvalidSignature,
        .mapped = error.PeerFailedVerification,
        .message = "a signature the peer sent does not check out against the key that must have made it",
    },
    .{
        .err = error.InvalidEncoding,
        .mapped = error.PeerFailedVerification,
        .message = "a key or a signature the peer sent is not encoded the way its algorithm requires",
    },
    .{
        .err = error.IdentityElement,
        .mapped = error.PeerFailedVerification,
        .message = "the peer sent an elliptic curve point that carries no key material",
    },
    .{
        .err = error.NonCanonical,
        .mapped = error.PeerFailedVerification,
        .message = "the peer sent a number that is not in the one form its algorithm allows",
    },
    .{
        .err = error.NotSquare,
        .mapped = error.PeerFailedVerification,
        .message = "the peer sent an elliptic curve point that is not on its curve",
    },
    .{
        .err = error.WeakPublicKey,
        .mapped = error.PeerFailedVerification,
        .message = "the peer offered a public key that is too weak to trust",
    },
    .{
        .err = error.NegativeIntoUnsigned,
        .mapped = error.PeerFailedVerification,
        .message = "a number in the peer certificate chain is negative where the standard allows none",
    },
    .{
        .err = error.MessageTooLong,
        .mapped = error.PeerFailedVerification,
        .message = "the peer asked zurl to check a signature over more bytes than its algorithm accepts",
    },
    .{
        .err = error.TargetTooSmall,
        .mapped = error.PeerFailedVerification,
        .message = "a value in the peer certificate chain is larger than the field that must hold it",
    },
    .{
        .err = error.BufferTooSmall,
        .mapped = error.PeerFailedVerification,
        .message = "a value in the peer certificate chain is larger than the field that must hold it",
    },

    // ---- The handshake itself did not finish. These are exit 35. ----
    //
    // Nothing here says the peer is untrusted. It says the two ends could
    // not agree, or that a record did not arrive as the protocol says it
    // must.
    .{
        .err = error.TlsAlert,
        .mapped = error.SslConnectError,
        .message = "the peer refused the handshake and sent a TLS alert",
    },
    .{
        .err = error.TlsBadSignatureScheme,
        .mapped = error.SslConnectError,
        .message = "the peer chose a signature scheme this TLS client does not speak",
    },
    .{
        .err = error.TlsBadRsaSignatureBitCount,
        .mapped = error.SslConnectError,
        .message = "the peer signed the handshake with an RSA key size this TLS client does not accept",
    },
    .{
        .err = error.TlsUnexpectedMessage,
        .mapped = error.SslConnectError,
        .message = "the peer sent a TLS message the handshake does not allow at that point",
    },
    .{
        .err = error.TlsIllegalParameter,
        .mapped = error.SslConnectError,
        .message = "the peer chose a handshake parameter the protocol does not allow",
    },
    .{
        .err = error.TlsDecryptFailure,
        .mapped = error.SslConnectError,
        .message = "the peer reported that it could not decrypt what this client sent",
    },
    .{
        .err = error.TlsDecryptError,
        .mapped = error.SslConnectError,
        .message = "the peer reported that a handshake message did not decrypt or did not verify",
    },
    // The usual cause is a peer that is not speaking TLS. A cleartext
    // HTTP server answers a Client Hello with a status line, and
    // `HTTP/1.1 4` reads as a record header that claims a record far over
    // the legal size. zurl reached this from its own redirect chain: a
    // `host:` line that carried the default port came back inside a
    // `location:`, and the next hop opened TLS on port 80. See
    // `h1.authorityPort`.
    .{
        .err = error.TlsRecordOverflow,
        .mapped = error.SslConnectError,
        .message = "the peer sent a TLS record larger than the protocol allows, so it may not be speaking TLS",
    },
    .{
        .err = error.TlsDecodeError,
        .mapped = error.SslConnectError,
        .message = "a TLS handshake message from the peer does not decode",
    },
    .{
        .err = error.TlsBadRecordMac,
        .mapped = error.SslConnectError,
        .message = "a TLS record did not authenticate, so the session cannot be trusted",
    },
    .{
        .err = error.TlsConnectionTruncated,
        .mapped = error.SslConnectError,
        .message = "the peer closed the connection in the middle of the TLS handshake",
    },

    // ---- The socket failed while the handshake was in flight. ----
    //
    // The handshake did not finish, so every one of these is exit 35 and
    // not exit 7: the connection was already open, and a user who reads
    // "could not connect" would look in the wrong place. The message
    // names the socket fault, so the cause is not lost.
    .{
        .err = error.ConnectionResetByPeer,
        .mapped = error.SslConnectError,
        .message = "the peer reset the connection during the TLS handshake",
    },
    .{
        .err = error.ConnectionRefused,
        .mapped = error.SslConnectError,
        .message = "the socket was refused during the TLS handshake",
    },
    .{
        .err = error.Timeout,
        .mapped = error.OperationTimedOut,
        .message = "the socket timed out during the TLS handshake",
    },
    .{
        .err = error.SocketUnconnected,
        .mapped = error.SslConnectError,
        .message = "the socket was already shut down during the TLS handshake",
    },
    .{
        .err = error.SocketNotBound,
        .mapped = error.SslConnectError,
        .message = "the socket was not bound during the TLS handshake",
    },
    .{
        .err = error.NetworkDown,
        .mapped = error.SslConnectError,
        .message = "the local network went down during the TLS handshake",
    },
    .{
        .err = error.NetworkUnreachable,
        .mapped = error.SslConnectError,
        .message = "the network became unreachable during the TLS handshake",
    },
    .{
        .err = error.HostUnreachable,
        .mapped = error.SslConnectError,
        .message = "the host became unreachable during the TLS handshake",
    },
    .{
        .err = error.SystemResources,
        .mapped = error.SslConnectError,
        .message = "the operating system ran out of resources during the TLS handshake",
    },
    .{
        .err = error.AccessDenied,
        .mapped = error.SslConnectError,
        .message = "the socket may not be read during the TLS handshake",
    },
    .{
        .err = error.AddressFamilyUnsupported,
        .mapped = error.SslConnectError,
        .message = "the socket refused the address family during the TLS handshake",
    },
    .{
        .err = error.FastOpenAlreadyInProgress,
        .mapped = error.SslConnectError,
        .message = "a TCP fast open was already in flight on this socket during the TLS handshake",
    },

    // ---- Two names `init` declares and never returns. ----
    //
    // `zurl_tls.Client.InitError` carries them, so `SetupError` carries
    // them, so the check below asks for a row. `Connection.init` replaces
    // each one with the socket fault that caused it, which is the whole
    // point of that replacement: neither name says anything a user can
    // act on. The messages say where to look, in case a later change
    // lets one through.
    .{
        .err = error.ReadFailed,
        .mapped = error.SslConnectError,
        .message = "a read failed during the TLS handshake and its cause was not recorded",
    },
    .{
        .err = error.WriteFailed,
        .mapped = error.SslConnectError,
        .message = "a write failed during the TLS handshake and its cause was not recorded",
    },

    // ---- Names `std.Io` writers carry that this package does not reach. ----
    //
    // A socket writer declares them because one `std.Io.Writer` error set
    // covers a file as well. None of the three can come from a socket.
    // The messages say so, so a user who ever reads one knows the fault is
    // in zurl and not in the network.
    .{
        .err = error.DiskQuota,
        .mapped = error.WriteError,
        .message = "a socket write reported a disk quota, which a socket cannot do",
    },
    .{
        .err = error.LockViolation,
        .mapped = error.WriteError,
        .message = "a socket write reported a file lock, which a socket cannot do",
    },
    .{
        .err = error.NotOpenForWriting,
        .mapped = error.WriteError,
        .message = "a socket write reported that the handle is not open for writing",
    },
};

comptime {
    // Every fault this package can produce must have a row. A row count
    // that matches the member count is not proof: a duplicated row keeps
    // the count right while a real name still has none. So this checks
    // `SetupError` by name, the way `zurl-core/errors.zig` checks its own
    // set.
    //
    // This check is what closes the catch-all. `lookup` walks a runtime
    // table and can still answer null to the compiler, but no value of
    // `SetupError` can make it do so.
    checkCovered(SetupError);
}

fn checkCovered(comptime set: type) void {
    // One pass over `rows` for each member of `set`. `SetupError` holds
    // about sixty members against about sixty rows, and the default quota
    // of a thousand branches does not cover that product.
    @setEvalBranchQuota(30_000);
    for (@typeInfo(set).error_set.?) |field| {
        const err: anyerror = @field(set, field.name);
        var found = false;
        for (rows) |row| {
            if (row.err == err) found = true;
        }
        if (!found) @compileError("zurl-net/errors.zig: error." ++ field.name ++ " has no row in `rows`");
    }
}

/// What `err` means to a user: the zurl error and the reason, when the
/// name alone does not carry it.
///
/// `err` is `SetupError` and not `anyerror`. A caller holds one of two
/// things: the fault a dial gave it, or the fault a handshake gave it.
/// A value from outside those two is a compile error at the call, where
/// somebody can read it, and never a wrong exit code at the user.
pub fn map(err: SetupError) Mapping {
    const row = lookup(err) orelse {
        // Not reachable: `checkCovered(SetupError)` fails the build before
        // a name can arrive here with no row. It stays a branch because
        // `unreachable` is removed in ReleaseFast, which is the build a
        // user runs, and it is loud rather than quiet.
        return .{ .err = error.SslConnectError, .message = no_row_message };
    };
    return .{ .err = row.mapped, .message = row.message };
}

/// The zurl error `err` means. Shorthand for `map(err).err`, for a caller
/// that writes its own message.
pub fn toCore(err: SetupError) Error {
    return map(err).err;
}

/// The libcurl exit code `err` earns.
pub fn curlCode(err: SetupError) u32 {
    return zurl_core.errors.curlCode(toCore(err));
}

fn lookup(err: anyerror) ?Row {
    for (rows) |row| {
        if (row.err == err) return row;
    }
    return null;
}

/// What a host that `tcp.Host.init` would not read means to a user.
///
/// **This is apart from `rows` on purpose, and `SetupError` does not
/// carry `tcp.Host.InitError`.** Every row of that table answers for one
/// fault whatever the caller was doing, because a certificate that did
/// not verify means the same thing at every dial. These two do not: the
/// same `InvalidHost` is a bad url at an origin, a bad `-x` flag at a
/// proxy, and a bad `227` reply on an FTP data connection, and those are
/// exits 3, 5, and 7. So the caller keeps the last word, and this
/// function answers only the one reading a caller cannot work out for
/// itself.
///
/// The switch has no `else`. A new member of `tcp.Host.InitError` is a
/// compile error here, which is the guarantee `checkCovered` gives the
/// table.
///
/// **The two members are two different faults.** `InvalidHost` says the
/// text is neither an address nor a host name, which is text somebody
/// wrote wrong, so it is exit 3. `HostNameTooLong` says the text is a
/// good host name that no resolver can look up, so it is exit 6, which is
/// what curl 8.21.0 answers for the same name.
pub fn hostInit(err: tcp.Host.InitError) Mapping {
    return switch (err) {
        error.InvalidHost => .{
            .err = error.InvalidUrl,
            .message = "the host is neither an address nor a host name",
        },
        error.HostNameTooLong => .{
            .err = error.CouldNotResolveHost,
            .message = "the host name is longer than the dns encoding holds, so no resolver can look it up",
        },
    };
}

/// What a `TCP_NODELAY` that did not take means to a user.
///
/// This is apart from `rows` because it is not a setup fault. The dial
/// succeeded and the transfer runs. See `tcp.setNoDelay`: the connection
/// carries every byte correctly, and only pays a stall of up to 40
/// milliseconds for each request. So the sentence describes a slower
/// transfer and never a failed one.
///
/// The switch names every member of `tcp.NoDelayError`. There is no
/// `else`, so a new name is a compile error here and never a silent fall
/// into a sentence that does not fit it.
///
/// Each sentence is a constant of this file, so it outlives any caller
/// and needs no allocation.
pub fn noDelayMessage(err: tcp.NoDelayError) []const u8 {
    return switch (err) {
        error.SocketOptionUnsupported => "This build cannot set TCP_NODELAY. Each request may wait up to 40 ms.",
        error.InvalidProtocolOption, error.OperationUnsupported => "This system does not support TCP_NODELAY. Each request may wait up to 40 ms.",
        error.PermissionDenied => "zurl may not set TCP_NODELAY. Each request may wait up to 40 ms.",
        error.SystemResources => "The system had no resources to set TCP_NODELAY. Each request may wait up to 40 ms.",
        error.NetworkDown => "The network went down before TCP_NODELAY was set. Each request may wait up to 40 ms.",
        error.NoDevice => "The network device refused TCP_NODELAY. Each request may wait up to 40 ms.",
        // The three below cannot come from this option on a connected
        // stream socket. They stay named, because the error set is a
        // promise the compiler checks, and a user who ever reads one must
        // learn that the fault is in zurl and not in the network.
        error.AlreadyConnected,
        error.SocketNotBound,
        error.FileDescriptorNotASocket,
        => "zurl asked for TCP_NODELAY on a socket that cannot take it. Each request may wait up to 40 ms.",
        error.TimeoutTooBig => "zurl set TCP_NODELAY with the wrong value. Each request may wait up to 40 ms.",
        error.Unexpected => "The operating system refused TCP_NODELAY for a reason zurl cannot name. Each request may wait up to 40 ms.",
    };
}

/// What a user reads if a fault ever reaches `map` with no row. It names
/// the table, because that is where the fix goes.
const no_row_message = "this fault has no row in zurl-net/errors.zig, so zurl cannot name its cause";

const testing = std.testing;

test "a certificate that does not verify earns exit 60, not exit 35" {
    // This is the defect the package exists to close. `std.http.Client`
    // collapses all four of these into one name, so zurl answered every
    // one of them with 35 where curl answers 60.
    const refused = [_]SetupError{
        error.CertificateExpired,
        error.CertificateHostMismatch,
        error.TlsCertificateNotVerified,
        error.CertificateIssuerMismatch,
        // The chain rules of RFC 5280. A forged leaf signed by a
        // certificate that is not a certificate authority reaches the
        // first of these, and it must read as a refused certificate and
        // not as a handshake that did not agree.
        error.CertificateIssuerNotCa,
        error.CertificateIssuerCannotSignCertificates,
        error.CertificatePathLengthExceeded,
        error.CertificateChainTooLong,
        // A certificate for another purpose, an authority that may not
        // answer for this name, a certificate that carries one extension
        // twice, and the cryptographic floor. Each one refuses a
        // certificate the peer sent, so each one is exit 60.
        error.CertificateNotForServerAuth,
        error.CertificateNameNotPermitted,
        error.CertificateHasDuplicateExtension,
        error.CertificateSignatureAlgorithmWeak,
        error.CertificatePublicKeyTooWeak,
    };
    for (refused) |err| {
        const mapping = map(err);
        try testing.expectEqual(Error.PeerFailedVerification, mapping.err);
        try testing.expectEqual(@as(u32, 60), zurl_core.errors.curlCode(mapping.err));
    }
}

test "an expired certificate and a wrong host name do not share a message" {
    // Both earn exit 60, so the exit code alone cannot tell them apart. A
    // user has to read which check refused the certificate, and each of
    // these names a different one.
    const expired = map(error.CertificateExpired);
    const mismatch = map(error.CertificateHostMismatch);
    const untrusted = map(error.TlsCertificateNotVerified);

    try testing.expect(!std.mem.eql(u8, expired.message.?, mismatch.message.?));
    try testing.expect(!std.mem.eql(u8, expired.message.?, untrusted.message.?));
    try testing.expect(!std.mem.eql(u8, mismatch.message.?, untrusted.message.?));
}

test "a handshake that did not agree stays exit 35" {
    // `SslConnectError` is right here and wrong for a certificate. The
    // two groups must not drift into one another.
    const not_verification = [_]SetupError{
        error.TlsAlert,
        error.TlsBadSignatureScheme,
        error.TlsConnectionTruncated,
        error.TlsUnexpectedMessage,
    };
    for (not_verification) |err| {
        const mapping = map(err);
        try testing.expectEqual(Error.SslConnectError, mapping.err);
        try testing.expectEqual(@as(u32, 35), zurl_core.errors.curlCode(mapping.err));
    }
}

test "a dial fault keeps the code curl gives it" {
    try testing.expectEqual(@as(u32, 6), curlCode(error.CouldNotResolveHost));
    try testing.expectEqual(@as(u32, 7), curlCode(error.CouldNotConnect));
    try testing.expectEqual(@as(u32, 28), curlCode(error.OperationTimedOut));
    // A bound this build cannot keep is reported as the connection that
    // did not happen, because no connect was ever attempted.
    try testing.expectEqual(@as(u32, 7), curlCode(error.ConnectTimeoutUnsupported));
}

test "a name that did not resolve and a peer that did not answer keep different codes" {
    // curl exits 6 for one and 7 for the other. A script reads those two
    // numbers differently.
    try testing.expect(curlCode(error.CouldNotResolveHost) != curlCode(error.CouldNotConnect));
}

test "a socket that failed mid-handshake says so, and does not read as a failed connect" {
    // The connection was already open, so `CouldNotConnect` would send a
    // user to check reachability for a fault that happened after the
    // socket came up.
    const mapping = map(error.ConnectionResetByPeer);
    try testing.expectEqual(Error.SslConnectError, mapping.err);
    try testing.expect(std.mem.indexOf(u8, mapping.message.?, "handshake") != null);
}

test "a build with no concurrency says why the bound was refused" {
    const mapping = map(error.ConnectTimeoutUnsupported);
    try testing.expectEqual(Error.CouldNotConnect, mapping.err);
    try testing.expect(std.mem.indexOf(u8, mapping.message.?, "concurrency") != null);
}

test "every setup fault has a row, so none of them can fall through" {
    // The comptime check proves this at build time. This says the same
    // thing out loud, so a reader of the suite sees the rule without
    // reading the comptime block.
    inline for (@typeInfo(SetupError).error_set.?) |field| {
        const err: anyerror = @field(SetupError, field.name);
        try testing.expect(lookup(err) != null);
    }
}

test "every row maps to an error that has a libcurl code" {
    // A mapped error with no row in `zurl-core/errors.zig` would make
    // `curlCode` unreachable at run time. That file proves its own table
    // is complete, so this only has to prove this table stays inside it.
    //
    // **The round trip is what lets this test fail.** The body used to be
    // one call with its result discarded. Its only failure channel was the
    // `unreachable` in `curlCode`, which ReleaseFast removes, so in the
    // build a user runs it could not fail even in principle, and a
    // `curlCode` stubbed to `return 0;` passed it. Reading the code back
    // asserts a number, in every build.
    for (rows) |row| {
        const code = zurl_core.errors.curlCode(row.mapped);
        // Zero is `CURLE_OK`, which no fault may carry.
        try testing.expect(code != 0);
        try testing.expectEqual(row.mapped, zurl_core.errors.fromCurlCode(code).?);
    }
}

test "every fault the peer can cause carries a message" {
    // The exit code cannot carry the cause here. `SslConnectError` is one
    // number for every handshake that did not finish, and
    // `PeerFailedVerification` is one number for every check that refused
    // a certificate. So the sentence is the only channel left, and a row
    // with none reaches a user as a bare name over a host name.
    //
    // `TlsRecordOverflow` was such a row. A user read
    // `zurl: (35) SslConnectError: github.com` and learned nothing about
    // a peer that was answering in cleartext HTTP.
    for (rows) |row| {
        switch (row.mapped) {
            error.SslConnectError, error.PeerFailedVerification => {
                if (row.message == null) {
                    std.debug.print("row for {t} maps to {t} and names no cause\n", .{ row.err, row.mapped });
                    return error.TestExpectedMessage;
                }
                try testing.expect(row.message.?.len > 0);
            },
            else => {},
        }
    }
}

test "a record the peer sent too large says the peer may not be speaking TLS" {
    // This is what a redirect into TLS on a cleartext port looks like from
    // inside the handshake. A user who reads only `SslConnectError` has
    // nowhere to go.
    const mapping = map(error.TlsRecordOverflow);
    try testing.expectEqual(Error.SslConnectError, mapping.err);
    try testing.expect(std.mem.indexOf(u8, mapping.message.?, "TLS") != null);
}

test "every reason TCP_NODELAY can fail carries a sentence" {
    // The switch has no `else`, so the compiler already proves every
    // member has an arm. This proves each arm says something: a name such
    // as `OperationUnsupported` tells a user nothing about a slower
    // transfer, and the sentence is the only channel that can.
    inline for (@typeInfo(tcp.NoDelayError).error_set.?) |field| {
        const err: tcp.NoDelayError = @field(tcp.NoDelayError, field.name);
        const message = noDelayMessage(err);
        try testing.expect(message.len > 0);
        // The option is the one thing a user must be able to search for.
        try testing.expect(std.mem.indexOf(u8, message, "TCP_NODELAY") != null);
        // The cost is the reason the sentence exists at all.
        try testing.expect(std.mem.indexOf(u8, message, "40 ms") != null);
    }
}

test "a TCP_NODELAY sentence says the transfer is slow, not that it failed" {
    // The dial succeeded and the transfer runs. A sentence that read like
    // a fault would send a user to look for a broken connection that is
    // not there.
    const message = noDelayMessage(error.OperationUnsupported);
    try testing.expect(std.mem.indexOf(u8, message, "wait") != null);
    try testing.expect(std.mem.indexOf(u8, message, "fail") == null);
}

test "a host name over the bound is a resolve fault and a bad host is a url fault" {
    // curl 8.21.0 exits 6 for a name of 254 characters and 3 for text
    // that is not a host name at all. zurl answered 3 for both, so a
    // script could not tell a name it must shorten from a url it must
    // fix.
    const too_long = hostInit(error.HostNameTooLong);
    try testing.expectEqual(Error.CouldNotResolveHost, too_long.err);
    try testing.expectEqual(@as(u32, 6), zurl_core.errors.curlCode(too_long.err));

    const unreadable = hostInit(error.InvalidHost);
    try testing.expectEqual(Error.InvalidUrl, unreadable.err);
    try testing.expectEqual(@as(u32, 3), zurl_core.errors.curlCode(unreadable.err));
}

test "each host fault carries a sentence that says which one it is" {
    // The two exit codes send a user to two different places, and the
    // sentence is what says why. A shared sentence would undo the split.
    inline for (@typeInfo(tcp.Host.InitError).error_set.?) |field| {
        const err: tcp.Host.InitError = @field(tcp.Host.InitError, field.name);
        try testing.expect(hostInit(err).message.?.len > 0);
    }
    try testing.expect(!std.mem.eql(
        u8,
        hostInit(error.InvalidHost).message.?,
        hostInit(error.HostNameTooLong).message.?,
    ));
}

test "no two rows describe the same fault" {
    // A duplicated row keeps `checkCovered` happy while the second copy
    // is dead. It is also how two different meanings end up under one
    // name.
    for (rows, 0..) |row, i| {
        for (rows[i + 1 ..]) |other| {
            try testing.expect(row.err != other.err);
        }
    }
}

test "the two certificate purpose faults do not share a sentence" {
    // An earlier patch had no row for a leaf whose extended key usage is
    // wrong, so it reported that leaf as
    // `CertificateIssuerCannotSignCertificates`. A user then read that a
    // certificate which is no authority at all was "a certificate
    // authority that cannot sign certificates". The two are apart now,
    // and this keeps them apart.
    const not_an_authority = map(error.CertificateNotForServerAuth);
    const cannot_sign = map(error.CertificateIssuerCannotSignCertificates);
    try testing.expect(!std.mem.eql(u8, not_an_authority.message.?, cannot_sign.message.?));

    // The same for a name a constraint forbids against a certificate for
    // another name. A host mismatch sends a user to the url they typed,
    // and a forbidden name sends them to the authority that issued the
    // certificate.
    const not_permitted = map(error.CertificateNameNotPermitted);
    const mismatch = map(error.CertificateHostMismatch);
    try testing.expect(!std.mem.eql(u8, not_permitted.message.?, mismatch.message.?));
}
