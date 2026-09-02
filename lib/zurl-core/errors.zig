//! The zurl error taxonomy, and its map to and from libcurl result codes.
//!
//! The map is public because two callers need it. The bindings phase needs it
//! to return a `CURLcode`. A caller that replaces libcurl needs it to keep the
//! error names that its own code already uses.

const std = @import("std");

/// Every runtime fault that a zurl transfer can report.
///
/// These are runtime faults, not programmer errors. A programmer error is an
/// assertion, not a member of this set.
pub const Error = error{
    /// The URL does not parse.
    InvalidUrl,
    /// No protocol handler is built in for this scheme.
    UnsupportedProtocol,
    /// The transfer asked for something this build does not do for the
    /// protocol in hand.
    ///
    /// **This is the answer to a control that would otherwise fail open.**
    /// A protocol package reads the fields of `Transfer.Options` it knows
    /// and drops the rest with no sign, so a user who asked for a proxy or
    /// for authentication got neither and no diagnostic. A silent drop of
    /// a privacy control or of a credential is worse than a refusal, so
    /// the combination is refused by name. A `Diagnostics.message` beside
    /// this says which option and which protocol.
    ///
    /// curl answers the same shape with `CURLE_NOT_BUILT_IN`, exit 4: a
    /// feature, protocol, or option that this build does not carry.
    NotBuiltIn,
    /// The host name has no address.
    CouldNotResolveHost,
    /// The proxy's host name has no address.
    ///
    /// Kept apart from `CouldNotResolveHost` because the two send a user to
    /// two different places. A url that does not resolve is a url the user
    /// typed. A proxy that does not resolve came from a `-x` flag, from a
    /// `--socks5` flag, or from an `http_proxy` in a shell profile the user
    /// may have forgotten about, and a message naming the url would send
    /// them to look at the wrong name.
    ///
    /// curl answers the same pair with two codes, `CURLE_COULDNT_RESOLVE_HOST`
    /// and `CURLE_COULDNT_RESOLVE_PROXY`. Measured against curl 8.21.0: a
    /// proxy host that does not resolve gave exit 5.
    CouldNotResolveProxy,
    /// The connection attempt did not succeed.
    CouldNotConnect,
    /// The proxy did not give a usable route to the origin.
    ///
    /// This is the SOCKS handshake refusing, a proxy reply this build
    /// cannot read, and a proxy that wrote bytes before its tunnel could
    /// carry any. A `Diagnostics.message` beside this says which of them
    /// happened, and it never holds a credential.
    ///
    /// A `CONNECT` that the proxy answered with a status is not this name.
    /// Measured against curl 8.21.0: a proxy answering `403` or `407` to a
    /// `CONNECT` gave exit 7, the code a refused connection gives, because
    /// no connection to the origin exists either way. So that path reports
    /// `CouldNotConnect` with the reason in the message.
    ///
    /// curl answers a refused SOCKS handshake with `CURLE_PROXY`, exit 97.
    /// Measured with a listener that answered `05 ff`, no acceptable
    /// method, and with one that answered a refused request.
    ProxyError,
    /// A read from the peer did not succeed.
    ReadError,
    /// The peer sent one response header line larger than the engine reads.
    ///
    /// This is the first of the two bounds zurl keeps on a response head,
    /// and it is the smaller one. It describes a single line, not the head
    /// together. A head of many short lines that comes to more than this
    /// number is legal, and `ResponseHeadTooLarge` is the bound that
    /// describes it.
    ///
    /// This is its own name, and not `ReadError`, because the cause is a
    /// bound that zurl keeps and not a fault on the wire. A user who reads
    /// `ReadError` looks at the network. A user who reads this one looks
    /// at the server, which is where the cause is.
    ///
    /// curl reports the same fault as `CURLE_TOO_LARGE`, so a caller that
    /// already reads curl codes gets the number it expects. See
    /// `zurl_http.h1.head_field_len_max` for the size of the bound.
    ///
    /// This member was named `HeadersTooLarge` while zurl kept one bound.
    /// The plural name described the head together, which is now the other
    /// bound, so the name moved with the meaning.
    HeaderLineTooLarge,
    /// The peer sent a whole response head larger than the engine reads.
    ///
    /// This is the second of the two bounds zurl keeps on a response head,
    /// and it is the larger one. It counts every byte of the head together,
    /// the status line and the empty line included. One line inside a legal
    /// head can still be too long on its own; `HeaderLineTooLarge` is the
    /// bound that describes that.
    ///
    /// curl reports the same fault as `CURLE_RECV_ERROR`, and not as the
    /// `CURLE_TOO_LARGE` that one long line gets, so a caller that already
    /// reads curl codes gets the number it expects. See
    /// `zurl_http.h1.head_len_max` for the size of the bound.
    ResponseHeadTooLarge,
    /// A write to the peer or to the output did not succeed.
    WriteError,
    /// The transfer stopped before the announced length arrived.
    PartialFile,
    /// The server answered with a status that the caller asked zurl to treat
    /// as a failure.
    HttpReturnedError,
    /// The transfer took longer than its limit, or it stalled.
    OperationTimedOut,
    /// The requested byte range is not usable.
    RangeError,
    /// The TLS handshake did not succeed.
    SslConnectError,
    /// The redirect count went over its limit.
    TooManyRedirects,
    /// The peer certificate did not verify.
    PeerFailedVerification,
    /// A certificate file did not load. `--cacert`, `CURL_CA_BUNDLE`, or
    /// `SSL_CERT_FILE` named a file that zurl could not read as
    /// certificates.
    CaCertBadFile,
    /// The transfer went over its size limit.
    FileSizeExceeded,
    /// The transfer asked for a decoded body and the peer answered in a
    /// content encoding zurl has no decoder for.
    ///
    /// **Only a transfer that asked for decoding can report this.**
    /// `--compressed` is the promise that the body comes back decoded, and
    /// a coding with no decoder breaks it: handing the compressed octets
    /// over writes a file no reader can open and reports success for it.
    /// A transfer that asked for no decoding takes whatever the peer sent
    /// and writes it out, which is what curl does, so an unsolicited
    /// `Content-Encoding` never reaches this name.
    ///
    /// This is its own name, and not `ReadError`, because the wire was
    /// fine. The peer wrote every octet it promised. The fault is in the
    /// one header, and a user who reads this looks at the server and not
    /// at the network. Dropping `--compressed` is also a fix.
    ///
    /// curl reports the same fault as `CURLE_BAD_CONTENT_ENCODING`, exit
    /// 61, so a caller that already reads curl codes gets the number it
    /// expects.
    BadContentEncoding,
    /// A callback stopped the transfer.
    AbortedByCallback,
    /// The credentials were not accepted.
    LoginDenied,
    /// The credential is too long to send in one `Authorization` header
    /// line.
    ///
    /// This is zurl's own bound and not a server's answer, so it is not
    /// `LoginDenied`: the server never saw the credential. It is not
    /// `InvalidUrl` either, which is what an earlier zurl reported. The
    /// url can be perfectly well formed while a netrc file holds a token
    /// too long for a header line, and a user who reads that the url is
    /// malformed looks at the wrong thing.
    ///
    /// A `Diagnostics.message` beside this names which source held the
    /// credential, and how long the header line would be. It never holds
    /// the credential.
    ///
    /// curl answers an over-long credential with
    /// `CURLE_BAD_FUNCTION_ARGUMENT`: `setstropt` refuses a `CURLOPT_USERPWD`,
    /// `CURLOPT_USERNAME`, or `CURLOPT_PASSWORD` string past
    /// `CURL_MAX_INPUT_LENGTH` with that code. So a caller that already
    /// reads curl codes gets the number curl gives for the same fault.
    CredentialTooLarge,
    /// A `file://` url named something zurl could not read.
    ///
    /// One name for every reason a local read did not start: the path is
    /// not there, the user may not open it, or a component of it is not a
    /// directory. curl answers all of them with the same code and the same
    /// sentence, `Could not open file <path>`, measured against curl
    /// 8.21.0 on a missing path and on a file with mode 000. A
    /// `Diagnostics.message` beside this names the operating system's own
    /// reason, so the detail curl drops is still there to read.
    ///
    /// This is not `RemoteFileNotFound`. That name is a server's answer,
    /// exit 78, and it says a peer looked and did not find. This one says
    /// no peer was involved at all.
    FileCouldNotReadFile,
    /// The named file is not on the server.
    RemoteFileNotFound,
    // The seven names below are the RFC 1350 error codes a TFTP server can
    // send back, one name for each. They are apart from the names above
    // because curl gives each of them an exit code of its own, 68 through
    // 74, and a script that branches on those numbers reads the same ones
    // here. Collapsing them into `RemoteFileNotFound` and `ReadError`
    // would give a user two numbers where curl gives seven, and the two
    // would be the wrong ones.
    /// A TFTP server answered `File not found`, RFC 1350 error code 1.
    ///
    /// Not `RemoteFileNotFound`, which is exit 78. curl answers this one
    /// with exit 68, `CURLE_TFTP_NOTFOUND`, and its manual page lists the
    /// two separately.
    TftpNotFound,
    /// A TFTP server answered `Access violation`, RFC 1350 error code 2.
    TftpPermission,
    /// A TFTP server answered `Disk full or allocation exceeded`, RFC 1350
    /// error code 3.
    TftpDiskFull,
    /// A TFTP server answered `Illegal TFTP operation`, RFC 1350 error
    /// code 4.
    ///
    /// This name also covers a request zurl refuses to send at all. curl
    /// 8.21.0 answers `tftp://host/`, which names no file, with exit 71
    /// and sends no datagram, measured.
    TftpIllegalOperation,
    /// A TFTP server answered `Unknown transfer ID`, RFC 1350 error code
    /// 5.
    TftpUnknownId,
    /// A TFTP server answered `File already exists`, RFC 1350 error code
    /// 6.
    TftpFileExists,
    /// A TFTP server answered `No such user`, RFC 1350 error code 7.
    TftpNoSuchUser,
    /// An LDAP `BindRequest` did not succeed, and the reason is not one
    /// the four names below cover.
    ///
    /// **Not `LoginDenied`, and the two are told apart the way curl tells
    /// them apart.** curl 8.21.0's `oldap_map_error` turns an LDAP
    /// `invalidCredentials`, RFC 4511 result code 49, into
    /// `CURLE_LOGIN_DENIED`, exit 67, and leaves every other bind failure
    /// as `CURLE_LDAP_CANNOT_BIND`, exit 38. Measured against curl 8.21.0
    /// on a real slapd 2.6.13: a wrong password gave exit 67 and a bind
    /// name that is not a distinguished name gave exit 38. A user who
    /// reads 67 checks the password, and a user who reads 38 checks what
    /// they typed for the name.
    LdapCannotBind,
    /// An LDAP `SearchRequest` came back with a result code that is not
    /// success.
    ///
    /// curl answers the same with `CURLE_LDAP_SEARCH_FAILED`, exit 39,
    /// measured: a base object that is not in the directory gave exit 39
    /// and the words `search failed No such object`.
    ///
    /// A few LDAP result codes reach other names first, and they are the
    /// same few curl maps: `protocolError` is `UnsupportedProtocol`, exit
    /// 1, and `insufficientAccessRights` is `FtpAccessDenied`, exit 9.
    /// See `zurl_ldap.Fetcher.mapResultCode`.
    LdapSearchFailed,
    // The six names below are the FTP answers curl gives an exit code of
    // its own. They are apart from the names above for the reason the
    // TFTP block gives: a script branches on the number, and collapsing
    // them would hand a user one number where curl gives six.
    /// A server sent something no reply grammar reads.
    ///
    /// The first line of a reply carried no three digit code, or a reply
    /// ran past the line count or the byte count zurl reads. Any of the
    /// three leaves the session with no way to tell which answer belongs
    /// to which command, so the transfer ends rather than read the answer
    /// to one command as the answer to another.
    ///
    /// curl reports the same fault as `CURLE_WEIRD_SERVER_REPLY`, exit 8.
    WeirdServerReply,
    /// The server refused to change to a directory the url named.
    ///
    /// This is a `CWD` that did not work. curl answers it with exit 9,
    /// `CURLE_REMOTE_ACCESS_DENIED`, and the sentence `Server denied you
    /// to change to the given directory`, measured against curl 8.21.0 on
    /// a loopback server answering `550` to `CWD`.
    ///
    /// Not `RemoteFileNotFound`, exit 78: that name is the answer to a
    /// `RETR`, and a user who reads it looks for a file. This one says the
    /// path above the file is the part that failed.
    FtpAccessDenied,
    /// A `PASV` or an `EPSV` was refused, or its answer named no port.
    ///
    /// curl answers this with exit 13, `CURLE_FTP_WEIRD_PASV_REPLY`.
    FtpWeirdPasvReply,
    /// A `227` answer did not hold six numbers in brackets.
    ///
    /// curl answers this with exit 14, `CURLE_FTP_WEIRD_227_FORMAT`, and
    /// the sentence `Could not interpret the 227-response`, measured.
    ///
    /// Its own name and not `FtpWeirdPasvReply`, because curl gives the
    /// two different numbers: a server that refused the command and a
    /// server that answered it with text nobody can read are different
    /// faults to a person reading a log.
    FtpWeird227Format,
    /// The server refused to set the representation type.
    ///
    /// This is a `TYPE I` or a `TYPE A` that did not work. curl answers it
    /// with exit 17, `CURLE_FTP_COULDNT_SET_TYPE`, and the sentence
    /// `Could not set desired mode`, measured.
    FtpCouldNotSetType,
    /// The server refused to restart the transfer at an offset.
    ///
    /// This is a `REST` that did not work, which is `-C` on an `ftp://`
    /// url. curl answers it with exit 31, `CURLE_FTP_COULDNT_USE_REST`,
    /// and the sentence `Could not use REST`, measured.
    FtpCouldNotUseRest,
    /// The transfer asked for TLS and did not get it.
    ///
    /// The server refused `AUTH TLS`, or it refused `PBSZ` or `PROT P`,
    /// which are what put the data connection inside the session.
    ///
    /// **There is no fallback to a session without TLS on this path, and
    /// there must not be.** A transfer that asked for TLS and carried on
    /// without it would send the credential in the clear, to a peer that
    /// nothing verified. curl answers the same shape with exit 64,
    /// `CURLE_USE_SSL_FAILED`, and sends no `USER` at all, measured with
    /// `--ssl-reqd` against a server answering `504` to `AUTH`.
    UseSslFailed,
    /// A command that names no file and no message was refused.
    ///
    /// This is an IMAP `LIST` that the server answered `NO` or `BAD`, and
    /// a `--request` command on a mail url that the server refused. curl
    /// answers the same shape with exit 21, `CURLE_QUOTE_ERROR`, and the
    /// sentence `Quote command returned error`, measured against curl
    /// 8.21.0 on a loopback IMAP fixture answering `NO` to `LIST`.
    ///
    /// Its own name and not `RemoteFileNotFound`, exit 78, because curl
    /// gives the two different numbers: a `FETCH` that found no message
    /// and a `LIST` that the server would not run are different faults to
    /// a person reading a log.
    QuoteError,
    /// A command that hands a message over was refused.
    ///
    /// This is an SMTP `MAIL FROM`, `RCPT TO`, or `DATA` that the server
    /// answered with a 4yz or a 5yz. curl answers the same shape with exit
    /// 55, `CURLE_SEND_ERROR`, and the sentences `MAIL failed: 550`,
    /// `RCPT failed: 550`, and `DATA failed: 550`, measured against curl
    /// 8.21.0 on a loopback SMTP fixture refusing each in turn.
    ///
    /// **The message did not go out.** A user who reads this knows the
    /// mail was not sent, which is the one thing that matters about a
    /// failed send.
    SendError,
    /// zurl ran out of memory.
    OutOfMemory,
};

/// One row of the map between `Error` and a libcurl result code.
const Row = struct { err: Error, code: u32 };

/// The map, in libcurl code order. The numbers are the `CURLE_*` values.
///
/// Add a row when you add an error. The round-trip test fails if you forget.
const rows = [_]Row{
    .{ .err = error.UnsupportedProtocol, .code = 1 }, // CURLE_UNSUPPORTED_PROTOCOL
    .{ .err = error.NotBuiltIn, .code = 4 }, // CURLE_NOT_BUILT_IN
    .{ .err = error.InvalidUrl, .code = 3 }, // CURLE_URL_MALFORMAT
    .{ .err = error.CouldNotResolveProxy, .code = 5 }, // CURLE_COULDNT_RESOLVE_PROXY
    .{ .err = error.CouldNotResolveHost, .code = 6 }, // CURLE_COULDNT_RESOLVE_HOST
    .{ .err = error.CouldNotConnect, .code = 7 }, // CURLE_COULDNT_CONNECT
    .{ .err = error.ProxyError, .code = 97 }, // CURLE_PROXY
    .{ .err = error.WeirdServerReply, .code = 8 }, // CURLE_WEIRD_SERVER_REPLY
    .{ .err = error.FtpAccessDenied, .code = 9 }, // CURLE_REMOTE_ACCESS_DENIED
    .{ .err = error.FtpWeirdPasvReply, .code = 13 }, // CURLE_FTP_WEIRD_PASV_REPLY
    .{ .err = error.FtpWeird227Format, .code = 14 }, // CURLE_FTP_WEIRD_227_FORMAT
    .{ .err = error.FtpCouldNotSetType, .code = 17 }, // CURLE_FTP_COULDNT_SET_TYPE
    .{ .err = error.PartialFile, .code = 18 }, // CURLE_PARTIAL_FILE
    .{ .err = error.FtpCouldNotUseRest, .code = 31 }, // CURLE_FTP_COULDNT_USE_REST
    .{ .err = error.QuoteError, .code = 21 }, // CURLE_QUOTE_ERROR
    .{ .err = error.SendError, .code = 55 }, // CURLE_SEND_ERROR
    .{ .err = error.UseSslFailed, .code = 64 }, // CURLE_USE_SSL_FAILED
    .{ .err = error.HttpReturnedError, .code = 22 }, // CURLE_HTTP_RETURNED_ERROR
    .{ .err = error.WriteError, .code = 23 }, // CURLE_WRITE_ERROR
    .{ .err = error.ReadError, .code = 26 }, // CURLE_READ_ERROR
    .{ .err = error.OutOfMemory, .code = 27 }, // CURLE_OUT_OF_MEMORY
    .{ .err = error.OperationTimedOut, .code = 28 }, // CURLE_OPERATION_TIMEDOUT
    .{ .err = error.RangeError, .code = 33 }, // CURLE_RANGE_ERROR
    .{ .err = error.SslConnectError, .code = 35 }, // CURLE_SSL_CONNECT_ERROR
    .{ .err = error.FileCouldNotReadFile, .code = 37 }, // CURLE_FILE_COULDNT_READ_FILE
    .{ .err = error.CredentialTooLarge, .code = 43 }, // CURLE_BAD_FUNCTION_ARGUMENT
    .{ .err = error.ResponseHeadTooLarge, .code = 56 }, // CURLE_RECV_ERROR
    .{ .err = error.AbortedByCallback, .code = 42 }, // CURLE_ABORTED_BY_CALLBACK
    .{ .err = error.TooManyRedirects, .code = 47 }, // CURLE_TOO_MANY_REDIRECTS
    .{ .err = error.PeerFailedVerification, .code = 60 }, // CURLE_PEER_FAILED_VERIFICATION
    .{ .err = error.FileSizeExceeded, .code = 63 }, // CURLE_FILESIZE_EXCEEDED
    .{ .err = error.BadContentEncoding, .code = 61 }, // CURLE_BAD_CONTENT_ENCODING
    .{ .err = error.LdapCannotBind, .code = 38 }, // CURLE_LDAP_CANNOT_BIND
    .{ .err = error.LdapSearchFailed, .code = 39 }, // CURLE_LDAP_SEARCH_FAILED
    .{ .err = error.LoginDenied, .code = 67 }, // CURLE_LOGIN_DENIED
    .{ .err = error.TftpNotFound, .code = 68 }, // CURLE_TFTP_NOTFOUND
    .{ .err = error.TftpPermission, .code = 69 }, // CURLE_TFTP_PERM
    .{ .err = error.TftpDiskFull, .code = 70 }, // CURLE_REMOTE_DISK_FULL
    .{ .err = error.TftpIllegalOperation, .code = 71 }, // CURLE_TFTP_ILLEGAL
    .{ .err = error.TftpUnknownId, .code = 72 }, // CURLE_TFTP_UNKNOWNID
    .{ .err = error.TftpFileExists, .code = 73 }, // CURLE_REMOTE_FILE_EXISTS
    .{ .err = error.TftpNoSuchUser, .code = 74 }, // CURLE_TFTP_NOSUCHUSER
    .{ .err = error.CaCertBadFile, .code = 77 }, // CURLE_SSL_CACERT_BADFILE
    .{ .err = error.RemoteFileNotFound, .code = 78 }, // CURLE_REMOTE_FILE_NOT_FOUND
    .{ .err = error.HeaderLineTooLarge, .code = 100 }, // CURLE_TOO_LARGE
};

comptime {
    // A missing row makes `curlCode` unreachable at run time, which is a bad
    // way to find out. Fail the build instead.
    //
    // A row count that matches the error count is not enough proof: a
    // duplicated row keeps the count right while still leaving one error
    // with no row. So this checks every error by name, the way `ca.zig`
    // checks `max_sources`.
    //
    // One pass over `rows` for each member of `Error`, and the two are
    // about forty each. The default quota of a thousand branches does not
    // cover that product.
    @setEvalBranchQuota(20_000);
    for (@typeInfo(Error).error_set.?) |field| {
        const err = @field(Error, field.name);
        var found = false;
        for (rows) |row| {
            if (row.err == err) found = true;
        }
        if (!found) @compileError("errors.zig: error." ++ field.name ++ " has no row in `rows`");
    }
}

/// Returns the libcurl result code for `err`.
pub fn curlCode(err: Error) u32 {
    for (rows) |row| {
        if (row.err == err) return row.code;
    }
    // The comptime block above proves every error has a row.
    unreachable;
}

/// Returns the error for a libcurl result code, or null if no error matches.
///
/// The code comes from outside zurl, so an unknown code is a runtime fault and
/// not an assertion.
pub fn fromCurlCode(code: u32) ?Error {
    for (rows) |row| {
        if (row.code == code) return row.err;
    }
    return null;
}

test "each error maps to its libcurl code and back" {
    try std.testing.expectEqual(@as(u32, 3), curlCode(error.InvalidUrl));
    try std.testing.expectEqual(@as(u32, 28), curlCode(error.OperationTimedOut));
    try std.testing.expectEqual(@as(u32, 60), curlCode(error.PeerFailedVerification));
    try std.testing.expectEqual(Error.InvalidUrl, fromCurlCode(3).?);
    try std.testing.expectEqual(Error.TooManyRedirects, fromCurlCode(47).?);
}

test "each response head bound carries the curl code curl carries" {
    // curl keeps two bounds on a response head and answers them with two
    // different numbers. A zurl that answered either one with the other's
    // number would send a script down a different branch than curl does.
    //
    // Measured against curl 8.21.0: one header line of 102400 bytes gives
    // exit 100, and a head of 307201 bytes built of short lines gives exit
    // 56.
    try std.testing.expectEqual(@as(u32, 100), curlCode(error.HeaderLineTooLarge));
    try std.testing.expectEqual(Error.HeaderLineTooLarge, fromCurlCode(100).?);
    try std.testing.expectEqual(@as(u32, 56), curlCode(error.ResponseHeadTooLarge));
    try std.testing.expectEqual(Error.ResponseHeadTooLarge, fromCurlCode(56).?);
}

test "a credential too long is its own code and not the code for a bad url" {
    // The defect: a netrc token too long for the buffer reported
    // `error.InvalidUrl`, which is exit 3, `CURLE_URL_MALFORMAT`. A
    // script that branches on 3 went down the "fix your url" path for a
    // url that was already right.
    try std.testing.expectEqual(@as(u32, 43), curlCode(error.CredentialTooLarge));
    try std.testing.expectEqual(Error.CredentialTooLarge, fromCurlCode(43).?);
    try std.testing.expect(curlCode(error.CredentialTooLarge) != curlCode(error.InvalidUrl));
    try std.testing.expect(curlCode(error.CredentialTooLarge) != curlCode(error.LoginDenied));
}

test "a local file that will not open is curl's own code for it" {
    // Measured against curl 8.21.0: `file:///nonexistent/x` and a file
    // with mode 000 both give exit 37. A script that branches on 37 for
    // curl reads the same number from zurl.
    try std.testing.expectEqual(@as(u32, 37), curlCode(error.FileCouldNotReadFile));
    try std.testing.expectEqual(Error.FileCouldNotReadFile, fromCurlCode(37).?);
    // A server that looked and did not find is a different fault with a
    // different number.
    try std.testing.expect(curlCode(error.FileCouldNotReadFile) != curlCode(error.RemoteFileNotFound));
}

test "each TFTP answer carries the number curl's own manual page lists" {
    // curl 8.21.0's manual page lists 68 through 74 for these seven, in
    // this order. A script that branches on curl's number reads the same
    // number here.
    try std.testing.expectEqual(@as(u32, 68), curlCode(error.TftpNotFound));
    try std.testing.expectEqual(@as(u32, 69), curlCode(error.TftpPermission));
    try std.testing.expectEqual(@as(u32, 70), curlCode(error.TftpDiskFull));
    try std.testing.expectEqual(@as(u32, 71), curlCode(error.TftpIllegalOperation));
    try std.testing.expectEqual(@as(u32, 72), curlCode(error.TftpUnknownId));
    try std.testing.expectEqual(@as(u32, 73), curlCode(error.TftpFileExists));
    try std.testing.expectEqual(@as(u32, 74), curlCode(error.TftpNoSuchUser));

    // A file a TFTP server did not find is not the same fault as a file
    // an HTTP or FTP server did not find, and the two numbers differ.
    try std.testing.expect(curlCode(error.TftpNotFound) != curlCode(error.RemoteFileNotFound));
}

test "an unknown libcurl code maps to null" {
    try std.testing.expectEqual(@as(?Error, null), fromCurlCode(9999));
}

test "the map is a round trip for every error" {
    inline for (@typeInfo(Error).error_set.?) |field| {
        const err = @field(Error, field.name);
        const code = curlCode(err);
        try std.testing.expectEqual(err, fromCurlCode(code).?);
    }
}
