//! Maps engine faults onto the zurl error taxonomy, and records diagnostics.
//!
//! `h1.zig` already turns every transport fault into an `engine.OpenError`
//! or an `engine.BodyError` (`mapSetupError`, `mapHeadError`). Most of
//! those names carry the same meaning as a `zurl_core.Error` of the same
//! name, but the two error sets are distinct Zig types, and a few
//! engine-only names have no `zurl_core.Error` counterpart at all. This
//! file is the one place that closes that gap and fills a `Diagnostics`,
//! so recovery is never silent.
//!
//! The sentence beside the name does not always come from here. A dial or
//! handshake fault carries its own, written by `zurl-net/errors.zig` and
//! handed over through `engine.Engine.cause`, because only that table
//! knows which check refused a peer. `mapError` keeps a caller's message
//! whenever it has one, which is what lets that sentence through.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");
const engine = @import("engine.zig");
const h1 = @import("h1.zig");

const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// One row of the map from a fault this package can produce to the
/// `zurl_core.Error` it means.
///
/// `message` is the sentence that says why the fault happened, for a fault
/// whose name alone does not say it. `mapError` records it when the caller
/// gave no message of its own, so a fault the caller cannot describe still
/// reaches the user with its cause. A null message leaves the line to the
/// error name.
const Row = struct { err: anyerror, mapped: Error, message: ?[]const u8 = null };

/// Why one response header line was refused, with the bound that refused
/// it.
///
/// The name `HeaderLineTooLarge` says what happened. This says how large is
/// too large, which is what a user needs to tell a server that sends a
/// little too much apart from one that sends a great deal. It also names
/// the line and not the head, so a user does not go looking for a head that
/// is in fact legal.
const header_line_too_large_message = std.fmt.comptimePrint(
    "one response header line reaches the {d} bytes this engine reads for a line",
    .{h1.head_field_len_max},
);

/// Why a whole response head was refused, with the bound that refused it.
///
/// Says the head together, to keep it apart from
/// `header_line_too_large_message`. A user who reads this looks at how many
/// headers the server sends, and not at how long one of them is.
const response_head_too_large_message = std.fmt.comptimePrint(
    "the response head is larger than the {d} bytes this engine reads",
    .{h1.head_len_max},
);

/// Why a content coding was refused, and what this build can decode.
///
/// The name alone sends a user to the `Content-Encoding` header. This adds
/// the other half: `--compressed` asked for the body decoded, and this
/// build has no decoder for the coding that came back. Naming the three it
/// does decode is what tells a user whether to change the server or to
/// drop the flag, and dropping the flag really is a fix, because a request
/// that asks for no decoding takes the octets as they arrive.
///
/// It names the decoders and not the offer, because the offer is not what
/// decides. See `engine.contentEncoding`.
const bad_content_encoding_message = std.fmt.comptimePrint(
    "--compressed asked for a decoded body and this build has no decoder for the " ++
        "content encoding the peer sent; it decodes {s}",
    .{h1.accept_encoding_value},
);

/// Why this engine refused a scheme.
///
/// The name alone leaves a user looking at the url they typed, and the
/// live cause is usually not that url: it is a `location:` header that
/// named another protocol. `zurl_core.redirect` refuses such a target, so
/// a server cannot move a transfer to `file` and read a local file. curl
/// says the same thing in its own words, `Protocol "file" is disabled (in
/// redirect)`, and gives it the same exit code.
///
/// **The sentence names the flag and not the engine.** It used to read
/// "this engine speaks http and https, and a redirect may not change to
/// another protocol", which named the wrong cause with full confidence: the
/// engine does change protocol, through the handoff in `zurl.Client`, and
/// `--proto-redir all` reaches `gopher://` today. The real cause is always
/// that the redirect list does not name the scheme, and that is what a user
/// can act on.
const unsupported_protocol_message =
    "--proto-redir does not name the protocol this redirect went to";

/// Why a request that had to go out twice did not.
///
/// The name says the body cannot restart. This says which bodies can and
/// which cannot, because a user answers the two differently: a file goes
/// back to its first byte and a pipe does not.
const request_body_not_resendable_message =
    "this request had to go out again, and a body read from a pipe cannot start over";

const rows = [_]Row{
    // Names that already carry the same meaning in `zurl_core.Error`.
    .{ .err = error.InvalidUrl, .mapped = error.InvalidUrl },
    .{
        .err = error.UnsupportedProtocol,
        .mapped = error.UnsupportedProtocol,
        .message = unsupported_protocol_message,
    },
    // The engine raises none of its own, and `Error` is one of the three
    // sets a caller can hand this file, so it needs a row like every other
    // name. `zurl.Client` is the one writer: see `Protocol.unread`.
    .{ .err = error.NotBuiltIn, .mapped = error.NotBuiltIn },
    .{ .err = error.CouldNotResolveHost, .mapped = error.CouldNotResolveHost },
    // The proxy's own name, kept apart from the origin's. A user who reads
    // that the host did not resolve looks at the url they typed, and the
    // name that did not resolve was in a `-x` flag or a shell profile.
    .{ .err = error.CouldNotResolveProxy, .mapped = error.CouldNotResolveProxy },
    .{ .err = error.CouldNotConnect, .mapped = error.CouldNotConnect },
    // A SOCKS handshake the proxy refused, and a proxy reply this build
    // cannot read. `Engine.cause` carries the sentence that says which.
    .{ .err = error.ProxyError, .mapped = error.ProxyError },
    .{ .err = error.SslConnectError, .mapped = error.SslConnectError },
    .{ .err = error.PeerFailedVerification, .mapped = error.PeerFailedVerification },
    .{ .err = error.CaCertBadFile, .mapped = error.CaCertBadFile },
    .{ .err = error.ReadError, .mapped = error.ReadError },
    // `--compressed` asked for a decoded body and this build has no
    // decoder for what came back. Nothing on the wire failed, so this
    // keeps a name of its own all the way to the exit code. curl answers
    // the same shape with exit 61, measured.
    .{
        .err = error.BadContentEncoding,
        .mapped = error.BadContentEncoding,
        .message = bad_content_encoding_message,
    },
    .{
        .err = error.HeaderLineTooLarge,
        .mapped = error.HeaderLineTooLarge,
        .message = header_line_too_large_message,
    },
    .{
        .err = error.ResponseHeadTooLarge,
        .mapped = error.ResponseHeadTooLarge,
        .message = response_head_too_large_message,
    },
    .{ .err = error.WriteError, .mapped = error.WriteError },
    .{ .err = error.TooManyRedirects, .mapped = error.TooManyRedirects },
    // The engine stopped a chain on a protocol it does not speak, and the
    // caller did not take the hop. A caller that can dispatch the scheme
    // never lets this reach the map: `zurl.Client.performHttp` reads
    // `h1.Engine.redirectHandoff` and runs the target itself. So this row
    // is the answer for a caller with no dispatch table of its own, and it
    // is the answer that url already had.
    .{
        .err = error.RedirectToOtherProtocol,
        .mapped = error.UnsupportedProtocol,
        .message = unsupported_protocol_message,
    },
    .{ .err = error.OperationTimedOut, .mapped = error.OperationTimedOut },
    .{ .err = error.OutOfMemory, .mapped = error.OutOfMemory },
    .{ .err = error.PartialFile, .mapped = error.PartialFile },

    // `engine.OpenError` names with no `zurl_core.Error` counterpart. Each
    // choice is a judgment call, documented here rather than left silent.

    // A header that would change the shape of the request on the wire is
    // refused before the engine writes anything. The nearest curl fault is
    // a write that did not happen as asked.
    .{ .err = error.InvalidHeader, .mapped = error.WriteError },
    // The engine had to send the request again and the body cannot go
    // back to its first byte, so the request never reached the wire a
    // second time. curl names this `CURLE_SEND_FAIL_REWIND`, exit 65,
    // which `zurl_core.Error` has no row for. The nearest name it does
    // have is a write that did not happen as asked.
    .{
        .err = error.RequestBodyNotResendable,
        .mapped = error.WriteError,
        .message = request_body_not_resendable_message,
    },
    // This build has no concurrency, so the engine cannot enforce the
    // caller's connect timeout and refuses the connect instead of
    // dropping the bound silently. No connect was attempted, so this
    // reports the connection that did not happen, not a timeout that was
    // never measured.
    .{ .err = error.ConnectTimeoutUnsupported, .mapped = error.CouldNotConnect },
    // A task cancel is how something outside the transfer stops it early,
    // the same shape as a callback answering "stop." No other
    // `zurl_core.Error` names an outside-initiated stop.
    .{ .err = error.Canceled, .mapped = error.AbortedByCallback },
    // An OS call failed in a way `std.Io` does not classify. Every place
    // this engine sees it today is on the connect path, so it reports the
    // connection that did not succeed, the same as any other unnamed
    // connect fault.
    .{ .err = error.Unexpected, .mapped = error.CouldNotConnect },

    // A peer certificate that fails verification maps to
    // `PeerFailedVerification`. `h1.zig` no longer hands these names over
    // one at a time: `zurl-net/errors.zig` holds one row for each of them
    // and reports `PeerFailedVerification` with the sentence that says
    // which check refused the peer, which reaches a user through
    // `engine.Engine.cause`. So the row right above, for
    // `PeerFailedVerification` itself, is the live path today.
    //
    // These rows stay because a caller may still hold one of these names,
    // and because a row is what stops a name falling through. Names come
    // from `std.crypto.Certificate.Certificate.VerifyError` and
    // `.VerifyHostNameError`.
    .{ .err = error.CertificateIssuerMismatch, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateNotYetValid, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateExpired, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateSignatureAlgorithmUnsupported, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateSignatureAlgorithmMismatch, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateFieldHasInvalidLength, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateFieldHasWrongDataType, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificatePublicKeyInvalid, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateSignatureInvalidLength, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateSignatureInvalid, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateSignatureUnsupportedBitCount, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateSignatureNamedCurveUnsupported, .mapped = error.PeerFailedVerification },
    .{ .err = error.CertificateHostMismatch, .mapped = error.PeerFailedVerification },

    // `zurl_core.Error` names with no engine counterpart. A caller that
    // already holds one of these passes it straight through, so the row
    // is the name itself. Without these rows the value fell to the
    // catch-all and reached the user as `CouldNotConnect`, exit 7,
    // whatever it really was.
    .{ .err = error.HttpReturnedError, .mapped = error.HttpReturnedError },
    .{ .err = error.RangeError, .mapped = error.RangeError },
    .{ .err = error.FileSizeExceeded, .mapped = error.FileSizeExceeded },
    .{ .err = error.AbortedByCallback, .mapped = error.AbortedByCallback },
    .{ .err = error.LoginDenied, .mapped = error.LoginDenied },
    // The front package builds the credential and checks it against the
    // header line bound, so this engine never raises this name itself. A
    // caller that already holds it still passes it through, and without a
    // row it would reach a user as `CouldNotConnect`.
    .{ .err = error.CredentialTooLarge, .mapped = error.CredentialTooLarge },
    .{ .err = error.RemoteFileNotFound, .mapped = error.RemoteFileNotFound },
    // A local read that would not start. No HTTP engine raises this: it
    // belongs to `zurl-file`. A caller that already holds it still passes
    // it through this map, and without a row it would reach a user as
    // `CouldNotConnect`, exit 7, for a file that was simply not there.
    .{ .err = error.FileCouldNotReadFile, .mapped = error.FileCouldNotReadFile },
    // The seven answers an RFC 1350 server can send. No HTTP engine raises
    // one: they belong to `zurl-tftp`. A caller that already holds one
    // still passes it through this map, and without a row each would reach
    // a user as `CouldNotConnect`, exit 7, where curl gives 68 through 74.
    .{ .err = error.TftpNotFound, .mapped = error.TftpNotFound },
    .{ .err = error.TftpPermission, .mapped = error.TftpPermission },
    .{ .err = error.TftpDiskFull, .mapped = error.TftpDiskFull },
    .{ .err = error.TftpIllegalOperation, .mapped = error.TftpIllegalOperation },
    .{ .err = error.TftpUnknownId, .mapped = error.TftpUnknownId },
    .{ .err = error.TftpFileExists, .mapped = error.TftpFileExists },
    .{ .err = error.TftpNoSuchUser, .mapped = error.TftpNoSuchUser },
    // The six FTP answers curl gives a number of its own. No HTTP engine
    // raises one: they belong to `zurl-ftp`. A caller that already holds
    // one still passes it through this map, and without a row each would
    // reach a user as `CouldNotConnect`, exit 7, where curl gives 8, 9,
    // 13, 14, 17, 31, or 64.
    .{ .err = error.WeirdServerReply, .mapped = error.WeirdServerReply },
    .{ .err = error.FtpAccessDenied, .mapped = error.FtpAccessDenied },
    .{ .err = error.FtpWeirdPasvReply, .mapped = error.FtpWeirdPasvReply },
    .{ .err = error.FtpWeird227Format, .mapped = error.FtpWeird227Format },
    .{ .err = error.FtpCouldNotSetType, .mapped = error.FtpCouldNotSetType },
    .{ .err = error.FtpCouldNotUseRest, .mapped = error.FtpCouldNotUseRest },
    .{ .err = error.UseSslFailed, .mapped = error.UseSslFailed },
    .{ .err = error.QuoteError, .mapped = error.QuoteError },
    .{ .err = error.SendError, .mapped = error.SendError },
    // The two LDAP answers curl gives a number of its own. No HTTP engine
    // raises one: they belong to `zurl-ldap`. A caller that already holds
    // one still passes it through this map, and without a row each would
    // reach a user as `CouldNotConnect`, exit 7, where curl gives 38 and
    // 39.
    .{ .err = error.LdapCannotBind, .mapped = error.LdapCannotBind },
    .{ .err = error.LdapSearchFailed, .mapped = error.LdapSearchFailed },
};

/// Every fault `mapError` accepts.
///
/// The three sets are exactly the three kinds of value a caller can hold:
/// the fault an `open` gave it, the fault a body read gave it, and a
/// `zurl_core.Error` it already mapped. A fault outside these three is a
/// compile error at the call, which is where it can be read, instead of a
/// silent `CouldNotConnect` at the user.
pub const MappableError = engine.OpenError || engine.BodyError || Error;

comptime {
    // Every fault a caller can hand this file must have a row. A row
    // count that matches the member count is not proof enough: a
    // duplicated row keeps the count right while a real name still has no
    // row. So this checks `MappableError` by name, the way
    // `zurl-core/errors.zig` checks its own error set.
    //
    // This is what closes the catch-all. `lookup` can still answer null
    // to the compiler, because it walks a runtime table, but no value of
    // `MappableError` can make it do so.
    checkCovered(MappableError);
}

fn checkCovered(comptime set: type) void {
    // One pass over `rows` for each member of `set`, and `MappableError`
    // holds about fifty members against about forty rows. The default
    // quota of a thousand branches does not cover that product.
    @setEvalBranchQuota(20_000);
    for (@typeInfo(set).error_set.?) |field| {
        const err: anyerror = @field(set, field.name);
        var found = false;
        for (rows) |row| {
            if (row.err == err) found = true;
        }
        if (!found) @compileError("errors.zig: error." ++ field.name ++ " has no row in `rows`");
    }
}

fn lookup(err: anyerror) ?Row {
    for (rows) |row| {
        if (row.err == err) return row;
    }
    return null;
}

/// Maps `err` onto the zurl error taxonomy and records `detail`, plus the
/// matching libcurl code, in `d`. Returns the mapped error.
///
/// A row that carries a `message` fills `detail.message` when the caller
/// left it empty. The caller knows which url failed. The row knows why the
/// fault happened. Neither one alone writes the whole line.
///
/// The return value lets a caller write `return mapError(...)` in one
/// line, so no recovery path can forget to fill the diagnostics.
///
/// `err` is `MappableError`, not `anyerror`. A caller holds one of three
/// things: the fault an `open` gave it, the fault a body read gave it, or
/// a `zurl_core.Error` it already has. `MappableError` is those three
/// together, and the comptime check above proves every member of it has a
/// row.
///
/// **The catch-all is gone.** `err` was `anyerror` and every name outside
/// the table became `error.CouldNotConnect`. That silently turned a
/// precise fault a caller already held, such as `HeaderLineTooLarge`
/// (exit 100), into exit 7. The comptime check covered only
/// `engine.OpenError` and `engine.BodyError`, so it proved nothing about
/// the `zurl_core.Error` the doc comment invited. Narrowing the parameter
/// makes such a value a compile error at the call, and the rows above now
/// carry every `zurl_core.Error` name, so a caller that legitimately holds
/// one gets that same name back.
///
/// `lookup` walks a runtime table, so the compiler cannot see that it
/// always finds a row. `unreachable` would answer that, and `unreachable`
/// is removed in ReleaseFast, which is the build a user runs. So the last
/// branch stays a branch, and it is loud: it keeps the fault's own name in
/// `message`, rather than pretending the connection failed.
pub fn mapError(err: MappableError, d: ?*Diagnostics, detail: Diagnostics.Detail) Error {
    const row = lookup(err) orelse {
        // Not reachable: `checkCovered(MappableError)` fails the build
        // before a name can arrive here with no row. It stays a branch
        // because the alternative disappears in a release build.
        return Diagnostics.record(d, error.ReadError, .{
            .url = detail.url,
            .host = detail.host,
            .status = detail.status,
            .message = detail.message orelse no_row_message,
        });
    };

    var filled = detail;
    if (filled.message == null) filled.message = row.message;
    return Diagnostics.record(d, row.mapped, filled);
}

/// What the user reads if a fault ever reaches `mapError` with no row.
///
/// It names the table, because that is where the fix goes. It does not
/// name the fault: a `[]const u8` built at runtime needs storage this
/// function does not own, and `Diagnostics.message` borrows.
const no_row_message = "this fault has no row in zurl-http/errors.zig, so zurl cannot name its cause";

const testing = std.testing;
const test_server = @import("test_server.zig");

test "a refused connection maps to CouldNotConnect and records the host" {
    // A port this process holds and never listens on refuses every attempt
    // at it, deterministically and without a live server.
    const port = try test_server.closedPort("127.0.0.1");

    var http_engine: h1.Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{port});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed }) catch |err| {
        var d: Diagnostics = .{};
        try testing.expectError(error.CouldNotConnect, @as(Error!void, mapError(err, &d, .{ .host = "127.0.0.1" })));
        try testing.expectEqualStrings("127.0.0.1", d.host.?);
        return;
    };
    exchange.close();
    try testing.expect(false); // a closed listener must refuse the connect
}

test "an unresolvable host maps to CouldNotResolveHost" {
    // A real lookup for an unresolvable name reaches the system resolver,
    // which can send a query out over the network. `h1.zig`'s own
    // `mapConnectError` already turns every DNS-lookup failure, an
    // unresolvable name included, into `error.CouldNotResolveHost` before
    // this layer would ever see it. So this drives `mapError` with that
    // same name directly, the way `Exchange.open` would call it, and never
    // asks the real resolver to look anything up.
    var d: Diagnostics = .{};
    try testing.expectError(
        error.CouldNotResolveHost,
        @as(Error!void, mapError(error.CouldNotResolveHost, &d, .{ .host = "does-not-exist.invalid" })),
    );
    try testing.expectEqualStrings("does-not-exist.invalid", d.host.?);
}

test "each response head bound keeps its own name, code, and cause" {
    // A head past a bound used to arrive as `ReadError`, which told a user
    // that a read failed and named no cause at all. Each bound now carries
    // the curl number curl carries for it, and a sentence with the bound
    // in it.
    //
    // The two numbers must differ. A single number for both would hide
    // which bound fired, and curl does not use one.
    var line_d: Diagnostics = .{};
    try testing.expectError(
        error.HeaderLineTooLarge,
        @as(Error!void, mapError(error.HeaderLineTooLarge, &line_d, .{ .host = "127.0.0.1" })),
    );
    try testing.expectEqual(@as(?u32, 100), line_d.curl_code);
    try testing.expectEqualStrings(header_line_too_large_message, line_d.message.?);

    var head_d: Diagnostics = .{};
    try testing.expectError(
        error.ResponseHeadTooLarge,
        @as(Error!void, mapError(error.ResponseHeadTooLarge, &head_d, .{ .host = "127.0.0.1" })),
    );
    try testing.expectEqual(@as(?u32, 56), head_d.curl_code);
    try testing.expectEqualStrings(response_head_too_large_message, head_d.message.?);

    // Each sentence names its own bound, so a user can tell a server that
    // sends one long line apart from one that sends a great many.
    var expected: [16]u8 = undefined;
    const line_bound = try std.fmt.bufPrint(&expected, "{d}", .{h1.head_field_len_max});
    try testing.expect(std.mem.indexOf(u8, line_d.message.?, line_bound) != null);

    var head_expected: [16]u8 = undefined;
    const head_bound = try std.fmt.bufPrint(&head_expected, "{d}", .{h1.head_len_max});
    try testing.expect(std.mem.indexOf(u8, head_d.message.?, head_bound) != null);

    // The two sentences must not read the same. A user who reads one and
    // then the other has to see which bound fired.
    try testing.expect(!std.mem.eql(u8, line_d.message.?, head_d.message.?));
}

test "a caller's own message wins over the one the row carries" {
    // The row's message is a fallback and not an override. A caller that
    // already knows more about the fault must not lose what it wrote.
    var d: Diagnostics = .{};
    try testing.expectError(
        error.HeaderLineTooLarge,
        @as(Error!void, mapError(error.HeaderLineTooLarge, &d, .{ .message = "the caller knew better" })),
    );
    try testing.expectEqualStrings("the caller knew better", d.message.?);
}

test "a certificate cause reaches the diagnostics beside exit 60" {
    // The two tables in one line, which is how a user meets them: the
    // sentence `zurl-net` wrote for the check that refused the peer, and
    // the exit code this table gives the name beside it.
    //
    // `PeerFailedVerification` carries no message of its own in the rows
    // above, on purpose. Only the layer that ran the handshake knows which
    // check refused the peer, so a message here would be a guess, and it
    // would win over the truth on the one path that has it.
    const faults = [_]zurl_net.errors.SetupError{
        error.CertificateExpired,
        error.CertificateHostMismatch,
        error.TlsCertificateNotVerified,
    };
    var seen: [faults.len][]const u8 = undefined;

    for (faults, 0..) |fault, i| {
        // What `h1.mapSetupError` reads, and what `engine.Engine.cause`
        // then hands to the call below.
        const cause = zurl_net.errors.map(fault).message;

        var d: Diagnostics = .{};
        try testing.expectError(
            error.PeerFailedVerification,
            @as(Error!void, mapError(error.PeerFailedVerification, &d, .{
                .host = "peer.example",
                .message = cause,
            })),
        );
        try testing.expectEqual(@as(u32, 60), d.curl_code.?);
        seen[i] = d.message orelse return error.TestExpectedCause;
    }

    // Three faults, three sentences. One sentence three times would leave
    // a user with exit 60 and no way to tell which check refused the peer,
    // which is the state this work started from.
    try testing.expect(!std.mem.eql(u8, seen[0], seen[1]));
    try testing.expect(!std.mem.eql(u8, seen[0], seen[2]));
    try testing.expect(!std.mem.eql(u8, seen[1], seen[2]));
}

test "a zurl_core fault that no engine can raise keeps its own name and code" {
    // `HttpReturnedError`, `RangeError`, `FileSizeExceeded`,
    // `AbortedByCallback`, `LoginDenied`, and `RemoteFileNotFound` are
    // members of `zurl_core.Error` and of neither `engine.OpenError` nor
    // `engine.BodyError`. The comptime check used to cover only those two
    // sets, so each of these fell to the catch-all and reached the user as
    // `CouldNotConnect`, exit 7. Every one of them now keeps its own name
    // and its own curl number.
    const outside = [_]Error{
        error.HttpReturnedError,
        error.RangeError,
        error.FileSizeExceeded,
        error.AbortedByCallback,
        error.LoginDenied,
        error.RemoteFileNotFound,
        error.FileCouldNotReadFile,
    };
    for (outside) |err| {
        var d: Diagnostics = .{};
        const mapped = mapError(err, &d, .{ .host = "127.0.0.1" });
        try testing.expectEqual(err, mapped);
        try testing.expect(mapped != error.CouldNotConnect);
        try testing.expectEqual(zurl_core.errors.curlCode(err), d.curl_code.?);
    }
}

test "a bound that is not the connection keeps the exit code the bound earns" {
    // The shape the old catch-all hid: a caller holds a precise
    // `zurl_core.Error` and hands it on. `HeaderLineTooLarge` is
    // `CURLE_TOO_LARGE`, which is 100. Exit 7 there sends a user to look
    // at the network for a fault the server caused.
    var d: Diagnostics = .{};
    const mapped = mapError(@as(Error, error.HeaderLineTooLarge), &d, .{});
    try testing.expectEqual(@as(Error, error.HeaderLineTooLarge), mapped);
    try testing.expectEqual(@as(?u32, 100), d.curl_code.?);
}

test "every zurl_core fault has a row, so none of them can fall through" {
    // The comptime check proves this at build time. This test says the
    // same thing out loud, so a reader of the suite sees the rule without
    // reading the comptime block.
    inline for (@typeInfo(Error).error_set.?) |field| {
        const err: anyerror = @field(Error, field.name);
        try testing.expect(lookup(err) != null);
    }
}

test "exceeding the redirect limit maps to TooManyRedirects" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: h1.Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 2 } }) catch |err| {
        var d: Diagnostics = .{};
        try testing.expectError(error.TooManyRedirects, @as(Error!void, mapError(err, &d, .{})));
        return;
    };
    exchange.close();
    try testing.expect(false); // three redirects must exceed a limit of two
}

test "every mapped error carries a curl code in the diagnostics" {
    // Reuses the redirect-limit scenario rather than repeating the
    // connection-refused one above, so this pins the diagnostics wiring
    // against an independent kind of failure.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: h1.Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 2 } }) catch |err| {
        var d: Diagnostics = .{};
        const mapped = mapError(err, &d, .{});
        try testing.expectEqual(zurl_core.errors.curlCode(mapped), d.curl_code.?);
        return;
    };
    exchange.close();
    try testing.expect(false); // three redirects must exceed a limit of two
}
