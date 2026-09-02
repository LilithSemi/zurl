//! zurl's `rtsp://` protocol, RFC 2326.
//!
//! One protocol, one module. A build that does not want to talk to a
//! camera or a media server leaves this module out and loses nothing else,
//! and a program outside this repository takes this module, `zurl-core`,
//! and `zurl-net` and gets the scheme with no other part of zurl.
//!
//! **One scheme, and no TLS twin.** RFC 2326 registers `rtsp` and `rtspu`,
//! and neither is a TLS scheme. `rtsps` belongs to RTSP 2.0, RFC 7826,
//! which this build does not speak, and curl 8.21.0 carries no `rtsps`
//! either: its `--version` protocol line lists `rtsp` alone, measured. So
//! this package registers one scheme where `zurl-mqtt` and `zurl-ldap`
//! register two.
//!
//! **This package does not import `zurl`, and it never will**: the front
//! package imports no protocol package, and a protocol package that
//! imported it back could not be left out. `Fetcher.protocol` takes the
//! front package's namespace as a comptime parameter instead.
//!
//! A caller wires it in three lines:
//!
//!     const fetcher = try zurl_rtsp.Fetcher.create(gpa, io);
//!     defer fetcher.destroy();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!
//! ## What this package is
//!
//! **RTSP looks like HTTP and is not HTTP.** It borrows the request line,
//! the header block, and the status line, and then it changes what those
//! carry:
//!
//! - The target of a request is an **absolute url** and not a path. RFC
//!   2326 section 6.1. `target.zig` builds one.
//! - Every request and every reply carries a **`CSeq`**, RFC 2326 section
//!   12.17, and a reply must echo the number it was sent. `Session.zig`
//!   checks it, and a mismatch is a protocol error and not something to
//!   skip: a session that read past one would be reading the answer to one
//!   request as the answer to another.
//! - There is **no chunked coding and no read-until-close**. A reply with
//!   no `Content-Length` has no body, RFC 2326 section 4.4.
//! - A server may send a **request** to a client, and it may put binary
//!   media on the control connection behind a `$`. This build reads
//!   neither. See `Session.interleave_marker`.
//!
//! ## The two rules a reader should know
//!
//! **RTSP is a line protocol, so `zurl_net.line.write` is the gate.**
//! `request.zig` is the only writer here, and every part it writes goes
//! through that one call, which refuses a NUL, a CR, and an LF before a
//! byte reaches the buffer. The parts that come from outside are the
//! request uri, `--rtsp-stream-uri`, `--rtsp-session-id`,
//! `--rtsp-transport`, every `-H`, and the `Authorization` value `-u`
//! builds. A CR in any of them would write a header the user did not
//! name.
//!
//! **Every length a server sends is bounded before it is used.** One head
//! line by `reply.max_line_bytes`, the head together by
//! `reply.max_head_bytes`, and `Content-Length` by the ceiling the
//! `Fetcher` passes in, which `--max-filesize` narrows. The last of the
//! three is checked inside `reply.head`, before the number ever reaches a
//! caller that could allocate on it.
//!
//! ## What curl's command line does, measured
//!
//! **curl's command line can send exactly one request: `OPTIONS *`.** It
//! sent that for every url and every flag tried, `-X DESCRIBE` included,
//! and `curl --help all` names no `--rtsp-request`, `--rtsp-session-id`,
//! `--rtsp-stream-uri`, or `--rtsp-transport`: those four are
//! `CURLOPT_RTSP_*` options a program sets through libcurl. This build
//! makes all four flags and reads `-X` as well, and its default with no
//! flag is `OPTIONS *`, so the plain invocation matches curl byte for
//! byte. See `Fetcher` for the whole comparison and for what was left out.

const std = @import("std");

/// Runs one RTSP transfer and builds the dispatch entry that registers it.
pub const Fetcher = @import("zurl-rtsp/Fetcher.zig");

/// The request methods this build sends, and the ones it refuses by name.
pub const method = @import("zurl-rtsp/method.zig");

/// One request head. **The file that holds this package's injection
/// gate**, and the only writer here.
pub const request = @import("zurl-rtsp/request.zig");

/// One reply head. **The file that bounds every length a server sends.**
pub const reply = @import("zurl-rtsp/reply.zig");

/// The absolute uri a request line names, built out of a url.
pub const target = @import("zurl-rtsp/target.zig");

/// One dialogue: the sequence numbers, and the tie between a reply and its
/// request.
pub const Session = @import("zurl-rtsp/Session.zig");

/// The loopback RFC 2326 server this package's tests use.
///
/// Exported for the same reason `zurl_http.test_server` is: the end to end
/// tests of the command line need an RTSP peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is a
/// fixture and not a product, and nothing but a test may use it.
pub const test_server = @import("zurl-rtsp/test_server.zig");

/// The url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The port an `rtsp://` url uses when it names none.
pub const default_port = Fetcher.default_port;

/// The method a transfer sends when nobody names one.
pub const default_method = Fetcher.default_method;

/// One RTSP request method. Re-exported so a caller that reads a flag has
/// a name for the type without a second import.
pub const Method = method.Method;

/// Reads a method name, however it is written. See `method.parse`.
pub const parseMethod = method.parse;

/// The sentence that refuses a method this build does not send, or null.
/// See `method.refusal`.
pub const methodRefusal = method.refusal;

test {
    _ = Fetcher;
    _ = method;
    _ = request;
    _ = reply;
    _ = target;
    _ = Session;
    _ = @import("zurl-rtsp/session_test.zig");
}

test "the package names one scheme and the port RFC 2326 assigns it" {
    try std.testing.expectEqualStrings("rtsp", scheme);
    try std.testing.expectEqual(@as(?u16, 554), default_port);
    try std.testing.expectEqual(Method.options, default_method);
}
