//! The seam between the front package and an HTTP engine.
//!
//! `h1.Engine` implements this seam over `zurl-net`, which owns the dial
//! and the TLS session. A later phase adds a second engine beside it for
//! ALPN and client certificates. Nothing outside this file and the engine
//! that implements it should know which engine is live. The seam is what
//! makes that swap invisible to the front package.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

/// What the engine does with a 3xx response that carries a `Location`.
///
/// This is a union, not a count, because the two meanings do not fit one
/// number. curl with no `-L` reports the redirect; curl with `-L
/// --max-redirs 0` refuses it. A bare `0` reads like the first and does the
/// second.
pub const Redirects = union(enum) {
    /// Follow no redirect. `Head` reports the 3xx status and its
    /// `location` to the caller. This is what curl does with no `-L`.
    unfollowed,
    /// Follow up to this many redirects, then report
    /// `error.TooManyRedirects`. A value of zero refuses the first
    /// redirect; it does not report it. Use `unfollowed` for that.
    follow: u16,
};

/// Which redirect statuses keep the method and the body of the request.
///
/// **The default is what a browser does, and it is what curl does with no
/// flag.** A `301`, a `302`, or a `303` turns a `POST` into a `GET` and
/// drops the body. RFC 9110 permits that for the first two and requires it
/// for the third, and every client has done it for long enough that a
/// server may depend on it.
///
/// Each field here turns one of the three off, so the method and the body
/// go to the redirect target as they were. curl spells them `--post301`,
/// `--post302`, and `--post303`, and `--follow` sets all three at once,
/// which is the "per spec" reading of the three statuses.
///
/// A `307` and a `308` keep the method and the body whatever this holds.
/// Neither status permits a rewrite, so neither has a flag.
pub const RedirectMethods = struct {
    /// `--post301`: a `301` keeps the method and the body.
    post301: bool = false,
    /// `--post302`: a `302` keeps the method and the body.
    post302: bool = false,
    /// `--post303`: a `303` keeps the method and the body.
    post303: bool = false,

    /// Whether the status `status` keeps the method and the body.
    ///
    /// Reads false for every status this struct does not name, so the
    /// caller asks one question and never has to know which three have a
    /// flag.
    pub fn keeps(m: RedirectMethods, status: u16) bool {
        return switch (status) {
            @intFromEnum(std.http.Status.moved_permanently) => m.post301,
            @intFromEnum(std.http.Status.found) => m.post302,
            @intFromEnum(std.http.Status.see_other) => m.post303,
            else => false,
        };
    }
};

/// Which HTTP version a hop asks for, on a TLS hop and on a cleartext one.
///
/// **On a TLS hop the peer chooses, out of what it was offered.** A client
/// offers an ALPN list and the server picks one entry, so three of these
/// four narrow the offer and none of them forces an answer. curl reads its
/// own flags the same way: `--http2` is a request and not a demand, and a
/// peer with no HTTP/2 answers it with HTTP/1.1.
///
/// `prior_knowledge` is the one that leaves the peer no choice, and it does
/// that by offering `h2` alone. Measured against curl 8.21.0 and an
/// `openssl s_server` that offered `http/1.1` only:
/// `--http2-prior-knowledge` ended in a `no_application_protocol` alert and
/// exit 35, while `--http2` on the same server answered on HTTP/1.1.
///
/// **On a cleartext hop the ALPN answer does not exist, so the flag is the
/// whole of the choice.** RFC 9113 section 3.3 lets a client that already
/// knows send the connection preface straight away, and RFC 7540 section
/// 3.2 defined an `Upgrade: h2c` handshake that RFC 9113 removed. curl
/// still offers the second one, measured, so zurl does too. See
/// `h1.sendOn`.
///
/// **HTTP/3 does not ride on the ALPN offer at all**, because it does not
/// ride on TCP. `http_3` and `http_3_only` open a QUIC connection on UDP
/// first, and the offer inside that handshake is `h3` alone. The TCP offer
/// of both is the default pair, because that is the offer the fallback hop
/// uses. Measured: `curl -v --http3 https://example.com/`, a host with no
/// HTTP/3, printed `ALPN: curl offers h2,http/1.1` on the TCP hop it fell
/// back to. **No TLS offer over TCP ever names `h3`**: a stream socket
/// cannot carry HTTP/3, so a peer that chose it there would leave the
/// connection with no protocol either side can use.
///
/// | value | quic first | https offer | http |
/// | --- | --- | --- | --- |
/// | `any` | no | `h2`, `http/1.1` | HTTP/1.1, plain |
/// | `http_1_1` | no | `http/1.1` | HTTP/1.1, plain |
/// | `http_2` | no | `h2`, `http/1.1` | HTTP/1.1 with `Upgrade: h2c` |
/// | `prior_knowledge` | no | `h2` | HTTP/2, preface first |
/// | `http_3` | yes | `h2`, `http/1.1` | HTTP/1.1, plain |
/// | `http_3_only` | yes | none, the hop fails | the hop fails |
///
/// Every row is what curl 8.21.0 does for the flag beside it, measured on
/// the wire.
pub const HttpVersion = enum {
    /// Offer `h2` and then `http/1.1`, and speak whichever the peer chose.
    /// A cleartext hop is HTTP/1.1 and offers nothing.
    ///
    /// This is the default, and it is what a command line with no version
    /// flag asks for. Measured: `curl http://host/` with no flag sends a
    /// plain HTTP/1.1 request and no `Upgrade` field.
    any,
    /// Offer `http/1.1` alone. This is `--http1.1`.
    ///
    /// A peer that speaks HTTP/2 then answers with HTTP/1.1, because it
    /// was never offered anything else. That is the whole of the flag: a
    /// way back to the older protocol when a peer's HTTP/2 misbehaves.
    http_1_1,
    /// Ask for HTTP/2 and take HTTP/1.1 when the peer has none. This is
    /// `--http2`.
    ///
    /// Over TLS it is the default offer, so it changes nothing there. Over
    /// cleartext it sends the RFC 7540 section 3.2 `Upgrade: h2c` fields
    /// beside the request, and a peer that answers `101` finishes the
    /// request on HTTP/2. A peer that answers anything else has answered
    /// the request on HTTP/1.1, and that answer is the one the caller
    /// reads.
    http_2,
    /// Speak HTTP/2 and take no other answer. This is
    /// `--http2-prior-knowledge`.
    ///
    /// Over TLS the ALPN offer is `h2` alone, so a peer with no HTTP/2 ends
    /// the handshake rather than answer on HTTP/1.1. Over cleartext the
    /// connection preface goes out first and no HTTP/1.1 octet is ever
    /// written. RFC 9113 section 3.3.
    ///
    /// This is the flag for a peer that is known to speak HTTP/2 and
    /// cannot say so: a gRPC service on a loopback port, a sidecar, a test
    /// fixture.
    prior_knowledge,
    /// Try HTTP/3 over QUIC first, and fall back to the TCP hop when QUIC
    /// does not answer. This is `--http3`.
    ///
    /// **The fallback is silent, and that is what curl does.** Measured
    /// against curl 8.21.0 and `https://example.com/`, a host with no
    /// HTTP/3: `curl --http3` exited 0, reported `%{http_version} 2`, and
    /// wrote nothing on standard error. The same command against
    /// `https://ziglang.org/` reported `1.1`. So the flag asks and never
    /// demands, exactly as `http_2` asks over TLS.
    ///
    /// A hop on an `http` url never opens QUIC, because RFC 9114 section
    /// 3.1 puts HTTP/3 on TLS and an `http` url has no TLS. Measured:
    /// `curl --http3 http://example.com/` answered on HTTP/1.1 and exited
    /// 0. A hop through a proxy never opens QUIC either, because this
    /// build speaks HTTP/1.1 to a proxy. Measured: `curl --http3 -x ...`
    /// dialed the proxy.
    http_3,
    /// Speak HTTP/3 and take no other answer. This is `--http3-only`.
    ///
    /// A peer with no QUIC on UDP 443 ends the transfer rather than fall
    /// back. Measured against curl 8.21.0 and `https://example.com/`:
    /// `curl --http3-only` exited 7 and wrote
    /// `Failed to connect to example.com:443 after 119 ms`.
    ///
    /// An `http` url is refused before any packet goes out. Measured:
    /// `curl --http3-only http://example.com/` exited 3 and wrote
    /// `HTTP/3 requested for non-HTTPS URL`.
    http_3_only,
};

/// Which version of HTTP framed a response.
///
/// **This is what `-w %{http_version}` prints**, and the text of each arm
/// is curl 8.21.0's own, measured: `1.1` for HTTP/1.1, `2` for HTTP/2, `3`
/// for HTTP/3, and `0` for a transfer that got no response at all. The
/// last one has no arm here, because a caller that has no `Head` has no
/// version to report and says so with a null.
pub const WireVersion = enum {
    http_1_0,
    http_1_1,
    http_2,
    http_3,

    /// The text curl prints for this version.
    pub fn text(self: WireVersion) []const u8 {
        return switch (self) {
            .http_1_0 => "1.0",
            .http_1_1 => "1.1",
            .http_2 => "2",
            .http_3 => "3",
        };
    }
};

/// The base64url text of a `SETTINGS` payload, for the `HTTP2-Settings`
/// field of an `Upgrade: h2c` request. RFC 7540 section 3.2.1.
///
/// No padding, and the url alphabet, which is what the RFC asks for and
/// what curl sends: measured, `curl --http2 http://host/path` wrote
/// `HTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA`, which decodes to the three
/// entries curl's own `SETTINGS` frame carries.
pub const http2_settings_len_max: usize = 128;

/// One `--resolve` or `--connect-to` entry: where to dial for a url that
/// names a given host and port.
///
/// **This moves the dial and nothing else.** The `Host` header, the TLS
/// server name, and the name the peer certificate is checked against all
/// stay the ones the url wrote. Any other reading would turn this into a
/// way to send a request for one host to a peer that holds a certificate
/// for another, which is the very thing verification exists to stop.
/// `h1.dialTarget` is the one place an entry is read here, and
/// `h1.tlsSetup` reads `Request.url.host` and never this.
///
/// **The definition lives in `zurl_net.override` and this is a
/// re-export.** Every protocol package dials through the same rule, so a
/// second definition here would be a copy that can drift. See that file.
pub const HostOverride = zurl_net.override.HostOverride;

/// Where one hop dials, after every `HostOverride` has been read.
/// Re-exported from `zurl_net.override` for the reason `HostOverride` is.
pub const DialTarget = zurl_net.override.DialTarget;

/// Where a url naming `host` on `port` dials, given `list`.
/// Re-exported from `zurl_net.override` for the reason `HostOverride` is.
pub const dialTarget = zurl_net.override.dialTarget;

/// The header names that carry a caller's secret, and that must not leave
/// the origin the url names.
///
/// This array is the only place the set is named. To make one more header
/// name origin-bound, add the name here, and nothing else changes: the
/// engine refuses every name here among `Request.headers`, carries every
/// name here through `Request.secrets`, and withholds all of them on the
/// request it sends again to get off a redirect chain. The front package
/// lifts every name here out of the caller's header list by the same rule.
///
/// curl keeps these two names inside the origin the url names, and sends
/// them across an origin change only with `--location-trusted`. An origin
/// is the scheme, the host, and the port together, so a change to any one
/// of the three ends it. zurl has no such option and makes no such
/// comparison: it withholds every secret on each redirect it follows,
/// which is stricter than curl and never looser. See
/// `Head.credential_withheld`.
pub const origin_bound_headers = [_][]const u8{ "Authorization", "Cookie" };

/// The largest `Cookie` header a jar may build for one hop, in bytes.
///
/// The engine holds one buffer of this size on the stack of the call that
/// sends a request, so a jar of any size costs the engine this much memory
/// and no more. A jar that matches more cookies than fit stops at the
/// bound and reports how many it dropped: see `CookieJar.send`.
pub const cookie_header_len_max: usize = 8 * 1024;

/// Where the cookies of a transfer live, for an engine that must ask about
/// them once for each hop.
///
/// **A cookie is a credential, and `origin_bound_headers` names `Cookie`
/// for that reason.** A `Cookie` header the caller wrote travels in
/// `Request.secrets`, and the engine withholds every secret on every
/// redirect it follows. That rule is right for a header the caller wrote,
/// because the engine cannot know which host the value belongs to.
///
/// A jar knows. Each cookie in it carries the domain, the path, and the
/// `Secure` flag it was stored with, so a jar can answer "does this hop
/// get this cookie" for each hop on its own. So a jar does not travel
/// through `secrets`: the engine calls `send` again for every hop, with
/// that hop's own url, and the jar's own domain rule decides. A redirect
/// to another host therefore carries no cookie of the first host, and a
/// redirect that stays on one host keeps them, which is what curl 8.21.0
/// does, measured with two names on one loopback listener.
///
/// **This is one more mechanism, not a way around the first one.** A
/// `Cookie` in `Request.headers` is still `error.InvalidHeader`, a
/// `Cookie` in `Request.secrets` is still withheld on every redirect, and
/// `isOriginBound` still names the whole set. A jar adds a source of
/// cookies that carries its own origin rule with it.
///
/// `ptr` is the jar. It must stay valid for as long as the engine can call
/// either function, which is the whole of one `Engine.open`.
pub const CookieJar = struct {
    ptr: *anyopaque,
    /// Writes the `Cookie` header value for `url` into `out` and returns
    /// the part of `out` it wrote. Null when the jar sends this url no
    /// cookie at all, and the engine then writes no `Cookie` line.
    ///
    /// `out` is at least `cookie_header_len_max` bytes. The answer must
    /// hold no CR, no LF, and no NUL: it reaches a request header, and the
    /// engine checks it the same way it checks every other header value.
    ///
    /// **The answer must start at the front of `out`.** The engine joins
    /// it with a `Cookie` the caller wrote by writing the join behind it,
    /// in that same buffer, so a slice that points somewhere else would
    /// join the wrong bytes. `h1.mergeCookies` asserts on it.
    send: *const fn (ptr: *anyopaque, url: zurl_core.Url, out: []u8) ?[]const u8,
    /// Records one `Set-Cookie` header value the peer sent on `url`.
    ///
    /// Called once for each such header of each response, in the order
    /// they arrived, before the caller reads any body byte. The jar owns
    /// every rule about whether the value becomes a cookie: the engine
    /// reads none of it.
    ///
    /// Returns nothing. A cookie the jar refused is the jar's business to
    /// count and to report, and a response that carried a bad `Set-Cookie`
    /// is not a failed transfer to curl or to zurl.
    receive: *const fn (ptr: *anyopaque, url: zurl_core.Url, set_cookie: []const u8) void,
};

/// The header names that carry a caller's secret for the proxy, and that
/// must not reach the origin.
///
/// **This is the mirror of `origin_bound_headers`, and it exists because
/// zurl now connects to a proxy.** Two credentials are in play from that
/// moment, and confusing them gives one peer the other peer's secret. The
/// two arrays name the two sets, `isOriginBound` and `isProxyBound` read
/// them the same way, and the tests walk both.
///
/// Every name here is also in `refused_headers`, so a caller can never
/// write one. The value travels on `Request.Proxy.authorization` instead,
/// which is a field the engine writes only on a request that goes to the
/// proxy: the `CONNECT` line of a tunnel, and the head of a proxied
/// cleartext request. `Request.headers` and `Request.secrets` reach the
/// origin, and neither may carry a name from this list.
///
/// The two sets are disjoint, and they must stay disjoint. A name in both
/// would have no one destination at all. The test *"the origin set and the
/// proxy set name no header in common"* holds that.
pub const proxy_bound_headers = [_][]const u8{"Proxy-Authorization"};

/// The header names that no request may carry at all.
///
/// `Proxy-Authorization` authenticates to a proxy, and `Request.headers`
/// and `Request.secrets` both reach the origin. So a caller that writes
/// this header hands the proxy's secret to the origin server, which has no
/// use for it and every opportunity to keep it. curl keeps proxy headers
/// apart from request headers for the same reason, with `--proxy-header`. A
/// refusal says so, where forwarding gives the secret away.
///
/// **The refusal is not the whole rule, it is one half of it.**
/// `proxy_bound_headers` is the other half: the proxy credential has a
/// channel of its own, `Request.Proxy.authorization`, and the engine writes
/// it on the requests that go to the proxy and on no other. So the header
/// name is refused here and the value still reaches the peer it belongs to.
///
/// The five names after it frame the request, and the engine owns the
/// framing. The engine writes its own `host:`, its own `connection:`, and
/// its own body framing, and it writes the caller's headers verbatim
/// beside them. So a caller name here does not replace what the engine
/// wrote: it goes out as a second copy. Two `Host` headers, or a
/// `Content-Length: 5` on a request with no body, is the classic
/// request-smuggling shape: a peer that reads one request as two answers
/// the second one on the same socket. `Expect: 100-continue` asks the peer
/// to wait for a body that the engine never sends, which stalls the
/// exchange for the peer's whole timeout.
///
/// curl owns these names too: it replaces `Host` rather than adding one,
/// and it computes the framing headers from the body it was given. zurl
/// refuses them instead: `Request.body` is the one way to give this engine
/// a body, and the engine reads that field for the framing. A caller that
/// wrote its own `Content-Length` would be answering a question the body
/// already answers, and the two answers could differ.
pub const refused_headers = [_][]const u8{
    "Proxy-Authorization",
    "Host",
    "Content-Length",
    "Transfer-Encoding",
    "Connection",
    "Expect",
};

/// Whether `value` holds a byte that a header value may not carry.
///
/// RFC 9110 section 5.5 builds a field value from visible characters,
/// spaces, and horizontal tabs. So a C0 control other than tab, and a DEL,
/// are outside it. A byte at or above 0x80 stays, because RFC 9110 leaves
/// such a byte to the recipient and both curl and this engine pass it
/// through.
///
/// **One rule, and both engines ask it.** A CR or an LF in a value writes a
/// header that the peer never sent, into `-D`, into `Response.headers`, and
/// into the next request line for a redirect target. Over HTTP/1.1 the head
/// parser already split on CRLF, so such a byte cannot survive a response
/// head. HTTP/2 carries a value as an opaque octet string, so nothing about
/// the wire format stops one, and `h2.validateResponseFields` asks here.
/// `h1.validateHeaderValue` asks here for a request value. Two copies of
/// this rule is how one engine keeps it and the next one loses it.
/// What a response's `Content-Encoding` means to this build, and the one
/// place the three engines ask.
///
/// **The offer plays no part. What decides is whether the request asked
/// for a decoded body.** Measured against curl 8.21.0 on a loopback
/// listener, with the offer forced away from the answer:
///
/// ```text
/// curl --compressed -H 'Accept-Encoding: gzip'   answer zstd    exit 0, decoded
/// curl --compressed -H 'Accept-Encoding: zstd'   answer gzip    exit 0, decoded
/// curl --compressed                              answer exotic  exit 61
/// curl                                           answer gzip    exit 0, raw
/// curl                                           answer br      exit 0, raw
/// curl                                           answer exotic  exit 0, raw
/// curl -H 'Accept-Encoding: gzip'                answer gzip    exit 0, raw
/// ```
///
/// curl decoded a coding that was absent from the offer it sent, and
/// passed the same coding through when `--compressed` was not given. So
/// curl never compares the answer against the offer. It asks one question:
/// did this request ask to have the body decoded.
///
/// That gives the whole rule, and it is two lines:
///
/// - `accept_encoding` false: the header is ignored and the answer is
///   `identity`. The peer's own octets go to the caller, undecoded, and
///   the transfer succeeds. An unsolicited `Content-Encoding` is a thing
///   real servers send, and refusing it broke commands that work under
///   curl.
/// - `accept_encoding` true: the coding is decoded, or it is
///   `error.BadContentEncoding`. The caller asked for the body and would
///   otherwise get compressed octets it writes out as the body.
///
/// `compress` is an error under an offer, because `std.http.Decompress`
/// has no decoder for it and reaches an `unreachable` on it, which is a
/// panic and not a fault a user can read. `br` is an error for the same
/// reason: this build carries no brotli, which is also why it never
/// offers `br`. curl gives 61 for exactly this shape, measured with
/// `exotic`, and a curl built without brotli gives 61 for `br` too.
///
/// **One function, because three engines deciding this apart is how the
/// HTTP/2 and HTTP/3 paths came to read an unknown coding as `identity`
/// while HTTP/1.1 reported a read error for it.** `h1`, `h2`, and `h3`
/// all call here and hold no rule of their own.
///
/// `value` is the field the peer wrote, already trimmed, or null when it
/// wrote none. An empty value is `identity`: the peer named no coding.
pub fn contentEncoding(
    value: ?[]const u8,
    accept_encoding: bool,
) error{BadContentEncoding}!std.http.ContentEncoding {
    // No offer, no decoding, and no opinion about the header. This is the
    // whole of curl's behaviour without `--compressed`.
    if (!accept_encoding) return .identity;

    const text = std.mem.trim(u8, value orelse return .identity, " \t");
    if (text.len == 0) return .identity;

    // A list such as `gzip, br` lands here as one unrecognised token and
    // is refused. That is right: one decoder is applied, and two codings
    // cannot be unwrapped.
    const coding = std.http.ContentEncoding.fromString(text) orelse
        return error.BadContentEncoding;

    return switch (coding) {
        .identity, .gzip, .deflate, .zstd => coding,
        .compress => error.BadContentEncoding,
    };
}

/// One field of a response head, as slices of the head itself.
///
/// Both slices point into the octets the caller gave `HeadFields.init`, so
/// a caller can find where a field sits by the address of its name. See
/// `h1.parseRefusedHead`, which does exactly that.
pub const HeadField = struct {
    name: []const u8,
    value: []const u8,
};

/// Walks the fields of a response head, and accepts every head that
/// `std.http.HeadParser` accepts.
///
/// **`std.http.HeaderIterator` cannot be used for this.** Its `init` reads
///
///     .index = std.mem.findPosLinear(u8, bytes, 0, "\r\n").? + 2,
///
/// and that `.?` says a head always holds a carriage return and a line
/// feed. `std.http.HeadParser` does not agree: it ends a head on two line
/// feeds as well. So a server that answers `HTTP/1.1 200 OK` and two line
/// feeds hands `std` a head that `std` itself parsed and that the iterator
/// then unwraps a null for. Measured: that answer with 64 octets after it
/// stopped a build with safety checks on `attempt to use null value`, and
/// a `ReleaseSmall` build, which is what ships, exited 134. Seventeen
/// octets from a server are enough.
///
/// Two parts of `std` disagreeing about what a head is leaves nowhere safe
/// to stand, so this reads the head itself. The rule is the one
/// `HeadParser` keeps: a line ends at a line feed, one carriage return
/// before it belongs to the ending and not to the field, and an empty line
/// ends the head.
///
/// A line with no colon is skipped. `std` refuses such a head before this
/// runs, so the case is unreachable through `h1` today, and skipping is
/// the reading that cannot turn a malformed line into a field.
pub const HeadFields = struct {
    rest: []const u8,

    /// Starts after the status line.
    ///
    /// A head with no line feed at all carries no field, and the walk is
    /// then empty rather than a read of the status line as a field.
    pub fn init(bytes: []const u8) HeadFields {
        const first = std.mem.indexOfScalar(u8, bytes, '\n') orelse return .{ .rest = "" };
        return .{ .rest = bytes[first + 1 ..] };
    }

    pub fn next(self: *HeadFields) ?HeadField {
        while (self.rest.len != 0) {
            const end = std.mem.indexOfScalar(u8, self.rest, '\n') orelse self.rest.len;
            const raw = self.rest[0..end];
            // A line with no line feed after it is the last one, and the
            // walk stops on the next turn because nothing is left.
            self.rest = self.rest[@min(end + 1, self.rest.len)..];

            const line = std.mem.trimEnd(u8, raw, "\r");
            // The empty line ends the head. Anything after it is the body.
            if (line.len == 0) return null;

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            return .{
                .name = line[0..colon],
                // `std.http.HeaderIterator` trims the value, so this does
                // too, and a caller reads the same octets either way.
                .value = std.mem.trim(u8, line[colon + 1 ..], " \t"),
            };
        }
        return null;
    }
};

/// Whether `value` is a legal `Content-Length` field value.
///
/// **RFC 9112 section 6.2 writes the grammar as `1*DIGIT`, and nothing
/// else is a length.** So the value must hold at least one octet and every
/// octet of it must be an ASCII digit. A sign, a space, a separator, a
/// comma list, and a hexadecimal prefix are all refused.
///
/// **`std.fmt.parseInt` is not that grammar, which is why this exists.**
/// `std.http.Client.Response.Head.parse` reads the field with
/// `std.fmt.parseInt(u64, header_value, 10)`. That function accepts a
/// leading `+` and Zig's own `_` digit separators, so `+5` parses as 5 and
/// `1_0` parses as 10. Measured against curl 8.21.0 on a loopback
/// listener, with a body of `ABCDEFGHIJ`:
///
/// ```text
/// Content-Length: +5     curl exit 8, wrote nothing
/// Content-Length: 1_0    curl exit 8, wrote nothing
/// Content-Length: 005    curl exit 0, wrote ABCDE
/// ```
///
/// A client that reads a length no proxy in front of it reads is the
/// response-splitting half of request smuggling: the two disagree about
/// where the response ends, and the octets past that point become the head
/// of the next response. So a value this refuses ends the transfer.
///
/// **Leading zeroes are accepted, because curl accepts them.** RFC 9112
/// permits them, `005` is `1*DIGIT`, and the table above shows curl and
/// zurl already agree on that value.
///
/// **One function, because three engines read this field.** HTTP/2 puts
/// the same rule on the `content-length` pseudo-field through RFC 9113
/// section 8.1.1, and HTTP/3 through RFC 9114 section 4.1.2, so `h2` and
/// `h3` must ask here rather than hold a copy. `h1` asks it over every
/// `Content-Length` of a response head before `std` parses that head.
///
/// `value` is the field the peer wrote, already trimmed of the spaces and
/// the tabs around it, which is what `HeadFields.next` gives.
pub fn contentLengthIsDigits(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

/// The length a `content-length` field announces, folded over every copy
/// of the field the head carries.
///
/// `seen` is the answer so far, null before the first field. A second
/// field that names another number is a malformed head, RFC 9110 section
/// 8.6, because the two say different things about one body. A second
/// field that names the same number is accepted, which is the reading
/// RFC 9110 permits and the one `h1` already kept. Measured against curl
/// 8.21.0, whose two engines disagree with each other here: its HTTP/1.1
/// parser accepts the repeat and nghttp2 refuses it. A build that replaces
/// curl may not refuse traffic curl serves, so the laxer reading wins.
///
/// **The grammar is `contentLengthIsDigits` and never `parseInt`.**
/// `std.fmt.parseInt` accepts a leading `+`, so a head of
/// `content-length: +2` read as 2 and the transfer exited 0, where both
/// curl engines refuse it. The digits are counted first and `parseInt`
/// is asked only for the width.
pub fn contentLengthField(seen: ?u64, value: []const u8) error{BadContentLength}!u64 {
    if (!contentLengthIsDigits(value)) return error.BadContentLength;
    // Every octet is a digit, so only the width can fail: a run of digits
    // past 2^64-1 is a length no transfer reaches and no caller can hold.
    const announced = std.fmt.parseInt(u64, value, 10) catch return error.BadContentLength;
    if (seen) |first| {
        if (first != announced) return error.BadContentLength;
    }
    return announced;
}

/// Whether a body that has delivered `received` octets is still inside the
/// length its head announced.
///
/// **`content-length` is a bound and not a claim.** Over HTTP/1.1 the
/// announced length is the framing, so `h1` cannot hand a caller more
/// octets than it. Over HTTP/2 and HTTP/3 the framing is the end of the
/// stream, so the field is a number a peer writes, and an engine that
/// never tests it hands a caller a body longer than the one it announced.
/// RFC 9113 section 8.1.1 and RFC 9114 section 4.1.2 both make the
/// mismatch malformed.
///
/// This rule and `contentLengthField` live here, and not in one engine
/// with the others asking it, for the reason `contentEncoding` and
/// `headerNameIsToken` do: a rule kept in two places drifts, and every
/// defect this file was written to close began as one copy growing a check
/// that its twin never grew.
pub fn bodyWithinContentLength(
    announced: ?u64,
    received: u64,
) error{BodyLongerThanContentLength}!void {
    const bound = announced orelse return;
    if (received > bound) return error.BodyLongerThanContentLength;
}

/// Whether `bytes` carries a NUL octet.
///
/// **One rule, asked by all three engines, because a NUL in a response
/// head is a fault every one of them has to refuse.** A NUL is not a legal
/// octet in an HTTP field value, and it is the one octet that means "the
/// text stops here" to everything below this library: a file name, an
/// `--etag-save` file, and from that file a later request header each read
/// a different length of the same value.
///
/// **The check belongs here and not in the program above.** The rule was
/// written once in `src/cli/run.zig`, over the head blocks the engine
/// kept. Two things were open there. A library caller of `zurl.Client`
/// still got the octet, because it never runs that code. And a head the
/// engine dropped for its size left `Head.headers` empty, so the scan had
/// nothing to read and the octet went through. The engines below see the
/// octets before anything keeps them, so neither hole is open here.
///
/// Measured against curl 8.21.0 with a loopback server answering
/// `ETag: "a<NUL>b"`: `curl: (8) Nul byte in header`, exit 8, with and
/// without `--etag-save`, and the etag file left empty. 8 is
/// `CURLE_WEIRD_SERVER_REPLY`, which is `error.WeirdServerReply` here, so
/// zurl answers the same code for the same response.
pub fn hasNulOctet(bytes: []const u8) bool {
    return std.mem.indexOfScalar(u8, bytes, 0) != null;
}

/// Refuses a response head that carries a NUL octet.
///
/// `bytes` is one piece of a head: the whole head block for HTTP/1.1,
/// which is the octets `std.http.Reader` read off the wire, and one field
/// name or one field value for HTTP/2 and HTTP/3, which is what the field
/// decoder produced. Every engine calls it before it keeps the head, so no
/// consumer of a header value ever sees the octet. See `hasNulOctet`.
pub fn refuseNulInHead(bytes: []const u8) error{WeirdServerReply}!void {
    if (hasNulOctet(bytes)) return error.WeirdServerReply;
}

/// How many characters a `:status` takes on the wire, and how many a
/// rendered status line writes.
///
/// RFC 9113 section 8.3.2 and RFC 9114 section 4.3.2 both make `:status`
/// exactly three digits. `h2.readStatus` and `h3.readStatus` refuse
/// anything else, so every status those engines report is below 1000.
pub const status_text_len: usize = 3;

/// Writes `status` as exactly `status_text_len` digits.
///
/// **A status line is counted before it is written, so the width has to be
/// fixed.** `h2.recordHead` and `h3.recordHead` size a block for a status
/// line of `"HTTP/x " ++ three digits ++ " \r\n"` and then write into it.
/// A line that printed the number at its natural width writes fewer
/// characters than the block holds when the peer sent `007`, and the
/// octets left over are heap this side never wrote. The assert that
/// catches that mismatch is removed in ReleaseFast and ReleaseSmall, so
/// the release build is the one that hands those octets to a `-D` file.
///
/// A status that is below 100 is written with its leading zeroes, which
/// are the characters the peer sent. The remainder keeps the function
/// total for a number outside the three-digit range, which no caller can
/// reach.
pub fn writeStatusDigits(status: u16, out: *[status_text_len]u8) void {
    var left: u16 = status % 1000;
    var index: usize = status_text_len;
    while (index > 0) {
        index -= 1;
        out[index] = '0' + @as(u8, @intCast(left % 10));
        left /= 10;
    }
}

/// The sentence that says why a response head was refused for a NUL.
///
/// The name `WeirdServerReply` says the peer answered something nothing
/// can read. This says which octet, so a user looks at the server's header
/// and not at the url they typed.
pub const nul_in_head_message =
    "the server sent a response header with a NUL in it";

/// How long one read of an HTTP engine may wait with no octet arriving.
///
/// **Every wait an HTTP transfer makes needs this, and `--connect-timeout`
/// covers none of them.** That flag bounds the dial, the proxy step, and
/// the TLS handshake through `zurl_net.bounded.setup`, and it stops there.
/// A peer that completes the connect and then writes nothing holds the
/// response head phase, and a peer that finishes the head and then stops
/// holds the body phase. On a pooled connection the connect is over
/// already, so no bound of any kind was left.
///
/// **A rate watchdog cannot close that gap, which is why this number is
/// here.** `zurl_stream.Stall` is `--speed-limit` and `--speed-time`, and
/// it measures a read after the read comes back. A read that never comes
/// back is never measured, so the watchdog reports a transfer that crawls
/// and says nothing at all about one that stopped.
///
/// 300 seconds is curl's own `--speed-time` default, and it is the number
/// `zurl-ftp` and the other protocol packages already use for the same
/// question. `--speed-time` narrows it through
/// `zurl_net.bounded.stallTimeout` and never widens it.
///
/// **This lives here and not in one engine, because all three ask it.**
/// `h1` races `receiveHead` and each body read against it, `h2` races the
/// frame read of a whole connection, and `h3` hands it to the QUIC
/// datagram wait. A number kept in three places drifts.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: std.Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// The value an engine's read bound takes for a transfer that named
/// `--speed-limit` and `--speed-time`.
///
/// **One function, so the front package needs no `zurl-net` of its own.**
/// `zurl_net.bounded.stallTimeout` is where the rule lives, and the eleven
/// other protocol packages call it directly. The `zurl` module's import
/// table holds `zurl-core`, `zurl-stream`, `zurl-tls` and `zurl-http` and
/// no `zurl-net`, so the owner of an engine reaches the same rule through
/// here.
///
/// A flag narrows the ceiling and never widens it, and a `--speed-limit`
/// or a `--speed-time` of zero leaves the ceiling standing rather than
/// turning the bound off. See `stallTimeout` for both rules.
pub fn readTimeoutFor(low_speed_limit: u64, low_speed_time_s: u32) std.Io.Timeout {
    return zurl_net.bounded.stallTimeout(
        low_speed_limit,
        low_speed_time_s,
        default_read_timeout_s,
    );
}

/// `readTimeoutFor`, as whole milliseconds, for a caller whose wait takes
/// a number and not a `std.Io.Timeout`.
///
/// `quic.Connection.pump` is that caller. A timeout of `.none` answers
/// null, which that caller reads as "wait for as long as the peer likes".
///
/// **It rounds up and never down.** A bound of under one millisecond would
/// round to zero and turn a wait into a poll that never sleeps, so the
/// floor is one millisecond. A bound past what an `i64` of milliseconds
/// holds is clamped rather than wrapped.
pub fn readTimeoutMilliseconds(io: std.Io, timeout: std.Io.Timeout) ?i64 {
    const duration = timeout.toDurationFromNow(io) orelse return null;
    const ns = duration.raw.nanoseconds;
    if (ns <= 0) return 1;
    // **Up and never down.** A bound of 200 milliseconds reaches this a
    // few microseconds spent, and truncation then asks for 199, so the
    // wait ends before the bound the caller named. Measured: the HTTP/3
    // deadline test read 199.1 milliseconds against a floor of 200. A wait
    // that runs a fraction of a millisecond long is a wait inside its own
    // bound; one that stops short is a bound nobody asked for.
    const ms = @divFloor(ns + std.time.ns_per_ms - 1, std.time.ns_per_ms);
    if (ms <= 0) return 1;
    // A nanosecond count is wider than an `i64` of milliseconds in the
    // type system and never in fact, because the source is a bound this
    // build wrote. Clamping keeps the function total either way, and a
    // wrap here would turn a long bound into a wait of nothing.
    return std.math.cast(i64, ms) orelse std.math.maxInt(i64);
}

/// What a read raced against a deadline answered.
///
/// Three arms and no fourth, so every caller has to say what it does about
/// each one. A read that finished keeps its own faults inside `done`: the
/// race says only which of the two ended first, never what the read found.
pub fn RacedRead(comptime Result: type) type {
    return union(enum) {
        /// The read finished first. `Result` is its own return type, so a
        /// read that failed on the wire arrives here and not as a
        /// deadline.
        done: Result,
        /// The deadline passed with the read still waiting. The connection
        /// is at an unknown place and can never serve another request.
        timed_out,
        /// Something outside the read stopped it.
        canceled,
    };
}

/// Runs `task` against `timeout` and answers whichever ended first.
///
/// **A bound belongs where the wait is, and for HTTP the wait is one read
/// of the peer's octets.** `zurl_net.bounded` holds this shape for the
/// protocols whose answers are lines or one lump, and each of them calls
/// `readLine`, `readExact` or `readToEnd`. HTTP reads neither: over
/// HTTP/1.1 the head is framed by `std.http.Reader.receiveHead` and the
/// body is a stream the caller pulls, and over HTTP/2 the wait is one
/// frame of a whole connection. So the engines race those calls instead.
/// The number still comes from `zurl_net.bounded.stallTimeout`, so HTTP
/// and the other eleven protocols read `--speed-time` the same way.
///
/// **The deadline is on one read and never on the whole transfer.** Each
/// call starts the clock again, so a transfer that keeps delivering octets
/// runs for as long as it needs: a download over a slow link is bounded by
/// the rate rule in `zurl_stream.Stall` and by `--max-time`, never by
/// this. Only a transfer that stops delivering reaches the deadline.
///
/// `dropped` counts a read this build could not bound. See
/// `h1.Engine.read_bounds_dropped` for why that is a count and not a
/// refusal.
///
/// **A read that finished at the deadline is reported as the deadline.**
/// Its octets already left the source, so the caller must treat the
/// connection as unusable either way, which is what every caller here
/// does. `zurl_net.bounded.fill` makes the same trade.
pub fn raceRead(
    io: std.Io,
    timeout: std.Io.Timeout,
    dropped: *usize,
    comptime Result: type,
    comptime task: anytype,
    args: std.meta.ArgsTuple(@TypeOf(task)),
) RacedRead(Result) {
    switch (timeout) {
        // No bound was asked for, so no second task is needed, and the
        // read costs exactly what it cost before this function existed.
        .none => return .{ .done = @call(.auto, task, args) },
        else => {},
    }

    const Race = union(enum) {
        read: Result,
        deadline: std.Io.Cancelable!void,
    };

    var results: [2]Race = undefined;
    var race: std.Io.Select(Race) = .init(io, &results);

    // **The deadline starts first, because it is the task that may be
    // dropped.** A deadline that cannot start says this build has no
    // second unit of concurrency, and the read then runs here with no
    // bound. Starting the read first and finding no room for the deadline
    // would leave a read to cancel, and a canceled read has already taken
    // octets that nothing can put back.
    race.concurrent(.deadline, deadlineTask, .{ io, timeout }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            dropped.* +|= 1;
            return .{ .done = @call(.auto, task, args) };
        },
    };
    race.concurrent(.read, task, args) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            endRace(Race, &race);
            dropped.* +|= 1;
            return .{ .done = @call(.auto, task, args) };
        },
    };

    const first = race.await() catch |err| switch (err) {
        error.Canceled => {
            endRace(Race, &race);
            return .canceled;
        },
    };

    switch (first) {
        .read => |result| {
            endRace(Race, &race);
            return .{ .done = result };
        },
        .deadline => |slept| {
            endRace(Race, &race);
            slept catch |err| switch (err) {
                error.Canceled => return .canceled,
            };
            return .timed_out;
        },
    }
}

/// Ends `race` and throws away whatever the losing task answered.
///
/// `std.Io.Select.cancel` waits for every task, so a read that finished at
/// the deadline is still reported here. Its octets are in the connection's
/// own buffer and the caller closes that connection, so there is nothing
/// to release and nothing to hand back.
fn endRace(comptime Race: type, race: *std.Io.Select(Race)) void {
    while (race.cancel()) |_| {}
}

/// The deadline, as its own task.
fn deadlineTask(io: std.Io, timeout: std.Io.Timeout) std.Io.Cancelable!void {
    return timeout.sleep(io);
}

/// The host to compare against a `no_proxy` entry.
///
/// **A host of `example.com.` and a host of `example.com` are one name to
/// DNS, and they must be one name here too.** The final dot is the root
/// label, and RFC 1034 section 3.1 says the two spellings name the same
/// node. `zurl_core.proxy.bypasses` compares text, so without this a url
/// the user pasted with a trailing dot matches neither the equality rule
/// nor the suffix rule, and the request goes to the proxy the user
/// excluded. That puts the request head, and any `Authorization` on it for
/// a cleartext origin, in front of that proxy.
///
/// **Measured against curl 8.21.0**, with `http_proxy` pointing at a port
/// that refuses and the answer read off the address curl dialed:
///
/// ```text
/// host                no_proxy             curl
/// example.test        example.test         direct, the entry matched
/// example.test.       example.test         direct, the entry matched
/// example.test.       example.test.        direct, the entry matched
/// example.test        (empty)              the proxy
/// ```
///
/// So curl reads the trailing dot off the host before it matches. This
/// answers the same way.
///
/// Only one dot is removed. A host of `example.com..` is not a name DNS
/// reads, and it keeps no match here.
///
/// A host that is a literal address never ends with a dot, so an address
/// passes through unchanged and keeps the address rules `bypasses` holds
/// for it.
pub fn proxyMatchHost(host: []const u8) []const u8 {
    if (host.len > 1 and host[host.len - 1] == '.') return host[0 .. host.len - 1];
    return host;
}

pub fn headerValueHasControl(value: []const u8) bool {
    for (value) |byte| switch (byte) {
        0x00...0x08, 0x0a...0x1f, 0x7f => return true,
        else => {},
    };
    return false;
}

/// Which letters a field name may hold, for `headerNameIsToken`.
pub const HeaderNameCase = enum {
    /// Upper case and lower case are both legal. This is HTTP/1.1, where
    /// RFC 9110 makes a field name case-insensitive and the name goes on
    /// the wire as the caller wrote it.
    mixed,
    /// Lower case only. RFC 9113 section 8.2.1 and RFC 9114 section 4.2
    /// make an upper-case letter in a field name a malformed message, and
    /// it is also what lets `h2` and `h3` compare a name byte for byte.
    lower,
};

/// Whether `name` is a field name, which RFC 9110 section 5.6.2 makes a
/// non-empty run of `tchar`.
///
/// The set is the letters, the digits, and
/// ``!``, ``#``, ``$``, ``%``, ``&``, ``'``, ``*``, ``+``, ``-``, ``.``,
/// ``^``, ``_``, `` ` ``, ``|`` and ``~``. A real server sends names from
/// all of it, so a stricter rule here would refuse traffic that works.
/// Everything else is refused, and that is what closes the attack: a CR,
/// an LF, a NUL, a space and a colon are none of the set.
///
/// **One rule, asked by all three engines, because the name half of the
/// injection stayed open for a year after the value half was closed.**
/// Over HTTP/1.1 a name cannot carry a CR or an LF, because the head
/// parser split the head on CRLF to find the name in the first place, and
/// `h1` asks this rule of a *request* name for the same reason `h1`
/// asks `headerValueHasControl` of a request value. Over HTTP/2 and
/// HTTP/3 a name is an opaque octet string out of HPACK or QPACK, so a
/// peer writes any byte it likes. `recordHead` then writes
/// `name: value\r\n` into the block that `-i` and `-D` show and that
/// `Response.header` reads back, and one response field named
/// `x-a\r\nset-cookie: injected=1` reached a user's file as two fields the
/// server never sent. `headerValueHasControl` is the same rule for the
/// value beside it. Keep the two together: a rule that one engine holds
/// alone is a rule the other two engines drift away from.
///
/// This is the shape `contentEncoding` already has, and the reason is the
/// same.
pub fn headerNameIsToken(name: []const u8, case: HeaderNameCase) bool {
    if (name.len == 0) return false;
    for (name) |byte| switch (byte) {
        'A'...'Z' => if (case == .lower) return false,
        'a'...'z',
        '0'...'9',
        '!',
        '#',
        '$',
        '%',
        '&',
        '\'',
        '*',
        '+',
        '-',
        '.',
        '^',
        '_',
        '`',
        '|',
        '~',
        => {},
        else => return false,
    };
    return true;
}

/// Whether `name` is one of `origin_bound_headers`.
///
/// Matched without regard to case, because HTTP field names are
/// case-insensitive: a caller writes `-H cookie: ...` as readily as
/// `-H Cookie: ...`, and both name the same header.
pub fn isOriginBound(name: []const u8) bool {
    for (origin_bound_headers) |bound| {
        if (std.ascii.eqlIgnoreCase(name, bound)) return true;
    }
    return false;
}

/// Whether `name` is one of `proxy_bound_headers`.
///
/// Matched without regard to case, for the same reason `isOriginBound` is.
/// **Read this to answer "may this header reach the origin".** A name that
/// answers true belongs to the proxy alone, and the engine writes it from
/// `Request.Proxy.authorization` and from nowhere else.
pub fn isProxyBound(name: []const u8) bool {
    for (proxy_bound_headers) |bound| {
        if (std.ascii.eqlIgnoreCase(name, bound)) return true;
    }
    return false;
}

/// Whether `name` is one of `refused_headers`. Matched without regard to
/// case, for the same reason as `isOriginBound`.
pub fn isRefused(name: []const u8) bool {
    for (refused_headers) |refused| {
        if (std.ascii.eqlIgnoreCase(name, refused)) return true;
    }
    return false;
}

/// One proxy a hop may go through, ready for the wire.
///
/// **Every credential field here belongs to the proxy and to no other
/// peer.** `authorization` is a whole `Proxy-Authorization` header value,
/// and `user` and `password` are the decoded halves a SOCKS5 exchange
/// needs. The origin's own credential travels in `Request.secrets`, and
/// nothing in this struct can hold it. `proxy_bound_headers` names the
/// header side of the same rule.
///
/// Every field borrows from the caller and must outlive the call to
/// `Engine.open`.
pub const Proxy = struct {
    kind: zurl_core.proxy.Kind,
    /// The proxy host, with no brackets around an IPv6 literal.
    host: []const u8,
    port: u16,
    /// The `Proxy-Authorization` header value, or empty for a proxy that
    /// asked for none. Read only by an HTTP or HTTPS proxy: a SOCKS proxy
    /// authenticates inside its own handshake.
    ///
    /// **The engine writes this on the `CONNECT` request and on a proxied
    /// cleartext request, and on no other request.** A tunnelled request
    /// goes inside the tunnel, where the proxy cannot read it, so it
    /// carries no copy of this value.
    authorization: []const u8 = "",
    /// The decoded user name for a SOCKS5 credential exchange, RFC 1929.
    user: []const u8 = "",
    /// The decoded password for the same exchange.
    password: []const u8 = "",
    /// Whether to verify the proxy's own certificate. This is
    /// `--proxy-insecure`, which gives true.
    ///
    /// **It answers for the hop to the proxy and for no other hop.** A
    /// `CONNECT` tunnel through a cleartext proxy still verifies the origin
    /// against the origin's own name and the origin's own roots, and
    /// `Request.insecure` is the flag that answers for that one. Crossing
    /// the two would let `--proxy-insecure` turn origin verification off,
    /// which is exactly the shape that lets a proxy terminate TLS without
    /// anybody noticing.
    ///
    /// False is the default, and no fault path sets it true.
    insecure: bool = false,

    /// Whether one connection through `a` may serve a request that named
    /// `b`.
    ///
    /// Every field but the credential, which is compared by digest. See
    /// `h1.Origin`.
    pub fn sameRoute(a: Proxy, b: Proxy) bool {
        if (a.kind != b.kind) return false;
        if (a.port != b.port) return false;
        if (a.insecure != b.insecure) return false;
        return std.mem.eql(u8, a.host, b.host);
    }
};

/// Which proxy a hop uses, and which hosts reach none.
///
/// **The choice is made for each hop and not once for the transfer.** curl
/// reads `http_proxy` for a cleartext target and `https_proxy` for a TLS
/// one, and it reads `no_proxy` against the host of the target. A redirect
/// chain changes both the scheme and the host, so the engine has to ask
/// again at each hop. That is why the whole set travels on the request
/// rather than one resolved answer.
///
/// A caller that named `-x` sets both fields to the same value, which is
/// what curl does: an explicit proxy covers every scheme.
pub const ProxySet = struct {
    /// The proxy for a hop whose url names `http`. Null for none.
    http: ?Proxy = null,
    /// The proxy for a hop whose url names `https`. Null for none.
    https: ?Proxy = null,
    /// The hosts that reach no proxy, in the `no_proxy` list form. This is
    /// `--noproxy` and the `no_proxy` environment variable.
    /// `zurl_core.proxy.bypasses` holds every matching rule and the
    /// measurement behind it.
    no_proxy: []const u8 = "",

    /// The proxy a hop for `host` on `protocol` goes through, or null for a
    /// hop that dials the origin itself.
    ///
    /// The bypass list is read first, so a host the user excluded reaches
    /// no proxy whichever scheme it names.
    ///
    /// The host goes through `proxyMatchHost` first, so a url written with
    /// a trailing root dot matches the entry the user wrote without one.
    /// That is what curl does, measured.
    pub fn forHop(set: ProxySet, secure: bool, host: []const u8) ?Proxy {
        const chosen = if (secure) set.https else set.http;
        if (chosen == null) return null;
        if (zurl_core.proxy.bypasses(set.no_proxy, proxyMatchHost(host))) return null;
        return chosen;
    }

    /// Whether this set can send any hop through a proxy at all.
    pub fn isEmpty(set: ProxySet) bool {
        return set.http == null and set.https == null;
    }
};

/// Where a request body comes from, and how many bytes of it there are.
///
/// **A plain data bag with a C-shaped callback.** `Transfer.Options`
/// carries one of these, and that file's header comment says why: a later
/// phase exposes a libcurl-compatible C ABI and passes a
/// `CURLOPT_READFUNCTION` straight through with no shim. So `read` has the
/// shape libcurl's own read callback has, and this struct holds no Zig
/// closure.
///
/// **The engine puts no bound on the size.** A body of a known length
/// streams through `read` in pieces the engine sizes, so a large upload
/// costs the engine no memory. A caller that builds a body in memory owns
/// the bound on that memory. `src/cli/body.zig` holds zurl's own.
pub const Body = struct {
    /// How many bytes `read` produces in total.
    ///
    /// A known count frames the request with `content-length`, which is
    /// what curl sends for `-d` and for `-T` on a regular file. `null`
    /// says the count is not known before the body goes out, and the
    /// engine then frames the request with the chunked transfer coding,
    /// which is what curl sends for `-T -` on a pipe.
    ///
    /// A `read` that ends before this count, or that produces more than
    /// it, is `error.WriteError`: the request on the wire would not match
    /// the `content-length` that announced it, and the peer would read the
    /// next request as part of this one.
    len: ?u64,
    /// The state `read` and `rewind` act on. Borrowed, and it must outlive
    /// the call to `Engine.open`.
    ctx: *anyopaque,
    /// Fills up to `len` bytes of `buffer` and returns how many bytes it
    /// wrote.
    ///
    /// Zero says the body has ended. A negative value says the source
    /// could not be read, and the engine reports `error.ReadError`, which
    /// is the code curl gives a failed upload read.
    read: *const fn (ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize,
    /// Puts the source back at its first byte, and reports whether it
    /// could.
    ///
    /// **This is what lets one request go out twice.** The engine sends a
    /// request again for a `307`, for a `308`, for a retry on a pooled
    /// connection the peer had closed, and for the `401` answer the front
    /// package builds. Each of those needs the same body bytes again.
    ///
    /// `null` for a source that cannot go back, such as a pipe. The engine
    /// then refuses the second send with
    /// `error.RequestBodyNotResendable` rather than send a body that
    /// starts in the middle.
    rewind: ?*const fn (ctx: *anyopaque) callconv(.c) bool,
    /// The `content-type` this body carries, or null for a body that
    /// names none.
    ///
    /// **It travels on the body and not among the headers, because it
    /// describes the body and nothing else.** A redirect that drops the
    /// body drops this header with it, and a `GET` that follows a `302`
    /// then carries no content type for a body it is not sending.
    ///
    /// Measured against curl 8.21.0. `curl -L -d 'a=1'` through a `302`
    /// sends `GET /moved` with no `Content-Type` at all, while the same
    /// chain with `-H 'Content-Type: text/plain'` keeps that header,
    /// because a header the user wrote is the user's and not the body's.
    /// zurl divides the two the same way: `src/cli/Args.zig` puts a user
    /// header in `headers` and `src/cli/body.zig` puts the implied one
    /// here.
    ///
    /// Checked like any other header value: a CR, an LF, or a NUL in it is
    /// `error.InvalidHeader`.
    content_type: ?[]const u8 = null,
};

/// A request to send.
///
/// `url`, `headers`, and `secrets` are borrowed. They must outlive the
/// call to `Engine.open`.
pub const Request = struct {
    /// The request method.
    ///
    /// Any method may carry a body, and any method may carry none. The
    /// engine frames what `body` holds and never guesses from the method:
    /// `curl -X POST` with no data sends `POST` with no `content-length`
    /// and no body at all, measured against curl 8.21.0, and this engine
    /// sends the same.
    method: std.http.Method,
    url: zurl_core.Url,
    /// Each name must be an RFC 9110 token, and no value may hold a CR, an
    /// LF, or a NUL. A name or a value that breaks this is
    /// `error.InvalidHeader`, because a CR or an LF in a value would put a
    /// header of the peer's choosing on the wire.
    ///
    /// These headers follow a redirect to any host. Put a secret in
    /// `secrets` instead: a name in `origin_bound_headers`, in any case,
    /// is `error.InvalidHeader` here, because this list is the one place a
    /// secret must never travel. A name in `refused_headers` is
    /// `error.InvalidHeader` wherever it appears.
    headers: []const std.http.Header,
    /// The headers that must stay inside the origin `url` names.
    ///
    /// Every name here must be one of `origin_bound_headers`. Any other
    /// name is `error.InvalidHeader`, so this channel carries exactly the
    /// named set and nothing else.
    ///
    /// This list is separate from `headers` because a secret must not
    /// follow a redirect to another origin. The engine sends these headers
    /// to the origin `url` names and to no other: a request that carries a
    /// secret asks for no redirect following, so it gets one answer from
    /// that origin. When that answer is a redirect the caller asked to
    /// follow, the engine sends the request again with no secret at all,
    /// and the chain then carries nothing worth stealing. See
    /// `h1.Exchange.open`, which owns this rule, for its cost. The same
    /// value in `headers` would instead travel to whichever host the first
    /// server named.
    ///
    /// Checked the same way as `headers`: a value holding a CR, an LF, or
    /// a NUL is `error.InvalidHeader`. A percent-encoded url can decode
    /// into a user name that holds one.
    secrets: []const std.http.Header = &.{},
    redirects: Redirects,
    /// Which protocols a `location:` header may name. This is
    /// `--proto-redir`.
    ///
    /// A redirect target naming a protocol outside this set is
    /// `error.UnsupportedProtocol`, and the engine never opens it. The
    /// default is `zurl_core.redirect.redirect_default`, which is curl's
    /// own `--proto-redir` default and holds no `file`, so a caller that
    /// sets nothing still gets the rule. See that constant for why.
    redirect_protocols: zurl_core.redirect.Set = zurl_core.redirect.redirect_default,
    /// The lowest TLS version a hop of this request may keep. This is
    /// `--tlsv1.2` and `--tlsv1.3`.
    ///
    /// Carried on the request and not on the engine, because a `Client`
    /// serves one transfer's options at a time and the floor belongs to
    /// the transfer. `zurl_net.Connection.Tls.min_version` says how it is
    /// enforced and what it costs.
    tls_min_version: zurl_core.tls.MinVersion = .floor,
    /// The highest TLS version a hop of this request may keep. This is
    /// `--tls-max`.
    ///
    /// Carried beside `tls_min_version` and for the same reason. The
    /// default is the highest version this build offers, so a caller that
    /// names nothing gets exactly the offer it always got.
    /// `zurl_net.Connection.Tls.max_version` says how it is enforced.
    tls_max_version: zurl_core.tls.Version = .highest,
    /// Whether the client hello leaves the ALPN extension out. This is
    /// `--no-alpn`.
    ///
    /// **With no extension there is no HTTP/2.** A peer cannot choose a
    /// protocol it was never offered, so such a hop speaks HTTP/1.1, which
    /// is what a user asking for this flag wants: a way past a peer or a
    /// middlebox that answers the extension badly.
    /// `zurl_net.Connection.Tls.alpn_protocols` says what each answer
    /// means.
    no_alpn: bool = false,
    /// Which HTTP versions the ALPN offer of a TLS hop names. This is
    /// `--http1.1` and `--http2`.
    ///
    /// The default offers both, so a peer that speaks HTTP/2 gets HTTP/2.
    /// See `HttpVersion`. The value is part of a pooled connection's
    /// identity, because the offer is made once in the client hello and
    /// cannot be made again on an open session.
    http_version: HttpVersion = .any,
    /// A flag the caller raises when this transfer must stop.
    ///
    /// **This is for a transport the caller's own cancel cannot
    /// interrupt.** A caller that bounds a transfer with a deadline of its
    /// own, such as `-m`/`--max-time`, runs the transfer as a task and
    /// cancels it when the bound passes. That cancel reaches a blocked TCP
    /// read, so HTTP/1.1 and HTTP/2 need nothing here. It does not reach a
    /// QUIC datagram wait, which runs through `Io.operateTimeout` and
    /// therefore blocks on a task of its own: measured, a `--max-time`
    /// cancel let a 1.3 MB HTTP/3 transfer run to the end and report
    /// success. The HTTP/3 transport reads this flag at every wait
    /// instead.
    ///
    /// Null for a caller that bounds nothing. Borrowed, and it must
    /// outlive the call to `Engine.open`.
    stop: ?*const std.atomic.Value(bool) = null,
    /// The `User-Agent` header value to send. The engine sends this exact
    /// text; it never falls back to a value of its own.
    ///
    /// Checked the same way as a value in `headers`: a CR, an LF, or a NUL
    /// here is `error.InvalidHeader`. This text reaches the wire like any
    /// other header value, and `-A` will fill it from the command line, so
    /// it is untrusted input too.
    ///
    /// Defaults to a value only so every existing test that builds a
    /// `Request` by hand still compiles. The front package always sets this
    /// from `Transfer.Options.user_agent`, which carries the real default.
    user_agent: []const u8 = "zurl/0.1",
    /// Whether the request offers the peer a compressed body. This is
    /// `--compressed`.
    ///
    /// **False sends no `Accept-Encoding` header at all, and that is the
    /// default.** Measured against curl 8.21.0 on a loopback listener: a
    /// plain `curl http://127.0.0.1:PORT/path` writes four request lines
    /// and none of them is `Accept-Encoding`, while `curl --compressed`
    /// adds `Accept-Encoding: deflate, gzip, br, zstd`. A client that asks
    /// for compression on every request gets a compressed answer where curl
    /// would have got a plain one, so the two tools read different bytes
    /// off the same server. The header is opt-in here for that reason.
    ///
    /// **This field decides whether the body is decoded, and the offer
    /// that went out plays no part in that.** See `contentEncoding`, which
    /// holds the rule and the measurements behind it. With it false the
    /// engine ignores `Content-Encoding` and writes the peer's own octets
    /// out. With it true the engine decodes the answer, or reports
    /// `error.BadContentEncoding` for a coding it has no decoder for.
    ///
    /// A caller that writes its own `Accept-Encoding` header in `headers`
    /// does **not** raise this, and the engine then writes no header of
    /// its own beside it, so exactly one offer goes out. Measured against
    /// curl 8.21.0: `curl -H 'Accept-Encoding: gzip'` with no
    /// `--compressed`, answered in gzip, wrote the 64 compressed octets
    /// out and exited 0. It did not decode. Only `--compressed` decodes.
    accept_encoding: bool = false,
    /// The request body, or null for a request that carries none.
    ///
    /// The engine writes the framing header this implies and nothing else:
    /// `content-length` for a known length, `transfer-encoding: chunked`
    /// for an unknown one, and neither header at all for a null body. A
    /// caller cannot write any of those three itself. `refused_headers`
    /// names them.
    ///
    /// **A body does not always survive a redirect.** A `301`, a `302`, or
    /// a `303` that the engine follows drops the body and asks for the
    /// target with `GET`, and a `307` or a `308` keeps both. See
    /// `h1.Exchange.followChain`, which holds the rule and the measurement
    /// behind it.
    body: ?Body = null,
    /// Whether the secrets may follow a redirect. This is
    /// `--location-trusted`.
    ///
    /// **False is the default, and the default must stay false.** A secret
    /// that follows a `location:` header reaches whichever host the first
    /// server named, which is a credential given away to a host the user
    /// never asked for. With false, the engine sends the request again
    /// with no secret before it follows the chain, and reports
    /// `Head.credential_withheld`.
    ///
    /// True is the documented opt-in curl spells `--location-trusted`.
    /// Measured against curl 8.21.0 with two loopback servers: `-L -u
    /// alice:secret` sends no `Authorization` to the redirect target, and
    /// `--location-trusted -u alice:secret` sends it. The same split holds
    /// for a `-H 'Authorization: ...'` the user wrote.
    ///
    /// Nothing sets this from a default. Only a caller that names the
    /// option can reach it.
    trusted_secrets: bool = false,
    /// Whether to verify the peer certificate on a TLS hop. This is
    /// `-k`/`--insecure`, which gives true.
    ///
    /// **False is the default, and no fault path may set it true.** A
    /// handshake that failed to verify is not a reason to try again
    /// without verification: that would turn every attack this check
    /// exists to stop into a transfer that quietly succeeds. Only a
    /// caller that names the option can reach it.
    ///
    /// True turns off both halves of the check, which is what curl does:
    /// the chain no longer has to reach a trusted root, and the
    /// certificate no longer has to carry the host name. Neither half is
    /// useful alone.
    ///
    /// The value is part of a pooled connection's identity. See
    /// `h1.Origin`: a connection opened with no verification can never
    /// answer a request that asked for verification.
    insecure: bool = false,
    /// Whether to turn Nagle's algorithm off on a new connection. This is
    /// `--no-tcp-nodelay`, which gives false.
    ///
    /// True is the default, because curl sets `TCP_NODELAY` on every
    /// connection unless the user says otherwise. See
    /// `zurl_net.tcp.DialOptions.no_delay`.
    ///
    /// This value is part of a pooled connection's identity too, because
    /// the option is set once on the socket and never read back.
    tcp_no_delay: bool = true,
    /// The cookie jar this request sends from and stores into. This is
    /// `-b`, `-c`, and `-j` together.
    ///
    /// Null keeps no cookie at all: the engine asks for none, sends none,
    /// and drops every `Set-Cookie` a peer writes. **That is curl's own
    /// default**, measured against curl 8.21.0: two urls in one
    /// invocation, the first answering `Set-Cookie`, sent no `Cookie`
    /// header on the second url unless a cookie flag turned the engine on.
    ///
    /// The engine calls `CookieJar.send` once for each hop of a redirect
    /// chain, with that hop's own url. See `CookieJar` for why a jar does
    /// not travel through `secrets`.
    cookies: ?CookieJar = null,
    /// Where each hop dials, when the caller wants that told apart from
    /// the host the url names. This is `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** See `HostOverride`.
    /// An empty list, the default, dials exactly the host and port the url
    /// carries, which is what every transfer did before this field
    /// existed.
    ///
    /// The list is read again for each hop of a redirect chain, with that
    /// hop's own host and port, so an entry naming the redirect target
    /// takes that hop too. curl reads its own DNS cache the same way.
    connect_to: []const HostOverride = &.{},
    /// Which proxy each hop of this request goes through. This is `-x`,
    /// `--socks5`, `--noproxy`, and the proxy environment variables.
    ///
    /// The default is empty, so a transfer that named no proxy dials
    /// exactly the peer it dialed before this field existed.
    ///
    /// **The set is read again for each hop of a redirect chain**, with
    /// that hop's own scheme and host, because both can change and curl
    /// reads both again too. See `ProxySet.forHop`.
    proxies: ProxySet = .{},
    /// Whether each hop of a redirect chain carries a `Referer` naming the
    /// hop before it. This is the `;auto` suffix of `-e`/`--referer`.
    ///
    /// The first request carries whatever `headers` holds and no more: a
    /// request the caller made itself came from nowhere. Measured against
    /// curl 8.21.0, `-e ';auto'` sent no `Referer` on the first request
    /// and `Referer: <the first hop's url>` on the second.
    ///
    /// A `Referer` in `headers` is replaced on each hop after the first,
    /// which is what curl does: measured, `-e 'http://a/;auto'` sent
    /// `http://a/` first and the previous hop's url after that.
    auto_referer: bool = false,
    /// Which redirect statuses keep the method and the body. This is
    /// `--post301`, `--post302`, `--post303`, and `--follow`.
    ///
    /// The default rewrites all three to `GET` with no body, which is
    /// what curl does with no flag. See `RedirectMethods`, which holds
    /// the rule and the measurement behind it.
    ///
    /// **A body that is kept must be sendable twice.** The engine sends
    /// the request again at the redirect target, so a body with no
    /// `Body.rewind`, which is what a pipe gives, is `error.WriteError`
    /// on that hop rather than a request that starts in the middle of
    /// itself. That is the same rule a `307` already runs under.
    redirect_methods: RedirectMethods = .{},
};

/// The parts of a response head that the front package needs before it
/// decides how to read the body.
pub const Head = struct {
    status: u16,
    /// Which version of HTTP framed this response.
    ///
    /// **The version the peer answered in, and never the version the
    /// caller asked for.** `Request.http_version` is a request, and a peer
    /// with no HTTP/2 and no HTTP/3 answers it on HTTP/1.1. A caller that
    /// reported the flag instead would tell a script that a transfer took
    /// a protocol it never took. See `WireVersion`.
    ///
    /// On a redirect chain this is the version of the last hop, which is
    /// the hop the body came from. curl reports the same hop.
    wire_version: WireVersion,
    /// How many bytes of body the peer announced, before any content
    /// decoding.
    ///
    /// `null` when the peer announced nothing, and also when
    /// `transfer_encoding` is `.chunked`. A chunked transfer frames its own
    /// length, so a `Content-Length` beside it says nothing about the body
    /// and must not reach a caller as if it did.
    content_length: ?u64,
    /// How the peer framed the body.
    transfer_encoding: std.http.TransferEncoding,
    /// Borrowed from the `Exchange`. Valid until `Exchange.close`.
    location: ?[]const u8,
    /// The `WWW-Authenticate` header value, for a `401` response. `null`
    /// when the response carried none, or one arrived too large for the
    /// engine to keep. Borrowed from the `Exchange`. Valid until
    /// `Exchange.close`.
    ///
    /// An engine that finds more than one such header reports the first
    /// that offers `Digest`, and the first of any kind when none does.
    www_authenticate: ?[]const u8,
    /// Whether a `WWW-Authenticate` header arrived too large for the
    /// engine to keep.
    ///
    /// `www_authenticate` is `null` both when a response carried no
    /// challenge and when it carried one that did not fit. Those are not
    /// the same thing to a caller: the second is a recovered fault, and a
    /// recovered fault must be reportable. This flag tells them apart.
    ///
    /// An engine that drops an oversize `Digest` challenge reports no
    /// challenge at all, even when a `Basic` one fit beside it. Answering
    /// the `Basic` challenge would send the password in reversible base64
    /// to a server that had offered a scheme where the password never
    /// travels.
    www_authenticate_oversize: bool,
    /// Whether the engine sent this request again without the secrets the
    /// caller gave it.
    ///
    /// The engine keeps every secret inside the origin the caller named,
    /// so a redirect that the caller asked to follow costs all of them.
    /// The answer then comes from a request that carried none, which looks
    /// exactly like a password the server refused. A caller reports this
    /// rather than leave the transfer to explain itself.
    ///
    /// This is set on every redirect the engine follows, a same-origin one
    /// included. The engine compares no origins, so it drops every secret
    /// on the first hop rather than decide which hop may keep one. See
    /// `h1.Exchange.open`.
    credential_withheld: bool,
    /// Whether the engine will transparently decode the body, because the
    /// peer sent a `Content-Encoding` other than `identity`.
    ///
    /// `content_length` counts bytes before that decoding. Once decoding
    /// runs, the bytes `Exchange.bodyReader` yields no longer match
    /// `content_length`, so a caller must not treat that number as the
    /// decoded size. The front package's `Client.performHttp` reads this
    /// flag to decide what to tell a progress reporter.
    body_decoded: bool,
    /// Every response head this request produced, in the order they
    /// arrived, byte for byte as the peer wrote them.
    ///
    /// Each block runs from the status line to the empty line that ends
    /// the head, and keeps its CRLF line endings and that empty line. A
    /// request that met a redirect the engine followed reports one block
    /// for each hop, one after the other, because that is what `curl -D -
    /// -L` writes. Measured against curl 8.21.0.
    ///
    /// `null` when a bound below stopped the engine keeping them. See
    /// `headers_oversize`: the engine keeps every block or none, and never
    /// a part of one.
    ///
    /// **Lifetime.** Valid until `Exchange.close`, or until the next
    /// `Engine.open` on the same engine, whichever comes first. That is a
    /// shorter life than `location` has, because an engine may keep the
    /// blocks of a whole redirect chain outside the one exchange that
    /// ends it. A caller that needs the text for longer must copy it.
    ///
    /// A response head carries no request header. `Authorization` and
    /// `Cookie` travel in `Request.secrets` and never come back this way,
    /// so this field opens no path to a caller's secret. A `Set-Cookie` is
    /// a response header and does appear here, because the peer sent it.
    headers: ?[]const u8,
    /// The last block of `headers`, which is the head of the response this
    /// `Head` describes. A subslice of `headers`, and `null` whenever
    /// `headers` is.
    ///
    /// A lookup by header name must read this and not `headers`. The
    /// blocks of the earlier hops answer a question about a response that
    /// was already redirected away from: a `Content-Type` found there
    /// describes the redirect page, not the body the caller is about to
    /// read.
    final_headers: ?[]const u8,
    /// Whether the engine dropped the response head blocks because they
    /// passed a bound of its own.
    ///
    /// `headers` is `null` both when an engine keeps no blocks at all and
    /// when a bound dropped the ones it had. Those are not the same thing
    /// to a caller, and a caller that writes the blocks to a file must not
    /// write a part of them as if it were the whole. This flag tells the
    /// two apart, the same way `www_authenticate_oversize` does for a
    /// challenge that did not fit.
    ///
    /// An engine that passes a bound drops every block, not the tail of
    /// one. A file holding the first half of a head reads exactly like a
    /// file holding a whole one.
    headers_oversize: bool,
    /// The url text of the final hop, when the engine followed at least
    /// one redirect.
    ///
    /// `null` when the engine followed none. The effective url is then the
    /// one the caller named in `Request.url`, which the caller already
    /// has, so the engine reports no copy of it.
    ///
    /// Carries no userinfo. The engine builds this text from the target it
    /// resolved, and a credential must not follow a redirect anyway.
    ///
    /// Borrowed from the `Exchange`. Valid until `Exchange.close`.
    effective_url: ?[]const u8,
};

/// Every runtime fault that opening a request can produce.
///
/// A server is untrusted input, so a malformed response is a member of this
/// set, never an assertion and never a panic. Names match `zurl_core.Error`
/// where a match exists, so a later mapping layer can reuse them without a
/// translation table. `Canceled` and `Unexpected` have no `zurl_core.Error`
/// counterpart yet; they pass through `std.Io` faults that layer has not
/// classified.
///
/// `PartialFile` is not here. Only a body read can find a short transfer,
/// and the head is already back by then. See `BodyError`.
pub const OpenError = error{
    /// The URL, or a redirect target, does not name a usable request.
    InvalidUrl,
    /// The URL names a scheme this engine does not speak.
    UnsupportedProtocol,
    /// A request header name is not a token, or a header value holds a CR,
    /// an LF, or a NUL. This name has no `zurl_core.Error` counterpart.
    InvalidHeader,
    /// The engine had to send the request again, and `Request.body` cannot
    /// go back to its first byte.
    ///
    /// A request goes out twice for a `307`, for a `308`, for a retry on a
    /// pooled connection the peer had closed, and for the answer to a
    /// `401`. A body read from a pipe has no `Body.rewind`, so the second
    /// send would carry whatever bytes were left, which is a request the
    /// peer would act on as if it were whole. Refuse it instead. This name
    /// has no `zurl_core.Error` counterpart.
    RequestBodyNotResendable,
    /// The host name has no address.
    CouldNotResolveHost,
    /// The proxy's host name has no address.
    ///
    /// Kept apart from `CouldNotResolveHost` because the two send a user to
    /// two different places: one is the url they typed, and the other is a
    /// `-x` flag or a shell profile they may have forgotten about. curl
    /// answers the same pair with two codes, 6 and 5, measured against curl
    /// 8.21.0 with a proxy host that does not resolve.
    CouldNotResolveProxy,
    /// The connection attempt did not succeed.
    CouldNotConnect,
    /// The proxy did not give a usable route to the origin.
    ///
    /// This covers a SOCKS handshake that the proxy refused, a reply this
    /// build cannot read, and a proxy that spoke out of turn. It does not
    /// cover a `CONNECT` the proxy answered with a status: measured against
    /// curl 8.21.0, a proxy answering `403` or `407` to a `CONNECT` gives
    /// exit 7, the code a refused connection gives, so that path reports
    /// `CouldNotConnect` and puts the reason in `Engine.cause`.
    ///
    /// curl answers a refused SOCKS handshake with exit 97, `CURLE_PROXY`,
    /// measured with a listener that answered `05 ff` and with one that
    /// answered a refusal.
    ProxyError,
    /// The TLS handshake, or loading trust roots for it, did not succeed.
    SslConnectError,
    /// The peer certificate did not verify. `TlsSetup` also reports this
    /// when a certificate directory could not be scanned for the roots
    /// the caller asked for.
    PeerFailedVerification,
    /// A certificate file the caller named could not be read as
    /// certificates. `TlsSetup` reports this.
    CaCertBadFile,
    /// A read from the peer did not succeed, including a response that does
    /// not parse as HTTP.
    ReadError,
    /// The peer answered a head no consumer of a header value may read.
    ///
    /// The one shape that reaches this today is a NUL octet in a response
    /// head. See `refuseNulInHead` for why the rule sits in this file and
    /// for the measurement against curl 8.21.0, which answers the same
    /// response with exit 8.
    ///
    /// Kept apart from `ReadError` because nothing on the wire failed and
    /// the head parsed. The fault is the octets inside it, and curl gives
    /// it a code of its own.
    WeirdServerReply,
    /// The request asked for a decoded body and the peer answered in a
    /// coding this build has no decoder for.
    ///
    /// **Only a request that asked for compression can reach this.** See
    /// `contentEncoding`, which is the one rule all three engines read. A
    /// request that sent no `Accept-Encoding` ignores the header
    /// altogether and writes the peer's own octets out, so it never
    /// arrives here.
    ///
    /// Kept apart from `ReadError` because nothing on the wire failed. The
    /// head parsed, and the fault is the one header. The alternative is to
    /// hand a caller compressed octets under a flag that promised the
    /// decoded body, which writes a file no reader can open and reports
    /// success for it.
    BadContentEncoding,
    /// The peer sent one response header line larger than the engine reads.
    ///
    /// The smaller of the two bounds an engine keeps on a response head.
    /// Kept apart from `ReadError` because the cause is a bound the engine
    /// keeps, not a fault on the wire. The engine that reports this names
    /// the size of its own bound. See `h1.head_field_len_max`.
    HeaderLineTooLarge,
    /// The peer sent a whole response head larger than the engine reads.
    ///
    /// The larger of the two bounds an engine keeps on a response head. It
    /// counts every byte of the head together, so a head of short lines
    /// that passes it carries no line long enough for
    /// `HeaderLineTooLarge`. See `h1.head_len_max`.
    ResponseHeadTooLarge,
    /// A write to the peer did not succeed.
    WriteError,
    /// The redirect count went over its limit.
    TooManyRedirects,
    /// A redirect target names a protocol that `Request.redirect_protocols`
    /// permits and this engine does not speak.
    ///
    /// **This is not a refusal.** It is the engine saying the hop belongs
    /// to somebody else. The only way to reach it is an explicit
    /// `--proto-redir` that adds a protocol outside http and https, such
    /// as `--proto-redir +file`, which curl treats as the user consenting
    /// to that target. The default set holds no such protocol, so a
    /// caller that names nothing can never see this name.
    ///
    /// The engine has closed everything it opened and written no byte of
    /// the new hop. The target url is in the engine's own storage: an
    /// `h1.Engine` reports it through `redirectHandoff`. A caller with no
    /// way to open another protocol reports `UnsupportedProtocol`, which
    /// is the answer the target had before this name existed.
    RedirectToOtherProtocol,
    /// The connect attempt went over the caller's connect timeout.
    OperationTimedOut,
    /// The caller asked for a connect timeout, but this build has no
    /// concurrency, so the engine cannot stop a connect that hangs. The
    /// engine refuses the request instead of dropping the bound. This name
    /// has no `zurl_core.Error` counterpart.
    ConnectTimeoutUnsupported,
    /// The underlying `std.Io` operation was canceled.
    Canceled,
    /// The underlying OS call returned something this engine does not
    /// classify.
    Unexpected,
} || std.mem.Allocator.Error;

/// Every runtime fault that reading a body can produce, beyond the
/// `std.Io.Reader` faults the reader itself reports.
///
/// A `std.Io.Reader` has a closed error set, so a body reader reports a
/// short transfer as `error.ReadFailed` and names it here. `Exchange.check`
/// is what turns that generic failure into this name. `zurl-stream`'s
/// `Throttle` uses the same shape for the same reason.
pub const BodyError = error{
    /// The peer announced a content length and then stopped before it.
    PartialFile,
    /// The peer sent no octet for as long as the engine waits on one read.
    ///
    /// **This is the fault a rate watchdog above the engine cannot
    /// report.** `zurl_stream.Stall` is `--speed-limit` and `--speed-time`,
    /// and it measures a read once the read comes back. A peer that keeps
    /// the socket open and writes nothing never lets a read come back, so
    /// the watchdog stays quiet and the transfer never ends. The engine
    /// keeps the deadline instead, and this is the name for it. See
    /// `h1.default_read_timeout_s`.
    ///
    /// A connection that reported this never goes back in the pool. The
    /// peer stopped at a place the engine cannot know, so what is left on
    /// the socket would reach the next request.
    OperationTimedOut,
};

/// One request/response round trip, open for reading the body.
pub const Exchange = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        head: *const fn (ptr: *anyopaque) Head,
        bodyReader: *const fn (ptr: *anyopaque, buffer: []u8) *std.Io.Reader,
        check: *const fn (ptr: *anyopaque) BodyError!void,
        close: *const fn (ptr: *anyopaque) void,
        adoptChain: *const fn (ptr: *anyopaque, storage: []u8, url: []const u8) void,
        withheldCredential: *const fn (ptr: *anyopaque) void,
        trailers: *const fn (ptr: *anyopaque) ?[]const u8,
    };

    /// The trailer section the peer sent after the body, rendered the way
    /// `curl -D` writes it, or null when it sent none.
    ///
    /// **Read this after the body ends and not before.** A trailer section
    /// arrives behind the last body octet, which is the whole point of one:
    /// RFC 9110 section 6.5 is for a field whose value the sender does not
    /// know until the body is done. An engine that has not reached the end
    /// of the body has not seen the trailers and answers null.
    ///
    /// **The shape is field lines and nothing else.** One `name: value\r\n`
    /// for each field, in the order they arrived, with no status line
    /// before them and no empty line after them. That is what curl 8.21.0
    /// appends to a `-D` file and to `-i` output, measured against a server
    /// that sent `grpc-status: 0` and `x-end: yes` behind the body:
    ///
    /// ```text
    /// HTTP/2 200 \r\n
    /// content-type: text/plain\r\n
    /// \r\n
    /// grpc-status: 0\r\n
    /// x-end: yes\r\n
    /// ```
    ///
    /// **These fields are not part of `Head.headers`.** curl does not put
    /// them there either: measured, `%header{grpc-status}` answered empty
    /// for the trailer above, `%{size_header}` counted the head block
    /// alone, and `%{header_json}` left the trailer out. A trailer is a
    /// field a caller may read only after it has the whole body, so a
    /// lookup that found one in the head would answer differently
    /// depending on when it ran.
    ///
    /// Borrowed from the `Exchange`. Valid until `Exchange.close`.
    pub fn trailers(exchange: *Exchange) ?[]const u8 {
        return exchange.vtable.trailers(exchange.ptr);
    }

    /// Hands the exchange the scratch a redirect chain walked in, and the
    /// url text of the final hop inside it.
    ///
    /// **The exchange takes over `storage` and frees it at `close`.** Only
    /// the loop that walked the chain has this text, and only the exchange
    /// that ends the chain outlives that loop, so the memory has to change
    /// owner here. `url` must point into `storage`, which is what makes
    /// `Head.effective_url` live as long as `Head.location` does.
    ///
    /// This is a call and not a field write, because an engine keeps its
    /// own exchange type behind `ptr` and the caller may not know which
    /// engine answered. A chain that started on HTTP/1.1 can end on an
    /// HTTP/2 hop.
    pub fn adoptChain(exchange: *Exchange, storage: []u8, url: []const u8) void {
        exchange.vtable.adoptChain(exchange.ptr, storage, url);
    }

    /// Records `Head.credential_withheld`.
    ///
    /// The engine sent this request again with no secret, so the answer
    /// comes from a request that carried none. See
    /// `Head.credential_withheld` for why a caller has to be told.
    pub fn withheldCredential(exchange: *Exchange) void {
        exchange.vtable.withheldCredential(exchange.ptr);
    }

    /// The status and the headers the front package needs to decide how to
    /// read the body.
    pub fn head(exchange: *const Exchange) Head {
        return exchange.vtable.head(exchange.ptr);
    }

    /// Returns a reader for the response body, decoding any content
    /// encoding the peer used. `buffer` is scratch space for the engine's
    /// own framing; it need not be sized to the body.
    ///
    /// Asserts this is called at most once per exchange.
    pub fn bodyReader(exchange: *const Exchange, buffer: []u8) *std.Io.Reader {
        return exchange.vtable.bodyReader(exchange.ptr, buffer);
    }

    /// Reports why the body reader failed, when the reason is one this
    /// seam names rather than one `std.Io.Reader` names.
    ///
    /// Call this after a body reader returns `error.ReadFailed`. The
    /// reader turns a transfer that stops short of its announced content
    /// length into that error, so `allocRemaining` and `streamRemaining`
    /// fail instead of handing back a body that is not all there.
    pub fn check(exchange: *const Exchange) BodyError!void {
        return exchange.vtable.check(exchange.ptr);
    }

    /// Releases the exchange. Invalidates `head().location`,
    /// `head().headers`, `head().final_headers`, `head().effective_url`,
    /// and any reader returned by `bodyReader`.
    ///
    /// **This does not always close the socket.** An engine may keep the
    /// connection to serve another request to the same origin, which is
    /// what `h1.Engine` does. An engine keeps a connection only where it
    /// can prove the stream sits at the start of the next response, so a
    /// caller that stops reading a body early costs that connection and
    /// nothing more. Every connection an engine still holds is closed by
    /// the engine's own `deinit`, so a caller must close every exchange
    /// before it closes the engine.
    pub fn close(exchange: *Exchange) void {
        exchange.vtable.close(exchange.ptr);
    }
};

/// The faults a `TlsSetup` can report.
///
/// Every name here is already an `OpenError` member, so an engine passes
/// any of them on unchanged. `SslConnectError` covers every reason the
/// trust roots did not become ready that has no more specific name.
/// `CaCertBadFile` and `PeerFailedVerification` name the two reasons that
/// do: a certificate file the caller named could not be read, and a
/// certificate directory the caller named could not be scanned. A
/// handshake with no roots cannot verify the peer, so one of these three
/// is the fault the caller must see.
pub const TlsSetupError = error{ SslConnectError, PeerFailedVerification, CaCertBadFile, OutOfMemory };

/// What an engine calls before each hop that speaks TLS, so the owner of
/// the engine can make the trust store ready.
///
/// The engine owns no trust store of its own. `zurl-http` does not link
/// the loader, and the sources come from flags and environment variables
/// that only the front package reads. So the engine names the moment, and
/// the owner does the work.
///
/// The moment matters. A transfer that stays on `http` never calls this,
/// so a certificate path that cannot be read cannot fail a transfer that
/// uses no TLS. A redirect chain that changes scheme reaches this call at
/// the first `https` hop, whatever scheme the caller named first.
///
/// `ptr` is the owner. It must stay valid for as long as the engine can
/// call `call`, which is every `open` from the moment the owner sets this
/// field.
pub const TlsSetup = struct {
    ptr: *anyopaque,
    call: *const fn (ptr: *anyopaque) TlsSetupError!void,
};

/// The same seam, for the hop to an `https` proxy.
///
/// **It is a second hook and not a second call of the first one, because
/// the two load different roots.** `--proxy-cacert` and `--proxy-capath`
/// name the roots that verify the proxy, and `--cacert` and `--capath` name
/// the roots that verify the origin. A build with one hook would verify one
/// peer against the other's roots at some hop, and no test of the origin
/// path would see it.
///
/// The engine calls this before a hop that puts TLS on the connection to
/// the proxy, and never before a hop that only tunnels through a cleartext
/// proxy. `Engine.proxy_tls_setup` is the field, and it is separate from
/// `Engine.tls_setup` all the way down to the bundle each one fills.
pub const ProxyTlsSetup = TlsSetup;

/// An HTTP engine: something that can open an `Exchange` for a `Request`.
pub const Engine = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        open: *const fn (ptr: *anyopaque, req: Request) OpenError!*Exchange,
        cause: *const fn (ptr: *anyopaque) ?[]const u8,
    };

    /// Sends `req` and waits for the response head. The caller owns the
    /// returned `Exchange` and must call `close` on it exactly once.
    ///
    /// Invalidates `Head.headers` and `Head.final_headers` of every
    /// earlier `open` on this engine. An engine may keep the head blocks
    /// of a redirect chain outside the exchange that ends it, so those
    /// blocks belong to the most recent open and to no other.
    ///
    /// Invalidates `cause` as well: it describes the most recent `open`
    /// and no earlier one.
    pub fn open(engine: Engine, req: Request) OpenError!*Exchange {
        return engine.vtable.open(engine.ptr, req);
    }

    /// Why the last `open` failed, when the fault carried a cause its name
    /// alone does not say. Null when it carried none.
    ///
    /// `open` gives back an error name and no room for a sentence, and for
    /// one whole group of faults the name is not enough: an expired
    /// certificate, a certificate for another host, and a chain that
    /// reaches no trusted root are all `PeerFailedVerification`, which is
    /// exit 60 for all three. Only the sentence says which check refused
    /// the peer, so this is where a caller reads it.
    ///
    /// Read it beside the error `open` returned, and never on its own. The
    /// text is a constant of the engine and outlives any caller.
    pub fn cause(engine: Engine) ?[]const u8 {
        return engine.vtable.cause(engine.ptr);
    }
};

const testing = std.testing;

test "the origin set and the proxy set name no header in common" {
    // **This is the rule the whole proxy path rests on.** A name in both
    // sets would have no one destination: the engine would have to decide
    // per request which peer gets it, and one of the two answers hands a
    // secret to the wrong peer. The sets are walked here rather than
    // compared by hand, so a name added to either array is covered with no
    // edit to this test.
    for (origin_bound_headers) |name| {
        try testing.expect(isOriginBound(name));
        try testing.expect(!isProxyBound(name));
    }
    for (proxy_bound_headers) |name| {
        try testing.expect(isProxyBound(name));
        try testing.expect(!isOriginBound(name));
    }
    try testing.expect(origin_bound_headers.len != 0);
    try testing.expect(proxy_bound_headers.len != 0);
}

test "every proxy-bound header is refused among the headers a caller writes" {
    // `Request.headers` and `Request.secrets` both reach the origin. A
    // proxy credential in either one is the proxy's secret given to the
    // origin server, so the name has to be refused wherever a caller can
    // write it. The value travels on `Request.Proxy.authorization`.
    for (proxy_bound_headers) |name| {
        try testing.expect(isRefused(name));
    }
    // And the refusal reads no case, the way a header name has none.
    try testing.expect(isRefused("proxy-authorization"));
    try testing.expect(isRefused("PROXY-AUTHORIZATION"));
    try testing.expect(isProxyBound("pRoXy-AuThOrIzAtIoN"));
}

test "the proxy credential fields cannot hold an origin credential" {
    // A structural check and not a behaviour one: `Proxy` has three
    // credential fields and every one of them is the proxy's. There is no
    // field an origin `Authorization` could travel in, so no code path can
    // put one there by mistake.
    const credential_fields = comptime blk: {
        var found: usize = 0;
        for (@typeInfo(Proxy).@"struct".fields) |field| {
            if (std.mem.eql(u8, field.name, "authorization")) found += 1;
            if (std.mem.eql(u8, field.name, "user")) found += 1;
            if (std.mem.eql(u8, field.name, "password")) found += 1;
            // No field of this struct names the origin at all.
            if (std.mem.indexOf(u8, field.name, "origin") != null) break :blk 0;
            if (std.mem.indexOf(u8, field.name, "secret") != null) break :blk 0;
        }
        break :blk found;
    };
    try testing.expectEqual(@as(usize, 3), credential_fields);
}

test "a hop with no proxy set dials the origin, whatever the scheme" {
    const empty: ProxySet = .{};
    try testing.expect(empty.isEmpty());
    try testing.expectEqual(@as(?Proxy, null), empty.forHop(false, "example.com"));
    try testing.expectEqual(@as(?Proxy, null), empty.forHop(true, "example.com"));
}

test "a hop reads the proxy of its own scheme" {
    // curl reads `http_proxy` for a cleartext target and `https_proxy` for
    // a TLS one, and a redirect chain can change the scheme between hops.
    const cleartext: Proxy = .{ .kind = .http, .host = "127.0.0.1", .port = 3128 };
    const secure: Proxy = .{ .kind = .http, .host = "127.0.0.2", .port = 3129 };
    const set: ProxySet = .{ .http = cleartext, .https = secure };

    try testing.expectEqualStrings("127.0.0.1", set.forHop(false, "example.com").?.host);
    try testing.expectEqualStrings("127.0.0.2", set.forHop(true, "example.com").?.host);
    try testing.expect(!set.isEmpty());

    // One scheme alone leaves the other dialing the origin.
    const only_http: ProxySet = .{ .http = cleartext };
    try testing.expectEqualStrings("127.0.0.1", only_http.forHop(false, "example.com").?.host);
    try testing.expectEqual(@as(?Proxy, null), only_http.forHop(true, "example.com"));
}

test "a host the bypass list names reaches no proxy on either scheme" {
    const spec: Proxy = .{ .kind = .http, .host = "127.0.0.1", .port = 3128 };
    const set: ProxySet = .{ .http = spec, .https = spec, .no_proxy = "example.com" };

    try testing.expectEqual(@as(?Proxy, null), set.forHop(false, "example.com"));
    try testing.expectEqual(@as(?Proxy, null), set.forHop(true, "sub.example.com"));
    // And a host outside the list still goes through the proxy.
    try testing.expectEqualStrings("127.0.0.1", set.forHop(false, "other.test").?.host);
}

test "two proxies are the same route only when every routing field agrees" {
    const base: Proxy = .{ .kind = .http, .host = "127.0.0.1", .port = 3128 };
    try testing.expect(base.sameRoute(base));

    var other = base;
    other.port = 3129;
    try testing.expect(!base.sameRoute(other));

    other = base;
    other.host = "127.0.0.2";
    try testing.expect(!base.sameRoute(other));

    other = base;
    other.kind = .socks5;
    try testing.expect(!base.sameRoute(other));

    // **The proxy's own verification answer is part of the route.** A
    // connection opened through a proxy nobody authenticated must never
    // serve a request that asked for one.
    other = base;
    other.insecure = true;
    try testing.expect(!base.sameRoute(other));

    // The credential is not compared here. `h1.Origin` compares a digest of
    // it, because a pooled connection must not hold a secret in cleartext
    // for the life of the client.
    other = base;
    other.authorization = "Basic Ym9iOnB3";
    try testing.expect(base.sameRoute(other));
}

test "the engine reads the one dial rule and not a copy of it" {
    // `HostOverride` and `dialTarget` moved to `zurl_net.override`, so
    // every protocol package reads the rule the HTTP engine reads.
    // `zurl-net/override.zig` holds the tests of the rule itself. This one
    // holds the re-export: an engine that grew a second definition would
    // fail here.
    try testing.expectEqual(zurl_net.override.HostOverride, HostOverride);
    try testing.expectEqual(zurl_net.override.DialTarget, DialTarget);

    const list: []const HostOverride = &.{
        .{ .from_host = "example.com", .from_port = 443, .to_host = "127.0.0.1", .to_port = 8443 },
    };
    const moved = dialTarget(list, "example.com", 443);
    try testing.expectEqualStrings("127.0.0.1", moved.host);
    try testing.expectEqual(@as(u16, 8443), moved.port);
    try testing.expect(moved.overridden);
}

test "a head that ends on two line feeds is walked and does not stop the program" {
    // **This is the head that crashed a shipped build.**
    // `std.http.HeadParser` ends a head here, and
    // `std.http.HeaderIterator.init` unwraps a null looking for a carriage
    // return that this head never held. Measured before the fix: a build
    // with safety checks stopped on `attempt to use null value`, and a
    // `ReleaseSmall` build exited 134. A server writes 17 octets for it.
    var it: HeadFields = .init("HTTP/1.1 200 OK\n\n");
    try testing.expect(it.next() == null);

    // The same head carrying a field, to show the walk reads it and does
    // not merely survive.
    var with_field: HeadFields = .init("HTTP/1.1 200 OK\ncontent-encoding: gzip\n\n");
    const field = with_field.next().?;
    try testing.expectEqualStrings("content-encoding", field.name);
    try testing.expectEqualStrings("gzip", field.value);
    try testing.expect(with_field.next() == null);
}

test "the walk reads a head written with carriage returns the same way" {
    // The ordinary head. Both endings must give one answer, because the
    // engine reads one head and cannot know which the peer wrote.
    var crlf: HeadFields = .init("HTTP/1.1 200 OK\r\na: 1\r\nb: 2\r\n\r\n");
    var lf: HeadFields = .init("HTTP/1.1 200 OK\na: 1\nb: 2\n\n");
    for ([_][2][]const u8{ .{ "a", "1" }, .{ "b", "2" } }) |want| {
        const from_crlf = crlf.next().?;
        const from_lf = lf.next().?;
        try testing.expectEqualStrings(want[0], from_crlf.name);
        try testing.expectEqualStrings(want[1], from_crlf.value);
        try testing.expectEqualStrings(want[0], from_lf.name);
        try testing.expectEqualStrings(want[1], from_lf.value);
    }
    try testing.expect(crlf.next() == null);
    try testing.expect(lf.next() == null);
}

test "the walk stops at the blank line and never reads the body" {
    // A body that looks like a field must not become one.
    var it: HeadFields = .init("HTTP/1.1 200 OK\r\na: 1\r\n\r\nx-body: 2\r\n");
    const first = it.next().?;
    try testing.expectEqualStrings("a", first.name);
    try testing.expect(it.next() == null);
}

test "a head the walk cannot read carries no field instead of stopping" {
    // Every one of these reached `std.http.HeaderIterator`'s unwrap or its
    // arithmetic before. None of them may stop the program now.
    for ([_][]const u8{
        "",
        "\n",
        "\r\n",
        "HTTP/1.1 200 OK",
        "HTTP/1.1 200 OK\n",
        "\n\n",
    }) |head| {
        var it: HeadFields = .init(head);
        while (it.next()) |_| {}
    }
}

test "a field name and value slice the head the caller gave" {
    // `h1.parseRefusedHead` finds where a field sits by the address of its
    // name, so the slices must point into the caller's octets and not into
    // a copy.
    const head = "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\n\r\n";
    var it: HeadFields = .init(head);
    const field = it.next().?;
    const at = @intFromPtr(field.name.ptr) - @intFromPtr(head.ptr);
    try testing.expectEqual(@as(usize, 17), at);
    try testing.expectEqualStrings("content-encoding", head[at .. at + field.name.len]);
}

test "a line with no colon is skipped and the fields after it are still read" {
    var it: HeadFields = .init("HTTP/1.1 200 OK\r\ngarbage\r\na: 1\r\n\r\n");
    const field = it.next().?;
    try testing.expectEqualStrings("a", field.name);
    try testing.expect(it.next() == null);
}

test "a field name is an RFC 9110 token and nothing else" {
    // The whole `tchar` set of section 5.6.2. A rule that refused any of
    // these would refuse traffic that real servers send.
    const legal = [_][]const u8{
        "content-type",
        "x-request-id-0123456789",
        "!#$%&'*+-.^_`|~",
        "a",
        "0",
    };
    for (legal) |name| {
        try testing.expect(headerNameIsToken(name, .mixed));
        try testing.expect(headerNameIsToken(name, .lower));
    }

    // The injection octets. A CR or an LF ends a line of the rendered
    // block, a colon starts the value on one, and a space and a NUL both
    // reach a parser that reads the block back.
    const forged = [_][]const u8{
        "x-a\r\nset-cookie: injected=1",
        "x-a\nset-cookie: injected=1",
        "x-a\rset-cookie: injected=1",
        "x-a\x00b",
        "x-a b",
        "x-a:b",
        "x-a\x7f",
        "x-a\t",
        "x-a\xc3\xa9",
        "(x-a)",
        "x-a,b",
        "\"x-a\"",
        // A name of no octets at all names no field.
        "",
    };
    for (forged) |name| {
        try testing.expect(!headerNameIsToken(name, .mixed));
        try testing.expect(!headerNameIsToken(name, .lower));
    }

    // Case is the one part the caller chooses. HTTP/1.1 sends the name as
    // the caller wrote it, and HTTP/2 and HTTP/3 make an upper-case letter
    // a malformed message.
    try testing.expect(headerNameIsToken("Content-Type", .mixed));
    try testing.expect(!headerNameIsToken("Content-Type", .lower));
}

test "h2 and h3 read the one field name rule" {
    // The finding says `validateResponseFields` was copied verbatim into
    // both engines, and that the copy in each one checked a field name for
    // an upper-case letter and for nothing else. So a rule added to one
    // copy would not reach the other, which is how the value rule came to
    // be stricter than the name rule beside it.
    //
    // Both engines now name `headerNameIsToken` and hold no name loop of
    // their own. The needles are built at run time, so this test's own
    // text is not what it finds.
    const sources = [_][]const u8{ @embedFile("h2.zig"), @embedFile("h3.zig") };

    var needle_buf: [64]u8 = undefined;
    const gone = std.fmt.bufPrint(&needle_buf, "std.ascii.{s}(byte)", .{"isUpper"}) catch unreachable;

    var shared_buf: [64]u8 = undefined;
    const shared = std.fmt.bufPrint(&shared_buf, "engine.{s}(item.name, .lower)", .{
        "headerNameIsToken",
    }) catch unreachable;

    for (sources) |source| {
        // No copy of the old name loop is left in either engine.
        try testing.expect(std.mem.indexOf(u8, source, gone) == null);

        // And each engine asks the shared rule exactly once, in its one
        // `validateResponseFields`.
        var count: usize = 0;
        var index: usize = 0;
        while (std.mem.indexOfPos(u8, source, index, shared)) |at| {
            count += 1;
            index = at + shared.len;
        }
        try testing.expectEqual(@as(usize, 1), count);
    }
}

test "a Content-Length value is 1*DIGIT and nothing wider" {
    // The grammar RFC 9112 section 6.2 writes, and the shapes
    // `std.fmt.parseInt` takes that it does not. Measured against curl
    // 8.21.0: `+5` and `1_0` are exit 8, `005` is exit 0.
    try testing.expect(contentLengthIsDigits("0"));
    try testing.expect(contentLengthIsDigits("5"));
    try testing.expect(contentLengthIsDigits("005"));
    try testing.expect(contentLengthIsDigits("18446744073709551615"));

    // `std.fmt.parseInt` reads the first two of these as 5 and 10.
    try testing.expect(!contentLengthIsDigits("+5"));
    try testing.expect(!contentLengthIsDigits("1_0"));
    try testing.expect(!contentLengthIsDigits("-5"));
    // An empty field names no length at all.
    try testing.expect(!contentLengthIsDigits(""));
    // A list, a hexadecimal prefix, and a trailing unit are each a value
    // some parser in a path would read and another would not.
    try testing.expect(!contentLengthIsDigits("5, 5"));
    try testing.expect(!contentLengthIsDigits("0x5"));
    try testing.expect(!contentLengthIsDigits("5 "));
}

test "a trailing root dot is read off a host before no_proxy matches it" {
    // DNS reads `example.com.` and `example.com` as one name, and curl
    // 8.21.0 matches a `no_proxy` entry against either spelling. Measured
    // with `http_proxy` pointing at a port that refuses: a host of
    // `example.test.` against `no_proxy=example.test` went direct.
    try testing.expectEqualStrings("example.test", proxyMatchHost("example.test."));
    try testing.expectEqualStrings("example.test", proxyMatchHost("example.test"));
    // Only one dot goes. `example.test..` is not a name DNS reads.
    try testing.expectEqualStrings("example.test.", proxyMatchHost("example.test.."));
    // An address carries no trailing dot and passes through whole.
    try testing.expectEqualStrings("127.0.0.1", proxyMatchHost("127.0.0.1"));
    try testing.expectEqualStrings("::1", proxyMatchHost("::1"));
    // A host that is one dot is not a name with a root label removed. It
    // would become the empty host, which matches no entry at all.
    try testing.expectEqualStrings(".", proxyMatchHost("."));
    try testing.expectEqualStrings("", proxyMatchHost(""));
}

test "a url host with a trailing dot reaches no proxy the user excluded" {
    // The finding: the suffix rule compares text, so `example.test.`
    // matched neither the equality arm nor the suffix arm against an entry
    // of `example.test`, and the request went to the proxy the user
    // excluded. That puts the request head, and any `Authorization` on it
    // for a cleartext origin, in front of that proxy.
    const set: ProxySet = .{
        .http = .{ .kind = .http, .host = "proxy.invalid", .port = 3128 },
        .no_proxy = "example.test",
    };

    try testing.expect(set.forHop(false, "example.test") == null);
    try testing.expect(set.forHop(false, "example.test.") == null);
    try testing.expect(set.forHop(false, "a.example.test.") == null);
    // A host the list does not name still goes through the proxy, so the
    // repair widened nothing else.
    try testing.expect(set.forHop(false, "other.test") != null);
    try testing.expect(set.forHop(false, "other.test.") != null);
    try testing.expect(set.forHop(false, "notexample.test.") != null);
}
