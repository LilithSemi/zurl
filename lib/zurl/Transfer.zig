//! The runtime settings for one transfer.
//!
//! `Options` is a plain data bag. Every field is settable at run time, and
//! every callback is a `ctx: *anyopaque` plus a `callconv(.c)` function
//! pointer. A later phase exposes a libcurl-compatible C ABI and passes a C
//! callback straight through this bag with no shim. This file must never
//! grow a comptime-only field or a Zig closure; either would break that
//! phase silently.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_stream = @import("zurl-stream");
const zurl_http = @import("zurl-http");

/// What `Options.redirects` chooses between: report a 3xx unfollowed, or
/// follow up to a limit. Re-exported from `zurl_http.engine` so a caller
/// that only imports `zurl` still has a name for it.
pub const Redirects = zurl_http.engine.Redirects;

/// What `Options.body` holds: where the request body comes from, and how
/// many bytes of it there are. Re-exported from `zurl_http.engine` for the
/// same reason `Redirects` is, so a caller that only imports `zurl` still
/// has a name for it.
///
/// It is a plain data bag with a `callconv(.c)` read callback, which is
/// what this file's header comment asks of every field. See
/// `zurl_http.engine.Body`.
pub const Body = zurl_http.engine.Body;

/// What `Options.connect_to` holds: where a url naming one host and port
/// dials instead. Re-exported from `zurl_http.engine` for the same reason
/// `Body` is, so a caller that only imports `zurl` still has a name for
/// it. See `zurl_http.engine.HostOverride`, which holds the rule that an
/// entry moves the dial and never the name a certificate is checked
/// against.
pub const HostOverride = zurl_http.engine.HostOverride;

/// Which HTTP version a hop asks for. Re-exported from
/// `zurl_http.engine` for the same reason `Redirects` is: a caller sets
/// `Options.http_version` and needs the type without a second import.
pub const HttpVersion = zurl_http.engine.HttpVersion;

/// Which HTTP version framed a response, which is what
/// `Response.http_version` reports and what `-w %{http_version}` prints.
/// Re-exported for the same reason `HttpVersion` is: a caller reads the
/// field and needs a name for its type. **The two are not the same type
/// and must not be confused**: one is what a flag asked for, the other is
/// what the peer answered in.
pub const WireVersion = zurl_http.engine.WireVersion;

/// What `Options.proxy` and `Options.proxy_tls` hold: the kind, the host,
/// the port, and the credential a proxy url names. Re-exported from
/// `zurl_core.proxy` for the same reason `Body` is, so a caller that only
/// imports `zurl` still has a name for it.
pub const ProxySpec = zurl_core.proxy.Spec;

/// Which HTTP authentication scheme a transfer may use, and when the
/// credential first goes out. `Options.auth_mode` holds one.
///
/// **The difference between the three is where the password goes and
/// when.** A preemptive `Basic` puts the password on the wire in
/// reversible base64 before the server has asked for anything. A user who
/// names `--digest` asked for a scheme where the password never travels,
/// so a transfer under `.digest` sends no credential until the server
/// names Digest, and it answers no other scheme at all.
pub const AuthMode = enum {
    /// Send `Basic` with the first request, and answer whatever challenge
    /// a `401` carries. This is the default and it is `--basic`.
    basic,
    /// Send no credential with the first request. Answer a `401` only when
    /// the challenge names Digest. This is `--digest`.
    ///
    /// A `401` that offers Basic alone goes back to the caller unanswered,
    /// with the reason in `Diagnostics.message`. Answering it with Basic
    /// would send the password the flag exists to keep off the wire.
    digest,
    /// Send no credential with the first request, and answer whatever
    /// challenge a `401` carries. This is `--anyauth`.
    any,

    /// Whether a transfer in this mode sends a credential before the
    /// server has asked for one.
    pub fn sendsPreemptiveCredential(m: AuthMode) bool {
        return m == .basic;
    }

    /// Whether a transfer in this mode may answer a challenge of
    /// `scheme`.
    pub fn answers(m: AuthMode, scheme: zurl_core.auth.Scheme) bool {
        return switch (m) {
            .basic, .any => true,
            .digest => scheme == .digest,
        };
    }
};

/// One transfer's settings. Each field notes the curl flag it maps to.
pub const Options = struct {
    /// The HTTP method. This is `-X`.
    ///
    /// Any method may go out, with a body or with none. The method does
    /// not decide the body and the body does not decide the method: a
    /// `POST` with a null `body` sends no framing header and no body,
    /// which is what `curl -X POST` sends with no data.
    method: std.http.Method = .GET,
    /// The request body. This is `-d`, `--data-binary`, `--json`, and
    /// `-T`. Null for a request that carries none.
    ///
    /// The engine frames it: `content-length` for a known length, and the
    /// chunked transfer coding for a body whose length is not known before
    /// it goes out, such as one read from a pipe. A `Content-Length` or a
    /// `Transfer-Encoding` in `headers` is refused, because this field is
    /// the one answer to how the request is framed.
    ///
    /// **A body does not always survive a redirect.** A `301`, a `302`, or
    /// a `303` that the transfer follows drops the body and asks for the
    /// target with `GET`, and a `307` or a `308` keeps it.
    ///
    /// **A body that goes out twice needs `Body.rewind`.** A redirect that
    /// keeps the body, a retry on a connection the peer had closed, and
    /// the answer to a `401` challenge each send the same request again. A
    /// source with no rewind, which is what a pipe gives, is
    /// `error.WriteError` on the second send rather than a request that
    /// starts in the middle of its own body.
    body: ?Body = null,
    /// Extra request headers. This is `-H`.
    ///
    /// An `Authorization` header here is the transfer's credential, and it
    /// outranks `credentials`, the url's userinfo, and `netrc_text`. zurl
    /// then builds none of its own and answers no `401` challenge, the way
    /// curl treats a `-H Authorization`.
    ///
    /// A header whose name `zurl_http.engine.origin_bound_headers` lists,
    /// which is `Authorization` and `Cookie` today, leaves this list before
    /// the request goes out. It reaches the origin the url names, and no
    /// host a redirect points at. curl does the same, and crosses an origin
    /// only with `--location-trusted`, which `location_trusted` below is.
    ///
    /// A header whose name `zurl_http.engine.refused_headers` lists ends
    /// the transfer with `error.WriteError` and a message in
    /// `Diagnostics`. **`Proxy-Authorization` is there because this build
    /// writes the proxy credential itself**, from `proxy`, and a copy from
    /// this list would go out beside it. An earlier comment here said the
    /// reason was that zurl reached no proxy at all, which stopped being
    /// true when `zurl_net.proxy` grew `CONNECT` and SOCKS. The refusal is
    /// unchanged and only the reason for it moved. `Host`,
    /// `Content-Length`, `Transfer-Encoding`,
    /// `Connection`, and `Expect` are there because the engine writes them
    /// itself: a copy from here goes out beside the engine's own, and two
    /// of either header lets a peer read one request as two.
    headers: []const std.http.Header = &.{},
    /// Whether to follow a redirect, and the limit when it does. This is
    /// `-L` together with `--max-redirs`.
    ///
    /// Reuses `zurl_http.engine.Redirects` rather than a field of its own,
    /// so the front package states the same choice the engine already
    /// makes, with no second type that could drift from it.
    ///
    /// Defaults to following, up to 10 hops. `curl_transport.zig`, the file
    /// this package replaces, set `CURLOPT_FOLLOWLOCATION` unconditionally,
    /// so a default-constructed `Options` must keep following; `fix` builds
    /// on that. curl's own command-line default is the opposite, no
    /// following at all, so `src/cli/Args.zig` sets this field itself
    /// rather than leaving it at the default: `.unfollowed` with no `-L`,
    /// `.{ .follow = 50 }` with `-L` and no `--max-redirs`, curl's own
    /// default limit.
    redirects: zurl_http.engine.Redirects = .{ .follow = 10 },
    /// Turns an HTTP error status into a failure instead of returning the
    /// body. This is `--fail`.
    fail_on_error: bool = false,
    /// A cap on how long connecting to the peer may take, the TLS
    /// handshake included. This is `--connect-timeout`. `.none` waits
    /// forever.
    ///
    /// This is `std.Io.Timeout`, not a millisecond count: `zurl-http`'s
    /// engine takes the connect bound in this exact shape and races it
    /// against the connect through `std.Io.Select`. Storing anything else
    /// here would need a unit conversion at the call site, and a
    /// conversion is one more place to get the bound wrong.
    ///
    /// A build with no concurrency cannot race the connect against this
    /// bound. `Client.perform` falls back to connecting with no bound at
    /// all, and records the fallback in `Diagnostics.message`. On such a
    /// build, treat this field as best-effort, not a guarantee.
    connect_timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(15), .clock = .awake } },
    /// The slowest acceptable transfer rate, in bytes each second. This is
    /// `--speed-limit`.
    low_speed_limit: u64 = 1,
    /// How long the transfer rate may stay below `low_speed_limit`, in
    /// seconds. This is `--speed-time`.
    low_speed_time_s: u32 = 300,
    /// A cap on the transfer rate, in bytes each second. Zero means no
    /// limit. This is `--limit-rate`.
    max_bytes_per_second: u64 = 0,
    /// A cap on the response size, in bytes. Zero means no limit. This is
    /// `--max-filesize`.
    ///
    /// Measures the body after any content decoding, the same bytes a
    /// download writes to disk and a reporter counts as transferred. curl's
    /// own manual describes `--max-filesize` as a cap on "the maximum size
    /// of a file to download", which is the saved file, not the bytes that
    /// crossed the wire; decoded is the reading that keeps that promise
    /// when the peer compresses the body. `zurl_stream.Progress.total`
    /// reports zero, unknown, for a decoded body rather than the peer's
    /// pre-decoding `Content-Length`, so the total a reporter sees and the
    /// count it accumulates always describe the same bytes.
    max_size: u64 = 0,
    /// Who to tell about transfer progress. A `null` reporter is `-s`.
    reporter: ?zurl_stream.Reporter = null,
    /// Credentials to send. This is `-u`.
    credentials: ?zurl_core.auth.Credentials = null,
    /// The text of a `.netrc` file, already read by the caller. This is
    /// `--netrc-file`.
    ///
    /// curl's `-n` and `--netrc` are a different flag. They take no argument
    /// and read the default path. This field holds text the caller already
    /// read, so it matches `--netrc-file`, which names an explicit file.
    netrc_text: ?[]const u8 = null,
    /// Which HTTP authentication scheme the transfer may use, and when the
    /// credential first goes out. This covers `--basic`, `--digest`, and
    /// `--anyauth`.
    auth_mode: AuthMode = .basic,
    /// The `User-Agent` header value. This is `-A`.
    user_agent: []const u8 = "zurl/0.1",
    /// Whether the request offers the peer a compressed body. This is
    /// `--compressed`.
    ///
    /// **False sends no `Accept-Encoding` header, which is what curl
    /// does.** Measured against curl 8.21.0 on a loopback listener: a
    /// plain `curl` sends no such header, and `curl --compressed` sends
    /// `Accept-Encoding: deflate, gzip, br, zstd`. A client that asks on
    /// every request reads a compressed answer where curl reads a plain
    /// one, so the flag owns the header here too.
    ///
    /// True offers `deflate`, `gzip`, and `zstd`, and the engine decodes
    /// the answer before any layer above it counts an octet. `max_size`
    /// and the progress reporter therefore both still measure the decoded
    /// body. See `max_size`. A coding this build has no decoder for is
    /// `error.BadContentEncoding` under this flag, because the flag is the
    /// promise that the body comes back decoded.
    ///
    /// **False ignores a `Content-Encoding` the peer sends anyway**, and
    /// writes the peer's own octets out. That is what curl does with an
    /// unsolicited coding, measured, and real servers send them. See
    /// `zurl_http.engine.contentEncoding`, which is the one rule all three
    /// HTTP engines read.
    ///
    /// Only HTTP carries this. Every other protocol applies no content
    /// coding, so the field reaches no other fetcher.
    accept_encoding: bool = false,
    /// Where to look for certificate authorities. This covers `--cacert`,
    /// `--capath`, and `--ca-native` together.
    ///
    /// A `Client` loads its trust bundle once, from the first transfer
    /// that needs it. A later transfer's `ca` is ignored, the same way
    /// curl's easy handle keeps one trust store for its whole life.
    ca: zurl_core.ca.Inputs = .{},
    /// Which protocols the url may name. This is `--proto`.
    ///
    /// `Client.perform` refuses a url outside this set with
    /// `error.UnsupportedProtocol`, before it resolves the protocol and
    /// before it opens anything. curl answers the same shape with exit 1
    /// and `Protocol "http" is disabled`, and `UnsupportedProtocol` is
    /// exit 1 here too.
    ///
    /// The default is every name `zurl_core.redirect.Protocol` holds, so a
    /// caller that sets nothing turns nothing off. A url naming a protocol
    /// this build cannot open still fails, from the dispatch table that
    /// has no entry for it.
    protocols: zurl_core.redirect.Set = zurl_core.redirect.transfer_default,
    /// Which protocols a `location:` header may name. This is
    /// `--proto-redir`.
    ///
    /// Passed straight to `zurl_http.engine.Request.redirect_protocols`,
    /// which is where the engine enforces it. The default is curl's own
    /// `--proto-redir` default, which holds no `file`.
    ///
    /// This is a separate set from `protocols`, and curl keeps them
    /// separate too: `--proto` starts from every protocol the build
    /// speaks, and `--proto-redir` starts from the four names above. A
    /// user who narrows one has not narrowed the other.
    redirect_protocols: zurl_core.redirect.Set = zurl_core.redirect.redirect_default,
    /// The lowest TLS version to keep. This is `--tlsv1.2` and
    /// `--tlsv1.3`.
    ///
    /// `zurl_core.tls.MinVersion` says what the floor of this build is and
    /// why `--tlsv1.0` and `--tlsv1.1` cannot move it down.
    tls_min_version: zurl_core.tls.MinVersion = .floor,
    /// The highest TLS version to keep. This is `--tls-max`.
    ///
    /// `zurl_core.tls.Version` says which values a flag can name.
    /// `--tls-max 1.3` is the default and changes nothing, `--tls-max 1.2`
    /// narrows the client hello, and a ceiling below TLS 1.2 leaves no
    /// version at all and fails the transfer.
    tls_max_version: zurl_core.tls.Version = .highest,
    /// Whether the client hello leaves the ALPN extension out. This is
    /// `--no-alpn`.
    ///
    /// The default sends the extension and offers `h2` and then
    /// `http/1.1`. **With no extension there is no HTTP/2**, because a
    /// peer cannot choose a protocol it was never offered, so a hop opened
    /// under this flag speaks HTTP/1.1.
    no_alpn: bool = false,
    /// Which HTTP version a hop asks for. This is `--http1.1`, `--http2`,
    /// `--http2-prior-knowledge`, `--http3`, and `--http3-only`.
    ///
    /// The default offers `h2` and `http/1.1` over TLS and the peer picks.
    /// `--http1.1` narrows the offer to `http/1.1`, which is the way back
    /// to the older protocol when a peer's HTTP/2 misbehaves. A cleartext
    /// hop is HTTP/1.1 whichever value this holds, because zurl speaks no
    /// HTTP/2 without TLS.
    ///
    /// **HTTP/3 is never the default, and no TLS offer over TCP names
    /// `h3`.** `--http3` opens a QUIC connection on UDP first and takes
    /// the TCP hop when QUIC does not answer; `--http3-only` takes no
    /// other answer. curl requires the flag for the same reason: QUIC
    /// needs UDP 443 reachable end to end. See
    /// `zurl_http.engine.HttpVersion`.
    http_version: zurl_http.engine.HttpVersion = .any,
    /// A flag the caller raises when this transfer must stop.
    ///
    /// **This is what `-m`/`--max-time` needs over HTTP/3.** A caller that
    /// bounds a transfer runs it as a task and cancels the task when the
    /// bound passes. That cancel reaches a blocked TCP read, so HTTP/1.1
    /// and HTTP/2 need nothing here, and it does not reach a QUIC datagram
    /// wait. The HTTP/3 transport reads this flag at every wait instead.
    /// See `zurl_http.engine.Request.stop`.
    ///
    /// Null for a caller that bounds nothing. Borrowed, and it must
    /// outlive the transfer.
    stop: ?*const std.atomic.Value(bool) = null,
    /// The scheme a url that carries none is read with. This is
    /// `--proto-default`.
    ///
    /// Null keeps the guess `zurl_core.url.parse` already makes: `ftp` for
    /// a host starting `ftp.`, and `http` for every other. curl 8.21.0
    /// replaces that guess outright when the flag is given, measured with
    /// `--proto-default http ftp.gnu.org/`, which reaches
    /// `http://ftp.gnu.org/`.
    ///
    /// The text is borrowed, so it must outlive the transfer.
    default_protocol: ?[]const u8 = null,
    /// Whether a credential may follow a redirect to another host. This is
    /// `--location-trusted`.
    ///
    /// **False is the default and the default must stay false.** With
    /// false, zurl withholds every origin-bound header on a redirect it
    /// follows and reports that it did so. See
    /// `zurl_http.engine.Request.trusted_secrets`, which holds the rule
    /// and the measurement behind it.
    location_trusted: bool = false,
    /// Whether to accept a peer certificate that no root vouches for, and
    /// one that carries the wrong host name. This is `-k`/`--insecure`.
    ///
    /// **False is the default and no fault path may set it true.** A
    /// verification that failed is never a reason to try again without
    /// verification. See `zurl_http.engine.Request.insecure`.
    insecure: bool = false,
    /// Whether to turn Nagle's algorithm off on a new connection. This is
    /// `--no-tcp-nodelay`, which gives false.
    ///
    /// True is what curl does by default. See
    /// `zurl_net.tcp.DialOptions.no_delay`.
    tcp_no_delay: bool = true,
    /// The cookie jar this transfer sends from and stores into. This is
    /// `-b`, `-c`, and `-j` together. `zurl.Jar.interface` builds one.
    ///
    /// **Null keeps no cookie at all**, which is curl's own default: with
    /// no cookie flag on the command line, curl drops every `Set-Cookie` a
    /// peer sends and carries no `Cookie` header of its own. Measured
    /// against curl 8.21.0 with two urls in one invocation.
    ///
    /// **A `Cookie` in `headers` is a different thing, and it takes a
    /// different path.** That header is one the caller wrote, and the
    /// engine cannot know which host it belongs to, so it travels through
    /// `zurl_http.engine.Request.secrets` and is withheld on every
    /// redirect. A jar carries the domain, the path, and the `Secure` flag
    /// of each cookie, so the engine asks it again for each hop and the
    /// jar's own rule decides. See `zurl_http.engine.CookieJar`.
    ///
    /// This is a struct of function pointers and not a Zig closure, so it
    /// keeps this file's rule that `Options` stays a plain data bag. The
    /// pointers are Zig and not `callconv(.c)`, unlike `body`: libcurl
    /// configures cookies with the string options `CURLOPT_COOKIEFILE` and
    /// `CURLOPT_COOKIEJAR` and has no cookie callback, so a later C ABI
    /// has no C function to pass straight through here.
    cookies: ?zurl_http.engine.CookieJar = null,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to` together.
    ///
    /// **An entry moves the dial and nothing else.** The `Host` header,
    /// the TLS server name, the name the peer certificate is checked
    /// against, and the name an SSH host key is looked up under all stay
    /// the ones the url wrote, so this flag can never be used to reach a
    /// peer whose credential names another host. See
    /// `zurl_net.override.HostOverride`, which holds the rule.
    ///
    /// **Every protocol that dials reads this.** The HTTP engine does, and
    /// so does each protocol package, through its own `Options.connect_to`
    /// and its own `Dispatch.translate`. `file` is the one scheme that
    /// reads nothing here, and it opens no socket at all. curl applies
    /// both flags to every scheme, measured against curl 8.21.0 on all
    /// twenty it builds.
    ///
    /// The default is an empty list, which dials exactly what the url
    /// says. Every entry borrows from the caller.
    connect_to: []const HostOverride = &.{},
    /// The proxy a cleartext target goes through. This is `-x` and the
    /// `http_proxy` environment variable.
    ///
    /// Null dials the origin, which is what every transfer did before this
    /// field existed. `zurl_core.proxy.parse` builds the value, and it
    /// borrows from the url text, which must outlive the transfer.
    proxy: ?ProxySpec = null,
    /// The proxy a TLS target goes through. This is `-x` and the
    /// `https_proxy` environment variable.
    ///
    /// A separate field because curl reads a separate variable, and because
    /// a redirect chain can change the scheme between hops. `-x` sets both
    /// fields to the same value: an explicit proxy covers every scheme.
    proxy_tls: ?ProxySpec = null,
    /// Whether the caller named a proxy that covers every protocol.
    ///
    /// This is `-x`/`--proxy`, the `--socks*` family, and `all_proxy`. It
    /// is **not** `http_proxy` or `https_proxy`: curl reads the first for a
    /// cleartext HTTP target and the second for a TLS HTTP one, so neither
    /// answers for an `ftp://` url and neither sets this.
    ///
    /// **It exists so a protocol that carries no proxy can refuse.**
    /// `proxy` and `proxy_tls` hold the HTTP answer alone, so neither says
    /// whether the user asked for indirection on a url of another scheme.
    /// A protocol package outside HTTP reads no proxy field at all, and a
    /// transfer that dialled direct after `-x` failed **open**. See
    /// `zurl.protocol.Protocol.unread`.
    proxy_every_protocol: bool = false,
    /// The hosts that reach no proxy. This is `--noproxy` and the
    /// `no_proxy` environment variable.
    ///
    /// `zurl_core.proxy.bypasses` holds every matching rule and the
    /// measurement behind each one. An empty list excludes nothing, which
    /// is what curl does: measured, an empty `no_proxy` still sent the
    /// request to the proxy.
    no_proxy: []const u8 = "",
    /// The credential to send to the proxy. This is `-U`/`--proxy-user`.
    ///
    /// **This credential goes to the proxy and never to the origin.** The
    /// origin's own credential is `credentials`, from `-u`, and the two are
    /// built by two different files: `zurl/proxy.zig` builds this one and
    /// `zurl/authorize.zig` builds that one. Neither reads the other's
    /// field.
    ///
    /// Null falls back to the userinfo in the proxy url, if it has any.
    proxy_credentials: ?zurl_core.auth.Credentials = null,
    /// Where to look for the certificate authorities that verify an `https`
    /// proxy. This covers `--proxy-cacert` and `--proxy-capath`.
    ///
    /// **A separate store from `ca`, and never the same one.** `ca` names
    /// the roots that verify the origin. A build with one store would
    /// verify one peer against the other's roots at whichever hop loaded
    /// last, and a transfer through a proxy puts both peers in play.
    ///
    /// Read only by a hop that puts TLS on the connection to a proxy, which
    /// is an `https://` proxy url and nothing else.
    proxy_ca: zurl_core.ca.Inputs = .{},
    /// Whether to accept a proxy certificate that no root vouches for, and
    /// one that carries the wrong host name. This is `--proxy-insecure`.
    ///
    /// **It answers for the proxy and for no other peer.** `insecure`
    /// answers for the origin. A `CONNECT` tunnel through a cleartext proxy
    /// still verifies the origin against the origin's name and the origin's
    /// roots, whatever this field holds.
    ///
    /// False is the default and no fault path may set it true, for the
    /// reason `insecure` gives.
    proxy_insecure: bool = false,
    /// Whether a listing names files alone. This is `-l`/`--list-only`.
    ///
    /// HTTP ignores it, which is what curl does: measured against curl
    /// 8.21.0, `-l` gives byte for byte the same answer for an `http://`
    /// url as no flag does. An `ftp://` url that names a directory reads
    /// it: `NLST` with the flag and `LIST` without one, measured.
    list_only: bool = false,
    /// Whether a transfer asks for the ASCII representation. This is
    /// `-B`/`--use-ascii`.
    ///
    /// Read by FTP alone, which sends `TYPE A` instead of `TYPE I` and
    /// turns each CRLF of the answer into one LF. A directory listing
    /// already goes out as `TYPE A` with no flag, so this field changes a
    /// file transfer and nothing else.
    ///
    /// Every other protocol here ignores it, which is what curl does: a
    /// `-B` on an `http://` url gives byte for byte the same answer as no
    /// flag does.
    use_ascii: bool = false,
    /// Whether an FTP transfer sends `PASV` alone. This is
    /// `--disable-epsv`.
    ///
    /// False, the default, sends `EPSV` first and falls back to `PASV`
    /// when the server refuses it. True leaves `EPSV` out, which is what
    /// the flag asks for: an old server or a middlebox that mishandles
    /// `EPSV` costs one round trip on every transfer without it.
    ///
    /// **This never changes which host the data connection dials.** The
    /// address inside a `PASV` answer is still ignored, because a hostile
    /// server writes that address. See `zurl_ftp.Fetcher.dataTarget`.
    ftp_disable_epsv: bool = false,
    /// The `blksize` a TFTP read request asks for, or null for the
    /// default of 512. This is `--tftp-blksize`.
    ///
    /// RFC 2348 bounds the option at 8 and at 65464, and this build holds
    /// a lower ceiling of its own, because the read buffer is sized from
    /// it. A value outside the range is refused by name before any
    /// datagram goes out, and never clamped. See `zurl_tftp.packet`.
    ///
    /// A server answers with the size it accepts, which RFC 2348 holds at
    /// or below the one asked for. A larger answer is a fault.
    tftp_block_size: ?u16 = null,
    /// Whether a TFTP read request carries the option block. This is
    /// `--tftp-no-options`, which gives false.
    ///
    /// True, the default, sends `tsize`, `blksize`, and `timeout`, which
    /// is what curl sends. False writes the file name and the mode alone,
    /// for a server that answers an option block with an error.
    tftp_send_options: bool = true,
    /// The token an `Authorization: Bearer` header carries, or null. This
    /// is `--oauth2-bearer`.
    ///
    /// **It outranks `credentials` and answers no challenge.** A bearer
    /// token goes out on the first request, the way curl sends one, and a
    /// `401` that names Basic or Digest is reported rather than answered:
    /// the user named the credential to send, so zurl sends no other.
    ///
    /// A `-H Authorization` the caller wrote still outranks this, which is
    /// the order `zurl.authorize.apply` holds for every scheme.
    ///
    /// The token reaches a header line, so a CR or an LF in it is refused
    /// before the request goes out.
    bearer_token: ?[]const u8 = null,
    /// Which redirect statuses keep the method and the body. This covers
    /// `--post301`, `--post302`, `--post303`, and `--follow`.
    ///
    /// Reuses `zurl_http.engine.RedirectMethods` rather than a field of
    /// its own, for the reason `redirects` gives: one type, stated once.
    redirect_methods: zurl_http.engine.RedirectMethods = .{},
    /// Where a transfer resumes from, in bytes. Zero fetches the whole
    /// body. This is `-C`/`--continue-at`.
    ///
    /// **Each protocol asks for it its own way**, and the number is the
    /// one thing they share. HTTP sends a `Range` header, which
    /// `src/cli/run.zig` builds and puts in `headers`. FTP sends `REST`,
    /// and this field is how the offset reaches that command: an FTP
    /// transfer carries no header at all, so a `Range` header would say
    /// nothing to it.
    ///
    /// The two are not both read for one transfer. `src/cli/run.zig`
    /// builds the header for HTTP and fills this field for every
    /// protocol, and the protocol that runs reads whichever one it
    /// understands.
    resume_from: u64 = 0,
    /// The `-r`/`--range` value, exactly as the `Range` header writes it,
    /// or null when the flag was not given.
    ///
    /// Here for the reason `resume_from` is here: a protocol with no
    /// headers cannot read the header `src/cli/run.zig` builds. FTP reads
    /// this and answers the open-ended form with `REST`. See
    /// `zurl_ftp.Fetcher.restFromRange` for why the other forms are
    /// refused there rather than half honoured.
    ///
    /// `Args` refuses `-r` and `-C` together, the way curl does, so at
    /// most one of this and `resume_from` is set.
    range: ?[]const u8 = null,
    /// Whether a transfer must put TLS on the connection with a command
    /// before the handshake. This is `--ssl-reqd`.
    ///
    /// The command is the one the protocol names: `AUTH TLS` for FTP,
    /// `STLS` for POP3, and `STARTTLS` for IMAP and SMTP.
    ///
    /// **A server that refuses fails the transfer**, with exit 64, and
    /// zurl sends no credential over the connection. That is curl's own
    /// answer, measured. `--ssl`, which curl reads as "try, and carry on
    /// in the clear when the server says no", is not here: a flag whose
    /// answer to a refusal is to send the password anyway needs a user to
    /// have asked for exactly that, and zurl has no such user yet.
    ///
    /// An `ftps://`, `pop3s://`, `imaps://`, or `smtps://` url needs no
    /// flag. Each of those is implicit TLS on a port of its own, which is
    /// what curl does, and each hand shakes on connect.
    ftp_ssl_required: bool = false,
    /// The command `-X`/`--request` named, exactly as the user wrote it,
    /// or null.
    ///
    /// **HTTP reads `method` and a mail protocol reads this.** The two are
    /// filled from the same flag and they are not the same thing: an HTTP
    /// method is one of nine names, and a mail command is a whole command
    /// line such as `TOP 1 0` or `FETCH 1 BODY[]`. `src/cli/Args.zig`
    /// fills `method` when the value names an HTTP method, and fills this
    /// always.
    ///
    /// A value that names no HTTP method is refused at the parse, unless
    /// every url of the run uses a scheme that reads a command from here.
    /// So `-X FROBNICATE http://x` is exit 2 as it always was, and
    /// `-X FETCH imap://x` reaches the protocol package.
    ///
    /// The value is a user's own text. The gate that keeps a forged line
    /// ending out of it is the protocol package's own command writer, and
    /// every one of them shares `zurl_net.line.write`.
    custom_request: ?[]const u8 = null,
    /// The envelope sender an SMTP transfer names, or null.
    ///
    /// This is `--mail-from`, and it becomes the `MAIL FROM:<...>` of RFC
    /// 5321. Null sends `MAIL FROM:<>`, the null reverse path, which is
    /// what curl sends for a transfer that names none, measured.
    ///
    /// **A CR or an LF in it is refused before any command goes out.** It
    /// would otherwise end the `MAIL FROM` line and write a command of its
    /// own, and `RCPT TO:` is the command it would write. curl 8.21.0 does
    /// **not** refuse it: measured, `--mail-from $'a@b>\r\nRCPT TO:<evil@x'`
    /// puts a second recipient on the wire that the user never named. See
    /// `zurl_smtp.Fetcher.checkAddress`.
    mail_from: ?[]const u8 = null,
    /// The envelope recipients an SMTP transfer names.
    ///
    /// This is `--mail-rcpt`, which is repeatable, and each entry becomes
    /// one `RCPT TO:<...>`. An SMTP transfer with none is refused: a
    /// message with no recipient reaches nobody.
    ///
    /// **A CR or an LF in an entry is refused**, for the reason
    /// `mail_from` gives, and with the same measurement behind it.
    mail_rcpt: []const []const u8 = &.{},
    /// The SASL authorization identity a mail login carries, or null. This
    /// is `--sasl-authzid`.
    ///
    /// RFC 4616 section 2 makes a `PLAIN` message `authzid NUL authcid NUL
    /// passwd`, where the authzid names the identity to act **as** and the
    /// authcid names the identity to log in **with**. Null writes an empty
    /// authzid, which asks the server to act as the authcid itself, and is
    /// what almost every login wants. Measured against curl 8.21.0:
    /// `--sasl-authzid admin -u alice:s3cret` put
    /// `admin\x00alice\x00s3cret` on the wire, and the same command with
    /// no `--sasl-authzid` put `\x00alice\x00s3cret`.
    ///
    /// **A NUL in it forges a field**, so it is refused before any encode
    /// runs. See `zurl_net.sasl.Fields.check`.
    ///
    /// Only `PLAIN` carries one. A mechanism with no place for an authzid
    /// drops it, which is what curl does: measured, `--sasl-authzid admin`
    /// against a server offering `CRAM-MD5` sent the `CRAM-MD5` response
    /// with no authzid anywhere in it.
    sasl_authzid: ?[]const u8 = null,
    /// Whether a mail login puts its first SASL message on the command
    /// line that opens the exchange. This is `--sasl-ir`.
    ///
    /// It saves one round trip and changes no byte of the message.
    /// Measured against curl 8.21.0 on all three mail protocols: `AUTH
    /// PLAIN AGFsaWNlAHMzY3JldA==` with the flag, and `AUTH PLAIN`
    /// followed by the same base64 on its own line without it.
    ///
    /// **`CRAM-MD5` ignores it**, because its first message answers a
    /// challenge that has not arrived. A `LOGIN` sends only the user name
    /// early, which is what curl sends, measured.
    sasl_ir: bool = false,
    /// The value `--login-options` named, or null.
    ///
    /// curl writes it as `AUTH=<mechanism>`, and it names the one SASL
    /// mechanism a mail login may use. **A named mechanism outranks the
    /// preference order**, so a user who names one gets that mechanism or
    /// an error and never a different one. Measured against curl 8.21.0:
    /// `--login-options AUTH=PLAIN` against a server offering `PLAIN LOGIN
    /// CRAM-MD5` sent `AUTH PLAIN` where the same command with no option
    /// sent `AUTH CRAM-MD5`, and `--login-options AUTH=CRAM-MD5` against a
    /// server offering neither gave exit 67 with no `AUTH` on the wire.
    ///
    /// A value in any other form is refused. curl reads more forms than
    /// this one, and none of them names anything this build can do.
    login_options: ?[]const u8 = null,
    /// Whether each hop of a redirect chain carries a `Referer` naming the
    /// hop before it. This is the `;auto` suffix of `-e`/`--referer`.
    ///
    /// The `Referer` of the *first* request is an ordinary header in
    /// `headers`, which `src/cli/Args.zig` builds from the url part of
    /// `-e`. This field is the per-hop half alone. See
    /// `zurl_http.engine.Request.auto_referer`.
    auto_referer: bool = false,
    /// The login name an SSH transfer uses when the url and `-u` name
    /// none, and a netrc file holds no entry either.
    ///
    /// **SSH has no anonymous account**, so a transfer with no name is
    /// refused rather than run as somebody. curl uses the login name of
    /// the account it runs as, and the CLI reads that name from the
    /// environment and puts it here: this library reads no environment
    /// variable, the way it reads no netrc file. See
    /// `Options.netrc_text`, which is the same shape for the same reason.
    ssh_user: ?[]const u8 = null,
    /// The user's home directory, which the caller read.
    ///
    /// It is where `~/.ssh/known_hosts` and `~/.ssh/id_ed25519` are looked
    /// for. Null means neither is looked for at all, which leaves every
    /// host unknown and every key unfound.
    ssh_home: ?[]const u8 = null,
    /// `--knownhosts`: the file that says which host keys are trusted.
    ///
    /// Null uses `ssh_home` and `~/.ssh/known_hosts`. **A path that is
    /// named and does not open is a refusal**, and never a quiet fall
    /// back to the default file or to "no record".
    ssh_known_hosts: ?[]const u8 = null,
    /// `--hostpubmd5`: the MD5 of the server's host key, as 32 hexadecimal
    /// digits.
    ///
    /// A pin answers on its own and `known_hosts` is not read, which is
    /// what curl does, measured. **MD5 is not a hash to pin with**, and it
    /// is here because curl carries the flag.
    ssh_host_pub_md5: ?[]const u8 = null,
    /// `--hostpubsha256`: the SHA-256 of the server's host key, base64.
    ///
    /// This is the text `ssh-keygen -l` prints after `SHA256:`, with or
    /// without the padding. It is the one to use.
    ssh_host_pub_sha256: ?[]const u8 = null,
    /// `--mqtt-client-id`: the client identifier an MQTT connect names.
    ///
    /// Null draws one. curl draws one too and gives no way to set it:
    /// measured, every run wrote `curl` and eight random characters. A
    /// broker often keys an access rule on the identifier, so naming it
    /// matters, and zurl draws `zurl` and eight when nobody does.
    mqtt_client_id: ?[]const u8 = null,
    /// `--mqtt-messages`: how many messages an MQTT subscribe reads before
    /// it ends.
    ///
    /// **This is where zurl and curl differ, and the flag is what makes
    /// the difference sayable.** curl's subscribe never ends: measured,
    /// `curl --max-time 5 mqtt://host/topic` printed every message and
    /// exited 28. zurl buffers its answer rather than streams it, so a
    /// transfer with no end of its own would fill memory until a bound
    /// stopped it. One is the default, and a user who wants curl's shape
    /// asks for a large count and a `--max-time`.
    ///
    /// Read only by a protocol package that speaks MQTT.
    mqtt_messages: u32 = 1,
    /// `--rtsp-request`: the RTSP method a request line names.
    ///
    /// Null sends `OPTIONS`, which is curl's own default and the only
    /// request curl's command line can send at all: measured, it wrote
    /// `OPTIONS * RTSP/1.0` for every url and every flag, `-X DESCRIBE`
    /// included. `-X` fills `custom_request` and an RTSP transfer reads
    /// this field first and that one second, so both spellings work.
    ///
    /// A method this build does not send is refused by name inside the
    /// protocol package, before any dial.
    rtsp_request: ?[]const u8 = null,
    /// `--rtsp-session-id`: the `Session` header an RTSP request carries.
    ///
    /// One zurl run is one RTSP request, so the identifier a `SETUP` reply
    /// gave has to travel to the next run through this flag.
    ///
    /// The value is a user's own text, and it reaches a header line. The
    /// gate that keeps a forged line ending out of it is
    /// `zurl_net.line.write`, through the protocol package's own request
    /// writer.
    rtsp_session_id: ?[]const u8 = null,
    /// `--rtsp-stream-uri`: the uri an RTSP request line names.
    ///
    /// Null builds one out of the url, except for an `OPTIONS`, which
    /// names `*`. A `SETUP` names a track inside a stream and no url can
    /// say which one, so this flag is how a track is named.
    ///
    /// The value reaches the request line. See `rtsp_session_id` for the
    /// gate.
    rtsp_stream_uri: ?[]const u8 = null,
    /// `--rtsp-transport`: the `Transport` header an RTSP request carries.
    ///
    /// RFC 2326 section 12.39 makes the header required on a `SETUP`, so a
    /// `SETUP` without this flag is refused rather than sent: inventing a
    /// transport would name a port zurl never opens.
    ///
    /// The value reaches a header line. See `rtsp_session_id` for the
    /// gate.
    rtsp_transport: ?[]const u8 = null,
};

const testing = std.testing;

test "the default options match curl_transport's behaviour" {
    const o: Options = .{};
    try testing.expectEqual(@as(i64, 15_000), o.connect_timeout.duration.raw.toMilliseconds());
    try testing.expectEqual(std.Io.Clock.awake, o.connect_timeout.duration.clock);
    try testing.expectEqual(@as(u32, 300), o.low_speed_time_s);
    try testing.expectEqual(zurl_http.engine.Redirects{ .follow = 10 }, o.redirects);
    try testing.expectEqual(@as(u64, 0), o.max_bytes_per_second);
}

test "every option field is settable at run time" {
    // Every value below is a `var`, and `_ = &v;` takes its address so the
    // compiler cannot fold the read back into a comptime-known value (a
    // plain `const` literal stays comptime-known and would not catch a
    // `comptime` field). A comptime-only field fails here with "cannot
    // store runtime value in compile time variable".
    var method: std.http.Method = .POST;
    _ = &method;
    var headers = [_]std.http.Header{.{ .name = "X-Test", .value = "1" }};
    var redirects: zurl_http.engine.Redirects = .{ .follow = 3 };
    _ = &redirects;
    var fail_on_error: bool = true;
    _ = &fail_on_error;
    var connect_timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(5_000), .clock = .awake } };
    _ = &connect_timeout;
    var low_speed_limit: u64 = 2;
    _ = &low_speed_limit;
    var low_speed_time_s: u32 = 10;
    _ = &low_speed_time_s;
    var max_bytes_per_second: u64 = 1024;
    _ = &max_bytes_per_second;
    var max_size: u64 = 2048;
    _ = &max_size;
    var reporter_ctx: u8 = 0;
    var user: []const u8 = "alice";
    _ = &user;
    var password: []const u8 = "secret";
    _ = &password;
    var netrc_text: []const u8 = "machine example.com login alice password secret";
    _ = &netrc_text;
    var user_agent: []const u8 = "custom/1";
    _ = &user_agent;
    var cacert: []const u8 = "/tmp/ca.pem";
    _ = &cacert;

    var body_ctx: u8 = 0;

    const Callback = struct {
        fn report(ctx: *anyopaque, transferred: u64, total: u64) callconv(.c) void {
            _ = ctx;
            _ = transferred;
            _ = total;
        }

        fn readBody(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
            _ = ctx;
            _ = buffer;
            _ = len;
            return 0;
        }
    };

    const o: Options = .{
        .method = method,
        .body = .{
            .len = 3,
            .ctx = &body_ctx,
            .read = Callback.readBody,
            .rewind = null,
        },
        .headers = &headers,
        .redirects = redirects,
        .fail_on_error = fail_on_error,
        .connect_timeout = connect_timeout,
        .low_speed_limit = low_speed_limit,
        .low_speed_time_s = low_speed_time_s,
        .max_bytes_per_second = max_bytes_per_second,
        .max_size = max_size,
        .reporter = .{ .ctx = &reporter_ctx, .report = Callback.report },
        .credentials = .{ .user = user, .password = password },
        .netrc_text = netrc_text,
        .user_agent = user_agent,
        .ca = .{ .cacert = cacert },
    };

    try testing.expectEqual(std.http.Method.POST, o.method);
    try testing.expectEqual(@as(?u64, 3), o.body.?.len);
    try testing.expectEqual(@as(?*const fn (*anyopaque) callconv(.c) bool, null), o.body.?.rewind);
    try testing.expectEqual(@as(usize, 1), o.headers.len);
    try testing.expectEqual(zurl_http.engine.Redirects{ .follow = 3 }, o.redirects);
    try testing.expectEqual(true, o.fail_on_error);
    try testing.expectEqual(@as(i64, 5_000), o.connect_timeout.duration.raw.toMilliseconds());
    try testing.expectEqual(@as(u64, 2), o.low_speed_limit);
    try testing.expectEqual(@as(u32, 10), o.low_speed_time_s);
    try testing.expectEqual(@as(u64, 1024), o.max_bytes_per_second);
    try testing.expectEqual(@as(u64, 2048), o.max_size);
    try testing.expect(o.reporter != null);
    try testing.expectEqualStrings("alice", o.credentials.?.user);
    try testing.expectEqualStrings("secret", o.credentials.?.password);
    try testing.expectEqualStrings("machine example.com login alice password secret", o.netrc_text.?);
    try testing.expectEqualStrings("custom/1", o.user_agent);
    try testing.expectEqualStrings("/tmp/ca.pem", o.ca.cacert.?);
}

test "the reporter callback is a C-compatible function pointer" {
    const Recorder = struct {
        calls: u32 = 0,
        last_transferred: u64 = 0,
        last_total: u64 = 0,

        fn report(ctx: *anyopaque, transferred: u64, total: u64) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            self.last_transferred = transferred;
            self.last_total = total;
        }
    };

    var recorder: Recorder = .{};
    const o: Options = .{ .reporter = .{ .ctx = &recorder, .report = Recorder.report } };

    const reporter = o.reporter.?;
    reporter.report(reporter.ctx, 4, 7);

    try testing.expectEqual(@as(u32, 1), recorder.calls);
    try testing.expectEqual(@as(u64, 4), recorder.last_transferred);
    try testing.expectEqual(@as(u64, 7), recorder.last_total);
}

test "the default auth mode is the one that sends Basic before the server asks" {
    const o: Options = .{};
    try testing.expectEqual(AuthMode.basic, o.auth_mode);
    try testing.expect(o.auth_mode.sendsPreemptiveCredential());
}

test "--digest and --anyauth send no credential before the server asks" {
    // The whole point of both flags. A preemptive `Basic` would put the
    // password on the wire in reversible base64 before the server had
    // asked for anything.
    try testing.expect(!AuthMode.digest.sendsPreemptiveCredential());
    try testing.expect(!AuthMode.any.sendsPreemptiveCredential());
}

test "--digest answers a Digest challenge and no other" {
    // A server that offers `Basic` alone gets no answer under `--digest`.
    // Answering it would send the password the flag exists to keep off
    // the wire, which is the same rule `--proxy-digest` follows.
    try testing.expect(AuthMode.digest.answers(.digest));
    try testing.expect(!AuthMode.digest.answers(.basic));
    try testing.expect(!AuthMode.digest.answers(.bearer));

    // The other two answer whatever the server named.
    for ([_]zurl_core.auth.Scheme{ .basic, .bearer, .digest }) |scheme| {
        try testing.expect(AuthMode.basic.answers(scheme));
        try testing.expect(AuthMode.any.answers(scheme));
    }
}
