//! Owns the resources one caller's transfers share.
//!
//! A `Client` owns the allocator, the `Io`, the CA bundle, the HTTP
//! connection pool, and the scheme dispatch table. `perform` drives one
//! transfer at a time: a second call to `perform` closes whatever
//! `Exchange` the previous call left open, so a caller must finish
//! reading a `Response.body` before starting another transfer on the same
//! `Client`. `deinit` closes anything still open.
//!
//! The pool lives in the HTTP engine, `zurl_http.h1.Engine`, keyed by
//! origin. A second url on one origin therefore pays no dial and no TLS
//! handshake. A caller that reads a `Response.body` to its end lets that
//! transfer's connection go back to the pool; a caller that stops early
//! costs that one connection, and nothing else. See `h1.Exchange.reusable`
//! for the rule and `h1.pool_idle_max` for the bound.
//!
//! `Client` is not safe to share across concurrent transfers. That
//! matches how curl's easy handle works: one handle, one transfer at a
//! time.

const Client = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_tls = @import("zurl-tls");
const zurl_http = @import("zurl-http");
const Transfer = @import("Transfer.zig");
const Response = @import("Response.zig");
const protocol = @import("protocol.zig");
const body = @import("body.zig");
const authorize = @import("authorize.zig");
const proxy = @import("proxy.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// Scratch space for the built-in HTTP protocol's transfer framing. See
/// `engine.Exchange.bodyReader`: the buffer it takes must outlive every
/// read of the body it returns, so it cannot be a stack buffer inside
/// `performHttp`. Sized to match `h1.zig`'s own internal transfer buffer.
const body_buffer_len = 8192;

/// Scratch space for `body_stack`'s own top reader, the one
/// `body_stack.reader()` returns as `Response.body`. Load-bearing: `peek`,
/// `takeByte`, and similar calls that ask `Response.body` for contiguous
/// memory go through it. Plain streaming never touches it: `performHttp`
/// reads the raw body through `body_buffer` above, and none of `Throttle`,
/// `Stall`, or `Progress` copies anything through a buffer of its own, so
/// they need none. See `body.Stack.Buffers`.
const decorator_buffer_len = 64;

/// The field name and the punctuation that `writeRequestHead` puts around
/// an `Authorization` value on the wire. The engine writes the headers it
/// owns in lower case, and `splitHeaders` writes this one the same way.
const authorization_line_overhead = "authorization".len + ": ".len + "\r\n".len;

/// The longest `Authorization` header line zurl sends, the CRLF included.
///
/// **Not a number chosen here.** `zurl_http.h1.head_field_len_max` is the
/// longest header line this engine reads, and a line that reaches that
/// number is refused, so the longest line it accepts is one byte shorter.
/// zurl sends no header line that it would refuse to read, so the same
/// number bounds what goes out. curl keeps one buffer of that size,
/// `CURL_MAX_HTTP_HEADER`, for the same job.
///
/// This is the whole bound on a credential. `authorize.apply` sizes its
/// buffer from the credential it was given and caps nothing, so the only
/// credential zurl refuses is one that no `Authorization` header line
/// could carry. An earlier zurl capped a decoded user name and password
/// at 256 bytes, which refused a 1200-character cache token that curl
/// sends without trouble.
///
/// The engine keeps no bound of its own on a request head, only on a
/// response head, so this check is the one that fires. It reports
/// `error.CredentialTooLarge` with a message that names the credential
/// source, which a bound inside the engine could not do: the engine sees
/// a header line and not where the header came from.
const authorization_line_len_max = zurl_http.h1.head_field_len_max - 1;

comptime {
    // A field name and its punctuation must leave room for a value. This
    // holds for any sane `head_field_len_max`, and the build checks it
    // rather than trust that the next edit keeps it true.
    if (authorization_line_overhead >= authorization_line_len_max) @compileError(
        "Client.zig: `authorization_line_len_max` leaves no room for a credential",
    );
}

/// How much scratch `performHttp` gives `auth.selectChallenge` for the
/// challenge parameters it unescapes. Past the 1024 bytes of challenge
/// text that `h1.zig` keeps, so every challenge the engine reports fits.
const challenge_scratch_len = 2048;

/// How many random bytes back a fresh client nonce. Hex-encoded, this is
/// `cnonce_hex_len` characters: enough entropy for a value that only needs
/// to be unique per challenge, not secret.
const cnonce_raw_len = 16;
const cnonce_hex_len = cnonce_raw_len * 2;

/// How large a stored server nonce may be, for `nextNc`'s repeat check. A
/// nonce longer than this is never recognised as a repeat, so `nextNc`
/// always starts it at 1; that is a lost optimisation, not a correctness
/// problem.
const digest_nonce_buf_len = 256;

/// How large a request target may be, for the digest `uri` parameter. RFC
/// 9110 asks a recipient to accept at least 8000 bytes of request line, so
/// a target longer than this does not reach a conforming server anyway.
const request_target_len = 8192;

/// How long a redirect target handed over from one protocol to another may
/// be. `zurl_http.h1` bounds its own redirect targets at the same size, so
/// a target that reached this client always fits.
const handoff_url_len = 8192;

/// How many times one `perform` may move a transfer from one protocol
/// package to another.
///
/// One. The HTTP engine hands a hop over only when it cannot speak the
/// target's protocol, so the target is never http or https and the hop
/// never comes back to the engine that gave it up. A second handoff can
/// therefore only come from a protocol a caller registered, and the bound
/// says that out loud rather than trusting the built-in table to stay this
/// shape. It also keeps `handoff_storage` written at most once for each
/// `perform`, so the url a dispatch is reading cannot be overwritten under
/// it.
const max_protocol_handoffs: u8 = 1;

allocator: Allocator,
io: Io,
/// The built-in HTTP/1.1 engine. Its `ca_bundle` is the trust store
/// `ensureCaBundle` fills.
http: zurl_http.h1.Engine,
/// Schemes registered at run time with `registerProtocol`, checked
/// before `protocol.builtins`.
protocols: std.ArrayList(protocol.Protocol),
/// The same schemes, in the shape `zurl_core.url.parseWith` reads.
///
/// Dispatch and parsing are two halves of one registration, and this
/// field is the second half. `registerProtocol` fills both or neither.
/// See it for why one call has to do both.
schemes: zurl_core.url.Schemes,
/// The exchange the most recent `perform` opened, if it opened one and
/// has not yet been closed. `perform` closes this before it opens
/// another; `deinit` closes it if the caller never called `perform`
/// again.
current_exchange: ?*zurl_http.engine.Exchange,
body_buffer: [body_buffer_len]u8,
/// The rate limit, stall watchdog, and progress decorators the most
/// recent `performHttp` stacked onto the raw body. `Response.body` is
/// `body_stack.reader()`. Rebuilt in place by every `performHttp` call;
/// see `body.Stack.init` for why it cannot be a fresh value each time.
body_stack: body.Stack,
/// True only while `body_stack` holds a stack built for the `Response`
/// currently in play. `perform` clears this before every dispatch; only
/// `performHttp` sets it back to true, once it has actually rebuilt
/// `body_stack`. A registered protocol's own `perform` returns a
/// `Response` whose `body` is its own reader and never touches
/// `body_stack`, so this stays false for that response, and a fresh
/// `Client` that has never performed a transfer starts false too, before
/// `body_stack` has ever held anything but `undefined`.
body_stack_live: bool,
body_stack_buffer: [decorator_buffer_len]u8,
/// How many times `ensureCaBundle` has actually loaded the bundle. Zero
/// means not yet loaded. This is what makes the load lazy instead of once
/// per transfer, and it goes above one only when a later transfer names
/// different trust inputs. See `ca_loaded`.
ca_load_count: usize,
/// The digest of the `ca.Inputs` that `http.ca_bundle` was built from, or
/// null when it has never been built.
///
/// **The guard is the value and not a counter.** A counter said "loaded
/// already" for a second transfer whose `--cacert` named another file, so
/// that transfer verified against the bundle of the first one. A caller
/// that pinned a root got the public root set instead, which fails open.
/// `Multi` reaches this: many jobs share one `Client` when there are more
/// jobs than slots, and each job carries its own `Transfer.Options`.
///
/// **A digest, and not the slices.** The paths belong to the caller and
/// may be freed the moment `perform` returns, so a later comparison
/// against kept slices would read memory this client does not own. See
/// `inputsDigest`.
ca_loaded: ?[inputs_digest_len]u8,
/// Where the transfer that runs now looks for certificate authorities.
///
/// `ensureCaBundle` runs from the engine's `tls_setup` hook, which takes
/// no arguments of its own, so the inputs for the transfer in play wait
/// here. `perform` writes this before it dispatches. The default names
/// only the embedded bundle, which is what a `Client` that has never
/// performed a transfer would load.
ca_inputs: zurl_core.ca.Inputs,
/// Where `ensureCaBundle` reports a load that failed.
///
/// Reaches the hook the same way `ca_inputs` does. `perform` writes the
/// caller's pointer here and clears it again before it returns, so no
/// later call can write through a pointer whose transfer has ended.
ca_diagnostics: ?*Diagnostics,
/// Every certificate directory entry the load skipped, and why.
///
/// A `--capath` or `SSL_CERT_DIR` directory belongs to the machine, so an
/// unreadable or stale entry in it is ordinary. `zurl_tls.loader.loadDir`
/// skips such an entry and keeps the rest, and IronStyle says that
/// recovery is never silent. This is where the record waits until a
/// caller asks for it. `takeCaSkips` is the only reader.
///
/// A `Diagnostics` cannot hold this, because a `Diagnostics` is read on a
/// transfer that failed and a skipped entry does not fail the transfer.
ca_skips: zurl_tls.loader.Skips,
/// True once `takeCaSkips` has handed `ca_skips` out. The load runs once
/// for the life of a `Client`, so without this every url after the first
/// would report the same skips again.
ca_skips_taken: bool,
/// How many times `ensureProxyCaBundle` has loaded the proxy's own trust
/// store. Zero means not yet loaded, exactly as `ca_load_count` works for
/// the origin's store.
proxy_ca_load_count: usize,
/// The digest of the inputs `http.proxy_ca_bundle` was built from. The
/// sibling of `ca_loaded`, and it keeps the same rule for the same reason.
proxy_ca_loaded: ?[inputs_digest_len]u8,
/// Where the transfer that runs now looks for the certificate authorities
/// that verify an `https` proxy. This is `--proxy-cacert` and
/// `--proxy-capath`.
///
/// **A separate field from `ca_inputs`, and never the same one.** The two
/// name two different trust stores, and a transfer through an `https` proxy
/// to an `https` origin loads both. `perform` writes this before it
/// dispatches, the same way it writes `ca_inputs`.
proxy_ca_inputs: zurl_core.ca.Inputs,
/// The most recent digest server nonce this `Client` has answered, and how
/// many requests have reused it. See `nextNc`. Empty until the first
/// digest challenge.
digest_nonce_buf: [digest_nonce_buf_len]u8,
digest_nonce_len: usize,
digest_nc: u32,
/// The two halves of the caller's header list, as `splitHeaders` divides
/// it: the headers that may follow a redirect, and the secrets that must
/// stay inside the origin the url names.
///
/// Both belong to the `Client` rather than to a stack frame because the
/// engine writes them again on every redirect hop, long after
/// `performHttp` hands the lists over. They keep their capacity from one
/// transfer to the next.
header_storage: std.ArrayList(std.http.Header),
secret_storage: std.ArrayList(std.http.Header),
/// The redirect target the HTTP engine handed over, when it handed one
/// over. See `takeHandoff`.
handoff_storage: [handoff_url_len]u8,
/// How much of `handoff_storage` holds that target. Zero when the last
/// dispatch handed nothing over, which `perform` resets it to before every
/// dispatch.
handoff_len: usize,
/// The url of the hop that issued a `401` challenge, when that hop was a
/// redirect target and the retry went there.
///
/// A copy, and not the engine's own text. `engine.Head.effective_url` is
/// borrowed from the `Exchange`, and the retry closes that exchange before
/// it sends anything, so the text has to outlive the exchange that
/// reported it. It also becomes `Response.effective_url` for the retry,
/// which reports the hop the body came from. Its life is the same as
/// every other field of a `Response`: valid until the next `perform` on
/// this `Client`.
challenge_url_storage: [handoff_url_len]u8,
/// How much of `challenge_url_storage` holds that url. Zero when the last
/// transfer answered no challenge from a redirect target, which
/// `performHttp` resets it to on entry.
challenge_url_len: usize,

pub fn init(gpa: Allocator, io: Io) Client {
    return .{
        .allocator = gpa,
        .io = io,
        .http = .init(gpa, io, .{}),
        .protocols = .empty,
        .schemes = .empty,
        .current_exchange = null,
        .body_buffer = undefined,
        .body_stack = undefined,
        .body_stack_live = false,
        .body_stack_buffer = undefined,
        .ca_load_count = 0,
        .ca_loaded = null,
        .ca_inputs = .{},
        .ca_diagnostics = null,
        .ca_skips = .{},
        .ca_skips_taken = false,
        .proxy_ca_load_count = 0,
        .proxy_ca_loaded = null,
        .proxy_ca_inputs = .{},
        .digest_nonce_buf = undefined,
        .digest_nonce_len = 0,
        .digest_nc = 0,
        .header_storage = .empty,
        .secret_storage = .empty,
        .handoff_storage = undefined,
        .handoff_len = 0,
        .challenge_url_storage = undefined,
        .challenge_url_len = 0,
    };
}

/// Closes any exchange `perform` left open, then releases the connection
/// pool and every registered protocol's entry. Registering a protocol
/// does not transfer ownership of what `p.ptr` points to; a caller that
/// heap-allocated it must still free it itself.
pub fn deinit(c: *Client) void {
    if (c.current_exchange) |exchange| exchange.close();
    c.protocols.deinit(c.allocator);
    c.header_storage.deinit(c.allocator);
    c.secret_storage.deinit(c.allocator);
    c.http.deinit();
}

/// What `registerProtocol` can answer.
///
/// `TooManySchemes` says the url parser's own table is full. See
/// `zurl_core.url.Schemes` for the bound and for why it is fixed.
pub const RegisterError = Allocator.Error || zurl_core.url.Schemes.AddError;

/// Adds `p` to the schemes this client handles, ahead of the built-in
/// table. A scheme already registered is not replaced; both entries stay,
/// and `perform` uses whichever `protocol.find` reaches first, which is
/// the one registered first.
///
/// **This teaches the url parser the scheme as well as the dispatch
/// table.** Registration used to fill the dispatch table alone, and a url
/// for the new scheme then never reached dispatch: `zurl_core.url.parse`
/// refused a scheme it did not know that named no port, and refused an
/// empty host whatever port it named, so a caller had to write a port
/// into every url. One call fills both tables because two calls is a
/// state a caller can reach half way, and half way is exactly the bug
/// that was there. `p.default_port` is what the parser is told, so the
/// protocol's own answer to "what port" is the only answer.
///
/// **Fills both tables or neither.** The room in the dispatch table is
/// taken first, because that is the step that can run out of memory. Then
/// the parser's table takes the scheme, and only then does the dispatch
/// entry go in, into room already held. So a `TooManySchemes` leaves a
/// client that dispatches nothing new, and an `OutOfMemory` leaves a
/// client that parses nothing new.
pub fn registerProtocol(c: *Client, p: protocol.Protocol) RegisterError!void {
    try c.protocols.ensureUnusedCapacity(c.allocator, 1);
    try c.schemes.add(.{ .name = p.scheme, .default_port = p.default_port });
    c.protocols.appendAssumeCapacity(p);
}

/// Runs one transfer against `url_text` and returns its response.
///
/// `Response.body` stays valid until the next call to `perform` on this
/// `Client`, or until `deinit`, whichever comes first. Read it before
/// either happens. `Response.headers`, `Response.final_headers`, and
/// `Response.effective_url` follow the same rule, and every one of them
/// may borrow from `url_text` or from the engine, so copy what must live
/// longer.
pub fn perform(c: *Client, url_text: []const u8, options: Transfer.Options, d: ?*Diagnostics) Error!Response {
    if (c.current_exchange) |exchange| {
        exchange.close();
        c.current_exchange = null;
    }
    // Cleared before dispatch, not after: whichever protocol handles this
    // URL might not be `performHttp`, and a protocol that never rebuilds
    // `body_stack` must leave this false for the `Response` it returns.
    //
    // **So the stall guard, the rate limit, and the progress meter reach
    // no registered protocol, and they cannot.** `body.Stack` watches a
    // reader while a caller pulls from it. A registered protocol reads its
    // whole answer inside its own `perform` and hands back a reader over
    // memory, so by the time a stack could wrap it there is no wait left
    // to watch. The waits that matter are the dial and the reads inside
    // that call, and each protocol package bounds them there:
    // `zurl_net.bounded.setup` for the dial and the handshake,
    // `zurl_net.bounded.readToEnd` for the answer, and
    // `zurl_net.bounded.stallTimeout` for the number `--speed-time` gives
    // both. `zurl-tftp` keeps its own per-datagram wait for the same
    // reason.
    c.body_stack_live = false;

    // `parseWithDefault` and not `parse`: a scheme this client had
    // registered must read like a built-in one (see `registerProtocol`),
    // and `--proto-default` names the scheme a url with none is read with.
    const url = zurl_core.url.parseWithDefault(
        url_text,
        &c.schemes,
        options.default_protocol,
    ) catch |err|
        return Diagnostics.record(d, err, .{ .url = url_text });

    // The trust roots do not load here. The engine calls `ensureCaBundle`
    // through this hook at the first hop that speaks TLS, and never for a
    // hop that does not, so this transfer reads a certificate path only if
    // it needs one. See `ensureCaBundle`.
    //
    // The hook is set on every `perform`, not once at `init`, because
    // `init` returns the whole `Client` by value: the address a hook needs
    // does not exist until the caller has somewhere to keep that value.
    // Setting it here also keeps it right for a `Client` that moved
    // between two transfers.
    c.ca_inputs = options.ca;
    c.ca_diagnostics = d;
    c.http.tls_setup = .{ .ptr = c, .call = tlsSetup };
    // **And the proxy's own roots, through a second hook.** The engine calls
    // this one before a hop that puts TLS on the connection to an `https`
    // proxy, and it calls the hook above before a hop that speaks TLS to the
    // origin. Two hooks, two inputs, and two bundles, because
    // `--proxy-cacert` and `--cacert` name two different trust stores and a
    // transfer through a proxy has both peers in play.
    c.proxy_ca_inputs = options.proxy_ca;
    c.http.proxy_tls_setup = .{ .ptr = c, .call = proxyTlsSetup };
    // **And the same two inputs reach the connection pool, as one digest.**
    // A certificate is checked once, at the handshake, so a pooled
    // connection carries the roots of the transfer that opened it for the
    // rest of its life. The pool keys on this, so a transfer that named
    // other roots opens a connection of its own. See
    // `zurl_http.h1.Origin.trust`.
    c.http.trust_digest = trustDigest(options.ca, options.proxy_ca);
    // The caller owns `d`, and it outlives this call only by the caller's
    // rules. Nothing may write through the stored copy after this returns.
    defer c.ca_diagnostics = null;

    // **`--proto` is read here, before the dispatch table.** The set the
    // caller named says which protocols this transfer may speak at all,
    // and a url outside it never reaches a protocol that could open it.
    // The order matters: a url naming a protocol the user turned off must
    // report that it was turned off, and not that this build has no entry
    // for it.
    //
    // curl 8.21.0 answers the same shape with exit 1 and
    // `Protocol "http" is disabled`, which is `CURLE_UNSUPPORTED_PROTOCOL`,
    // the same code this name carries.
    if (!options.protocols.hasScheme(url.scheme))
        return Diagnostics.record(d, error.UnsupportedProtocol, .{ .url = url_text });

    // The url a dispatch runs, which is the caller's until a redirect
    // moves the transfer to another protocol package. See the handoff arm
    // below.
    var current_url = url;
    var current_text = url_text;
    var handoffs: u8 = 0;
    // What each dispatch is given. It is the caller's until a handoff,
    // which takes the credential out of it. See the handoff arm below.
    var current_options = options;

    var response = while (true) {
        const p = protocol.find(c.protocols.items, current_url.scheme) orelse
            return Diagnostics.record(d, error.UnsupportedProtocol, .{ .url = current_text });

        // **Before the dispatch, because the dispatch cannot say no.** A
        // protocol package reads the option fields it knows and drops the
        // rest with no sign. Every option a protocol names in
        // `Protocol.unread` is refused here instead. See
        // `zurl.protocol.Unread`.
        try refuseUnread(p, current_url, current_text, current_options, d);

        // Cleared before the dispatch, so a target read after it can only
        // be one this dispatch recorded.
        c.handoff_len = 0;
        break p.perform(c, current_url, current_options, d) catch |err| {
            // **A redirect that left the protocol the engine speaks.**
            //
            // `sendOnce` records the target when the HTTP engine reports
            // `error.RedirectToOtherProtocol`, which it does only when
            // `--proto-redir` named a protocol outside http and https.
            // The default set names none, so a caller that asked for
            // nothing never reaches this arm and a redirect into `file`
            // is still refused inside the engine.
            //
            // `--proto` is not asked again here. `sendOnce` hands the
            // engine both lists already, as one intersection, so a target
            // that reached this arm passed `--proto` and `--proto-redir`
            // together.
            const target = c.takeHandoff() orelse return err;
            if (handoffs == max_protocol_handoffs)
                return Diagnostics.record(d, error.TooManyRedirects, .{ .url = target });
            handoffs += 1;

            current_text = target;
            // The parse error goes through as it came. A target naming a
            // scheme this build does not speak is
            // `error.UnsupportedProtocol`, exit 1, and only a target
            // nobody can read is `error.InvalidUrl`, exit 3. Folding the
            // first into the second sent a reader to look at a url the
            // server wrote and that was never wrong.
            current_url = zurl_core.url.parseWith(target, &c.schemes) catch |target_err|
                return Diagnostics.record(d, target_err, .{ .url = target });

            // **The credential does not cross a handoff.** A handoff
            // happens only when a redirect changed the protocol, and a
            // changed protocol is another origin whatever the host says.
            // Without this, `-u alice:secret` on an `https://` url that a
            // server redirects to `ftp://elsewhere/` would send that
            // password to the ftp peer. `zurl_http.engine` already
            // withholds the same secret from an HTTP hop that crossed an
            // origin; this is the same rule for the hop that left HTTP
            // altogether.
            //
            // Measured against curl 8.21.0: `curl -u alice:s3cret -L`
            // through a `302` into an `ftp://` url logs in as `anonymous`,
            // so curl withholds it too.
            //
            // `--location-trusted` is the flag that keeps it, exactly as
            // it does for an `Authorization` header.
            //
            // **`netrc_text` stays, and that is curl parity and not a
            // safety property.** curl reads its netrc after a redirect
            // too, measured, so a transfer that kept it behaves the way a
            // curl user expects.
            //
            // The reason it is not a safety property: a netrc entry is
            // looked up by the host of the url in hand, but
            // `zurl_core.netrc.lookup` falls back to a `default` entry for
            // **any** host. So a file holding `default login u password p`
            // does reach a host the file never names, including one a
            // redirect chose. `ftp` and `ftps` are in
            // `zurl_core.redirect.redirect_default`, so no opt-in flag is
            // needed to get there.
            //
            // This comment once claimed the opposite, as the reason for
            // the decision. `lib/zurl-ws/Fetcher.zig` clears `netrc_text`
            // on its own hop and is stricter than curl there. The two
            // differ on purpose: a WebSocket hop has no
            // `--location-trusted` plumbed into it at all, so there is no
            // way to opt back in, and the strict answer is the only safe
            // one available to it.
            if (!options.location_trusted and current_options.credentials != null) {
                current_options.credentials = null;
                if (d) |dg| {
                    if (dg.message == null) dg.message = credential_withheld_message;
                }
            }
            continue;
        };
    };

    // A transfer that stayed on the url it was given ends on that url. The
    // protocol reports no text for it: `performHttp` is handed a parsed
    // `zurl_core.Url` and never sees the text behind it, and a registered
    // protocol reports one only when it moved somewhere else. So the
    // answer is filled in here, where the text is.
    //
    // The text is the caller's, or this client's own handoff storage, so
    // `Response.effective_url` lives no longer than the caller keeps the
    // one and no longer than the next `perform` for the other.
    // `Response.effective_url` says so.
    if (response.effective_url.len == 0) response.effective_url = current_text;

    if (options.fail_on_error and response.status >= 400) {
        return Diagnostics.record(d, error.HttpReturnedError, .{ .url = current_text, .status = response.status });
    }

    return response;
}

/// The redirect target the dispatch that just failed handed over, or null
/// when it handed over none.
///
/// The text lives in this client until the next `perform`, which is the
/// same life `Response.effective_url` has, because it becomes that value
/// for a transfer that made the hop.
fn takeHandoff(c: *Client) ?[]const u8 {
    if (c.handoff_len == 0) return null;
    return c.handoff_storage[0..c.handoff_len];
}

/// Copies `target` into `handoff_storage`, so `perform` can dispatch it
/// after the engine that reported it has let go.
///
/// A target longer than the storage records nothing. The transfer then
/// fails with the fault the engine already mapped, which is
/// `error.UnsupportedProtocol` for the target: the same answer that
/// target had before this path existed. `zurl_http.h1` bounds its own
/// redirect targets at `handoff_url_len`, so no target it reports can be
/// this long, and the branch is a bound and not a recovery.
fn recordHandoff(c: *Client, target: []const u8) void {
    if (target.len > c.handoff_storage.len) return;
    @memcpy(c.handoff_storage[0..target.len], target);
    c.handoff_len = target.len;
}

/// Copies the url of the hop that issued a `401` into
/// `challenge_url_storage`, so the retry can be sent there after the
/// exchange that reported it has closed.
///
/// Answers false for a url longer than the storage, and the caller then
/// answers the `401` as an ordinary response rather than retry the wrong
/// url. `zurl_http.h1` bounds its own redirect targets at
/// `handoff_url_len`, so no hop it reports can be this long, and the
/// branch is a bound and not a recovery.
fn recordChallengeUrl(c: *Client, text: []const u8) bool {
    if (text.len == 0 or text.len > c.challenge_url_storage.len) return false;
    @memcpy(c.challenge_url_storage[0..text.len], text);
    c.challenge_url_len = text.len;
    return true;
}

/// The url of the hop that answered the most recent transfer's `401`, or
/// null when no such retry was made. See `recordChallengeUrl`.
fn challengeUrl(c: *const Client) ?[]const u8 {
    if (c.challenge_url_len == 0) return null;
    return c.challenge_url_storage[0..c.challenge_url_len];
}

/// Appends as much of `text` as fits past `at.*` in `out`, and advances
/// `at.*` by however much that was. Never writes past `out.len`: a `text`
/// that does not fully fit is truncated, not refused, because this backs a
/// diagnostic message, not a value anything parses back.
fn boundedCopy(out: []u8, at: *usize, text: []const u8) void {
    const n = @min(out.len - at.*, text.len);
    @memcpy(out[at.*..][0..n], text[0..n]);
    at.* += n;
}

/// The engine's view of `ensureCaBundle`. `perform` puts this in
/// `http.tls_setup`, and the engine calls it at each hop that speaks TLS.
///
/// The inputs and the diagnostics come from `ca_inputs` and
/// `ca_diagnostics`, which `perform` sets for the transfer that runs now.
/// The hook takes no arguments of its own, so those two fields are the
/// only channel.
///
/// The hook reports the four faults the engine names, where
/// `ensureCaBundle` speaks the whole `zurl_core.Error` set. An allocation
/// failure keeps its own name, because a caller that ran out of memory
/// must not read that the handshake failed. `CaCertBadFile` and
/// `PeerFailedVerification` also keep their own names, so the exit code
/// tells a bad certificate file apart from a bad certificate directory,
/// the way curl's own 77 and 60 do. Every other fault means the trust
/// roots are not ready in some way that engine names, which is what
/// `SslConnectError` says, and `ensureCaBundle` has already put the real
/// name in `d`.
fn tlsSetup(ptr: *anyopaque) zurl_http.engine.TlsSetupError!void {
    const c: *Client = @ptrCast(@alignCast(ptr));
    c.ensureCaBundle(c.ca_inputs, c.ca_diagnostics) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.CaCertBadFile => return error.CaCertBadFile,
        error.PeerFailedVerification => return error.PeerFailedVerification,
        else => return error.SslConnectError,
    };
}

/// The engine's view of `ensureProxyCaBundle`. `perform` puts this in
/// `http.proxy_tls_setup`, and the engine calls it before a hop that puts
/// TLS on the connection to an `https` proxy.
///
/// **The mirror of `tlsSetup`, and never a second call of it.** This one
/// reads `proxy_ca_inputs` and fills `http.proxy_ca_bundle`. That one reads
/// `ca_inputs` and fills `http.ca_bundle`. A build with one hook would
/// verify the proxy against the origin's roots, or the origin against the
/// proxy's, at whichever hop loaded first.
fn proxyTlsSetup(ptr: *anyopaque) zurl_http.engine.TlsSetupError!void {
    const c: *Client = @ptrCast(@alignCast(ptr));
    c.ensureProxyCaBundle(c.proxy_ca_inputs, c.ca_diagnostics) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.CaCertBadFile => return error.CaCertBadFile,
        error.PeerFailedVerification => return error.PeerFailedVerification,
        else => return error.SslConnectError,
    };
}

/// The trust store, and the way to fill it, for a protocol package that
/// opens a TLS session of its own.
///
/// **This is what keeps one trust store in a program that speaks more than
/// one encrypted protocol.** The built-in HTTP engine reads `http.ca_bundle`
/// through `http.tls_setup`. A registered protocol such as `zurl-gopher`
/// cannot reach either field: it must not import `zurl`, so it has no name
/// for `zurl_http.h1.Engine` and none for `engine.TlsSetup`. Without this
/// function such a package would have to load roots of its own, and a
/// program would then hold two trust stores that a `--cacert` could move
/// apart.
///
/// The fields are exactly what `zurl_net.Connection.Tls` needs for a
/// `.bundle` trust check, plus the hook that fills the bundle. A caller
/// calls `load` before it opens a session and then reads `lock` and
/// `bundle`, which is the order `zurl_http.h1.openOnce` uses.
///
/// **`load` is lazy and one-time**, exactly as it is for HTTP: the roots
/// load at the first session that needs them and never for a transfer that
/// speaks no TLS.
///
/// The pointers name fields of this `Client`, so they live as long as it
/// does and no longer. The reported faults are the whole `zurl_core.Error`
/// set, because a protocol package maps its own faults and needs no
/// narrowing here.
pub const TlsMaterials = struct {
    lock: *Io.RwLock,
    bundle: *std.crypto.Certificate.Bundle,
    /// The `Client` that `load` reads. Passed back to it.
    ptr: *anyopaque,
    /// Fills `bundle` from the sources the transfer in play named.
    load: *const fn (ptr: *anyopaque) Error!void,
};

/// The trust store this `Client` verifies with, for a registered protocol
/// that speaks TLS. See `TlsMaterials`.
///
/// Call it inside a dispatch, where `perform` has already written
/// `ca_inputs` and `ca_diagnostics` for the transfer that runs now. Called
/// outside one, `load` would read the inputs of no transfer at all.
pub fn tlsMaterials(c: *Client) TlsMaterials {
    return .{
        .lock = &c.http.ca_bundle_lock,
        .bundle = &c.http.ca_bundle,
        .ptr = c,
        .load = loadTrustRoots,
    };
}

/// `TlsMaterials.load`. The same call `tlsSetup` makes for the HTTP
/// engine, with no narrowing of the fault set.
fn loadTrustRoots(ptr: *anyopaque) Error!void {
    const c: *Client = @ptrCast(@alignCast(ptr));
    return c.ensureCaBundle(c.ca_inputs, c.ca_diagnostics);
}

/// Loads the trust roots `inputs` names into `http.ca_bundle`, the first
/// time a transfer on this `Client` speaks TLS.
///
/// **Nothing else fills that bundle.** The engine loads no certificate of
/// its own: it borrows `http.ca_bundle` for the length of each handshake
/// and never scans anything into it. So without this function every
/// `https://` transfer runs with zero trust roots and fails verification,
/// every time. The sources come from flags and environment variables that
/// only this package reads, which is why the work is here and the moment
/// is the engine's.
///
/// Loads only when a hop is about to speak TLS. The engine decides that
/// moment and calls `tlsSetup` there, because the engine is the only part
/// that knows the scheme of the hop it opens. A load in `perform` instead
/// looked at the scheme the caller named, and that scheme is not the
/// scheme of every hop: a redirect from `http` to `https` needs the roots
/// that `http` alone does not. A load in `perform` also failed a plain
/// `http` transfer for a certificate path it never read, and
/// `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, and `SSL_CERT_DIR` come from the
/// environment, so one stale value in a shell profile stopped every
/// transfer. curl exits 7 there, for the connect that failed, and this
/// now does the same.
///
/// A lazy load stays ready for every later transfer, the same as an eager
/// one: the bundle sits on the `Client`, and `ca_load_count` keeps the
/// work to one time either way.
///
/// Loads one source at a time, although `zurl_tls.loader.load` takes the
/// whole list. Every source adds to the same bundle, so the result is the
/// same, and a failure then names the source that failed. The caller has
/// up to five paths in play, from two flags and three environment
/// variables, and `FileNotFound` on its own does not say which one is bad.
fn ensureCaBundle(c: *Client, inputs: zurl_core.ca.Inputs, d: ?*Diagnostics) Error!void {
    return c.loadBundle(&c.http.ca_bundle, &c.ca_load_count, &c.ca_loaded, inputs, d);
}

/// Loads the roots that verify an `https` proxy into
/// `http.proxy_ca_bundle`, the first time a transfer on this `Client` opens
/// such a hop.
///
/// **A separate load into a separate bundle.** It runs from
/// `proxy_tls_setup`, which the engine calls before a hop that puts TLS on
/// the connection to a proxy, and never before a hop to the origin. So a
/// transfer that names no `https` proxy reads no `--proxy-cacert` path at
/// all, exactly as a transfer that stays on `http` reads no `--cacert` one.
///
/// The two loads share `ca_skips`, which records the directory each skipped
/// entry came from, so a user reading that line can tell which store the
/// entry belonged to.
fn ensureProxyCaBundle(c: *Client, inputs: zurl_core.ca.Inputs, d: ?*Diagnostics) Error!void {
    return c.loadBundle(
        &c.http.proxy_ca_bundle,
        &c.proxy_ca_load_count,
        &c.proxy_ca_loaded,
        inputs,
        d,
    );
}

/// Loads `inputs` into `bundle` and records them in `loaded`.
///
/// The body of `ensureCaBundle` and `ensureProxyCaBundle` alike. One
/// function, so the fault map, the reuse rule, and the per-source
/// reporting cannot drift between the origin's store and the proxy's.
///
/// **The reuse rule reads the inputs and not a counter.** A transfer whose
/// trust inputs match the ones the bundle already holds reuses it, which is
/// what keeps the work to one time for a caller that names one `--cacert`
/// for every url. A transfer that names different ones gets its own load,
/// into a bundle emptied first: keeping the old roots beside the new ones
/// would verify against roots the caller replaced, which is the failure
/// that opens.
fn loadBundle(
    c: *Client,
    bundle: *std.crypto.Certificate.Bundle,
    load_count: *usize,
    loaded: *?[inputs_digest_len]u8,
    inputs: zurl_core.ca.Inputs,
    d: ?*Diagnostics,
) Error!void {
    const digest = inputsDigest(inputs);
    if (loaded.*) |previous| {
        if (std.mem.eql(u8, &previous, &digest)) return;
        // The roots in hand answer for another transfer's flags. An
        // explicit source replaces the built-in bundle rather than add to
        // it, so the old roots have to go with it. See `zurl_core.ca`.
        bundle.deinit(c.allocator);
        bundle.* = .empty;
        loaded.* = null;
        c.ca_skips = .{};
        c.ca_skips_taken = false;
    }

    var sources_buf: [zurl_core.ca.max_sources]zurl_core.ca.Source = undefined;
    const sources = zurl_core.ca.resolve(inputs, &sources_buf);

    const now = Io.Clock.real.now(c.io);
    for (sources) |source| {
        const one = [_]zurl_core.ca.Source{source};
        zurl_tls.loader.load(bundle, c.allocator, c.io, now, &one, &c.ca_skips) catch |err| {
            // `zurl_core.Error` has a real `OutOfMemory` member, and
            // folding it into `SslConnectError` would tell the caller the
            // handshake failed when the true cause was an allocation
            // failure. Report it unchanged.
            if (err == error.OutOfMemory) return Diagnostics.record(d, error.OutOfMemory, .{});

            // `source` names which kind of load failed, and curl gives a
            // file and a directory two different codes: 77 for a
            // certificate file it could not read (`--cacert`,
            // `CURL_CA_BUNDLE`, `SSL_CERT_FILE`), 60 for a certificate
            // directory it could not scan (`--capath`, `SSL_CERT_DIR`).
            // The native store and the embedded bundle name neither a
            // file nor a directory the caller chose, so a failure there
            // keeps the closest fault this engine has a name for: the
            // handshake failure that an empty bundle would cause anyway.
            const load_err: Error = switch (source) {
                .file => error.CaCertBadFile,
                .dir => error.PeerFailedVerification,
                .native, .embedded => error.SslConnectError,
            };
            return Diagnostics.record(d, load_err, .{
                .message = c.caFailureMessage(d, source, err),
            });
        };
    }
    loaded.* = digest;
    load_count.* += 1;
}

/// How many bytes `inputsDigest` returns.
const inputs_digest_len = std.crypto.hash.sha2.Sha256.digest_length;

/// The digest of one set of trust inputs.
///
/// **Every field is walked at compile time**, so a field added to
/// `zurl_core.ca.Inputs` and forgotten here cannot change without a
/// reload. That is the shape this fix is about: a guard that covers one
/// input and not its siblings.
///
/// Each text is written with a tag and a length before it, so `ab` and
/// null cannot digest the same as `a` and `b`. `zurl_http.h1` keys its
/// connection pool the same way, for the same reason.
fn inputsDigest(in: zurl_core.ca.Inputs) [inputs_digest_len]u8 {
    var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
    inline for (@typeInfo(zurl_core.ca.Inputs).@"struct".fields) |field| {
        const value = @field(in, field.name);
        switch (@typeInfo(field.type)) {
            .bool => hash.update(&[_]u8{ 2, @intFromBool(value) }),
            else => {
                if (value) |text| {
                    var length: [8]u8 = undefined;
                    std.mem.writeInt(u64, &length, text.len, .little);
                    hash.update(&[_]u8{1});
                    hash.update(&length);
                    hash.update(text);
                } else {
                    hash.update(&[_]u8{0});
                }
            },
        }
    }
    return hash.finalResult();
}

/// The one digest that stands for every trust root a transfer may use.
///
/// **Both stores, in one value.** `--cacert` and `--capath` name the roots
/// that verify an origin, and `--proxy-cacert` and `--proxy-capath` name
/// the roots that verify an `https` proxy. A connection through a tunnel
/// was checked against both, so a key that held only one of them would let
/// a transfer that named other proxy roots take that tunnel.
///
/// The two digests are joined in a fixed order, so the pair can be read
/// only one way and two different pairs cannot digest the same.
fn trustDigest(
    ca: zurl_core.ca.Inputs,
    proxy_ca: zurl_core.ca.Inputs,
) [inputs_digest_len]u8 {
    var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
    hash.update(&inputsDigest(ca));
    hash.update(&inputsDigest(proxy_ca));
    return hash.finalResult();
}

/// Sends every HTTP connection this client opens through `pool`, which
/// other clients use too.
///
/// **This is what lets several transfers ride one HTTP/2 connection.** A
/// `Client` cannot run two transfers at once, so a caller that wants two
/// at once holds two clients, and two clients used to mean two pools and
/// two handshakes to one host. One pool between them means one connection:
/// an HTTP/2 peer carries a stream for each client, and the second client
/// waits for the first client's handshake rather than start one of its own.
///
/// Call it once, before the first `perform`, and keep the pool alive until
/// every client that joined it has been deinitialised. The caller makes the
/// pool with `zurl.createConnectionPool` and frees it with
/// `zurl.destroyConnectionPool`.
///
/// **The clients that share a pool need not be configured alike.** The pool
/// key carries the trust roots, the TLS bounds, the proxy and its
/// credential, and the ALPN offer, so a connection one client opened can
/// only answer a request that named all of the same things. What a caller
/// must still promise is that `io` is the same for every one of them,
/// because the pool locks and waits on the pool's own.
pub fn shareConnections(c: *Client, pool: *zurl_http.h1.SharedPool) error{PoolInUse}!void {
    return c.http.joinSharedPool(pool);
}

/// Returns the one-line record of the certificate directory entries this
/// client skipped, or null when it skipped none.
///
/// Hands the text out once. The trust roots load one time for the life of
/// a `Client`, so a caller that asks after every url would otherwise print
/// the same line for every url.
///
/// The text points into the `Client`'s own storage, so it stays good for
/// as long as the `Client` does.
pub fn takeCaSkips(c: *Client) ?[]const u8 {
    if (c.ca_skips_taken) return null;
    if (!c.ca_skips.any()) return null;
    c.ca_skips_taken = true;
    return c.ca_skips.text();
}

/// Builds the sentence that names the certificate source which did not
/// load, and returns it.
///
/// The sentence names the path. `--cacert`, `--capath`, `CURL_CA_BUNDLE`,
/// `SSL_CERT_FILE`, and `SSL_CERT_DIR` all end at the same loader, so a
/// bare `FileNotFound` left a user with five candidates and no way to tell
/// which one was wrong.
///
/// The text goes into `Diagnostics.message_storage`, for the reason
/// `Diagnostics` keeps its own url storage: one buffer per `Client` is one
/// buffer for every transfer that client runs, and a second transfer
/// overwrote what the first had recorded. A message longer than the
/// storage loses its tail.
///
/// Returns an empty string when there is no `Diagnostics`. Nothing reads
/// the result then: `Diagnostics.record` drops every detail it is given
/// once its pointer is null.
///
/// A `.dir` source that failed carries the skip record with it. The one
/// way a directory fails now is `NoUsableCertificateFile`, and the reason
/// each entry was skipped is exactly what a user needs to fix it. The
/// bound on `message_storage` still holds: `boundedCopy` stops at the end
/// of the buffer.
fn caFailureMessage(c: *Client, d: ?*Diagnostics, source: zurl_core.ca.Source, err: anyerror) []const u8 {
    const target = d orelse return "";
    const out: []u8 = &target.message_storage;
    var at: usize = 0;
    switch (source) {
        .file => |path| {
            boundedCopy(out, &at, "zurl did not read the certificate file ");
            boundedCopy(out, &at, path);
        },
        .dir => |path| {
            boundedCopy(out, &at, "zurl did not read the certificate directory ");
            boundedCopy(out, &at, path);
        },
        .native => boundedCopy(out, &at, "zurl did not read the trust store of the operating system"),
        .embedded => boundedCopy(out, &at, "zurl did not read the built-in trust store"),
    }
    boundedCopy(out, &at, ": ");
    boundedCopy(out, &at, @errorName(err));
    if (source == .dir and c.ca_skips.any()) {
        boundedCopy(out, &at, ", skipped ");
        boundedCopy(out, &at, c.ca_skips.text());
        // Taken here as well, so the same skips do not reach the user a
        // second time through `takeCaSkips`.
        c.ca_skips_taken = true;
    }
    return out[0..at];
}

/// Set on `Diagnostics.message` when a build with no concurrency cannot
/// enforce `options.connect_timeout`. See `performHttp`.
const connect_timeout_degraded_message = "This build has no concurrency. The connect timeout was not enforced.";

/// Maps an `authorize.ApplyError` onto the zurl error taxonomy.
///
/// `InvalidEscape` means the url's userinfo holds an escape that is not an
/// escape, so the url itself is what is wrong.
///
/// `NoSpaceLeft` means a credential did not fit the buffer that was
/// measured for it. `authorize.apply` measures every buffer from the value
/// that goes in it, so no ordinary credential reaches this, however long
/// it is. It stays mapped, because an error set is a promise the compiler
/// checks, and `CredentialTooLarge` is the honest name for it. This
/// mapping used to be `error.InvalidUrl`, which told a user with a
/// 1200-character netrc token that a well-formed url was malformed.
///
/// `IncompleteChallenge`, `UnsupportedAlgorithm`, and `UnsupportedQop`
/// mean the server's `WWW-Authenticate` challenge asked for something zurl
/// cannot answer, so zurl cannot authenticate; that is the same outward
/// result as a server that refuses the login.
fn mapAuthorizeError(err: authorize.ApplyError) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidEscape => error.InvalidUrl,
        error.NoSpaceLeft => error.CredentialTooLarge,
        error.IncompleteChallenge,
        error.UnsupportedAlgorithm,
        error.UnsupportedQop,
        // A credential or a challenge parameter holds a byte that no
        // header value can carry, so zurl cannot build the credential the
        // server asked for. That is a login it cannot complete.
        error.InvalidQuotedValue,
        => error.LoginDenied,
    };
}

/// Maps a fault building the proxy credential onto the zurl taxonomy.
///
/// A bad escape in a proxy url's userinfo is `InvalidUrl`, which is what a
/// bad escape in the origin url's userinfo already reports. The
/// `Diagnostics.message` beside it names the fault, so a user is not sent to
/// look at the url they typed.
fn mapProxyError(err: proxy.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidEscape => error.InvalidUrl,
        error.NoSpaceLeft => error.CredentialTooLarge,
    };
}

/// Set on `Diagnostics.message` when a `401` carries a `WWW-Authenticate`
/// value that `zurl_core.auth` cannot read. The transfer keeps the `401`,
/// because zurl has nothing to answer it with. See `performHttp`.
const challenge_unreadable_message = "The server's WWW-Authenticate challenge is malformed.";

/// Set on `Diagnostics.message` when a `401` carries a `WWW-Authenticate`
/// value too large for the engine to keep. See `performHttp`.
const challenge_oversize_message = "The server's WWW-Authenticate challenge is too long to read.";

/// Set on `Diagnostics.message` when a `401` arrives on a request whose
/// body cannot be sent again. See `performHttp`.
const challenge_unanswerable_message =
    "The server asked for credentials, and a request body read from a pipe cannot be sent again.";

/// Set on `Diagnostics.message` when a `401` names a scheme that
/// `Transfer.Options.auth_mode` does not permit. Only `--digest` narrows
/// the set, so this says the server offered something other than Digest.
/// See `performHttp`.
const challenge_scheme_refused_message =
    "The server offered no Digest challenge, and --digest sends the password with nothing else.";

/// Set on `Diagnostics.message` when a `401` came from a hop the engine
/// redirected to and the secrets were not trusted to follow. The challenge
/// goes unanswered, because the credential may not reach the hop that asked
/// for it. See `performHttp`.
const challenge_redirect_untrusted_message =
    "A redirect target asked for credentials, and a credential does not follow a redirect without --location-trusted.";

/// Set on `Diagnostics.message` when a `401` came from a redirect target
/// whose url text this client cannot read back. The challenge goes
/// unanswered rather than to the url the caller named. See `performHttp`.
const challenge_hop_unreadable_message =
    "A redirect target asked for credentials, and its url could not be read back to answer it.";

/// Set on `Diagnostics.message` when a url's request target is longer than
/// `request_target_len`. See `requestTarget`.
const request_target_oversize_message = "The request target is too long to sign.";

/// Whether the `Authorization` header line for `value` is longer than the
/// engine can carry. See `authorization_line_len_max`.
fn authorizationOversize(value: []const u8) bool {
    return authorization_line_overhead + value.len > authorization_line_len_max;
}

/// Builds the sentence for a credential too long to send, and returns it.
///
/// **This never names the credential.** It names the source that holds it,
/// how long the header line would be, and the bound. A diagnostic is
/// printed, redirected into a log, and pasted into a bug report, so a
/// credential in one is a credential given away. `Diagnostics` masks a url
/// through `redact` for the same reason.
///
/// A user needs the source above all else. `-u`, the userinfo of the url,
/// and a netrc file are three different places, and a message that names
/// none of them leaves three candidates to check.
///
/// Writes into `Diagnostics.message_storage`, the way `caFailureMessage`
/// does, so a second transfer cannot overwrite what this one recorded.
/// Returns an empty string when there is no `Diagnostics`, because nothing
/// reads the result then.
fn credentialOversizeMessage(d: ?*Diagnostics, source: authorize.Source, value_len: usize) []const u8 {
    const target = d orelse return "";
    const out: []u8 = &target.message_storage;
    var at: usize = 0;
    boundedCopy(out, &at, "The credential from ");
    boundedCopy(out, &at, source.describe());
    boundedCopy(out, &at, " is too long to send. Its Authorization header line is ");
    boundedNumber(out, &at, authorization_line_overhead + value_len);
    boundedCopy(out, &at, " bytes, and zurl sends at most ");
    boundedNumber(out, &at, authorization_line_len_max);
    boundedCopy(out, &at, " bytes on one header line. The credential is not shown here.");
    return out[0..at];
}

/// Appends the decimal form of `n` past `at.*` in `out`. Truncates the
/// same way `boundedCopy` does, and for the same reason.
fn boundedNumber(out: []u8, at: *usize, n: usize) void {
    // A `usize` is at most 20 decimal digits, so this buffer always
    // holds one and the print cannot fail.
    var digits: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{n}) catch unreachable;
    boundedCopy(out, at, text);
}

/// Set on `Diagnostics.message` when the caller writes `Proxy-Authorization`.
/// The transfer sends nothing at all.
const proxy_authorization_refused_message =
    "zurl sends no Proxy-Authorization header. That header authenticates to a proxy, " ++
    "and zurl connects to no proxy, so it would only hand the secret to the origin server.";

/// The reason a framing header is refused. Each message in
/// `refused_header_messages` puts the name the caller wrote in front of
/// this text.
const framing_header_reason =
    " header itself. A copy from the caller goes out beside zurl's own, and a second " ++
    "Host, Content-Length, Transfer-Encoding, Connection, or Expect header lets a peer " ++
    "read one request as two.";

/// Set on `Diagnostics.message` when a refused name is not one this file
/// knows. Nothing reaches it today: `splitHeaders` asks
/// `engine.isRefused` first, and `refusedHeaderMessage` reads the same
/// set.
const framing_header_refused_message = "zurl writes this" ++ framing_header_reason;

/// One refusal message per name in `engine.refused_headers`, each naming
/// the header the caller wrote.
///
/// The proxy message already named its own header. The framing message
/// listed all five names and said nothing about which one the caller had
/// written, so the two read as different rules. `Diagnostics.message`
/// borrows its text, so each message is built here at comptime and lives
/// as long as the program does.
///
/// Built from `engine.refused_headers` itself, so a name added to that set
/// gets a message of its own with no edit here.
const refused_header_messages = blk: {
    var out: [zurl_http.engine.refused_headers.len][]const u8 = undefined;
    for (zurl_http.engine.refused_headers, 0..) |name, i| {
        out[i] = if (std.mem.eql(u8, name, "Proxy-Authorization"))
            proxy_authorization_refused_message
        else
            "zurl writes the " ++ name ++ framing_header_reason;
    }
    break :blk out;
};

/// The message that names why `name` is refused.
fn refusedHeaderMessage(name: []const u8) []const u8 {
    for (zurl_http.engine.refused_headers, refused_header_messages) |refused, message| {
        if (std.ascii.eqlIgnoreCase(name, refused)) return message;
    }
    return framing_header_refused_message;
}

/// Set on `Diagnostics.message` when the engine sends a request again
/// without the credential, to keep the credential off a redirect.
///
/// The transfer still returns whatever the server answered. A `401` at the
/// end of such a chain is not a password the server refused, so the caller
/// must be able to tell the two apart. See `performHttp`, and
/// `h1.Exchange.open`, which owns the rule.
const credential_withheld_message =
    "zurl did not send the caller's secrets again after the redirect. " ++
    "A credential and a cookie stay inside the origin that the url names.";

/// The sentence a transfer gets when it named a proxy for a protocol that
/// carries none.
const proxy_unread_message =
    "zurl does not carry this protocol through a proxy. " ++
    "The transfer is refused, because a direct connection is not what the " ++
    "proxy flag asked for. Use --noproxy to name this host, or run this " ++
    "url through curl.";

/// The sentence a transfer gets when it named a credential for a protocol
/// that sends none.
const credentials_unread_message =
    "zurl has no authentication for this protocol. " ++
    "The transfer is refused, because an unauthenticated transfer is not " ++
    "what the credential asked for. Drop -u and the userinfo of the url to " ++
    "run it with no credential.";

/// Refuses a transfer that named an option the protocol in hand reads
/// nothing of.
///
/// **This is the one place an unread option becomes loud.** Each protocol
/// names its own gaps in `Protocol.unread`, and every gap is answered here,
/// so a new protocol that carries no proxy needs no new refusal of its own.
/// See `zurl.protocol.Unread` for why a silent drop is the worse answer.
fn refuseUnread(
    p: protocol.Protocol,
    url: zurl_core.Url,
    url_text: []const u8,
    options: Transfer.Options,
    d: ?*Diagnostics,
) Error!void {
    // A host the user excluded from proxying reaches the origin direct
    // under every protocol, so there is nothing to refuse for it.
    if (p.unread.proxy and options.proxy_every_protocol and
        !zurl_core.proxy.bypasses(options.no_proxy, url.host))
    {
        return Diagnostics.record(d, error.NotBuiltIn, .{
            .url = url_text,
            .message = proxy_unread_message,
        });
    }

    // The url's userinfo counts as much as `-u`: both are a credential the
    // user named for this transfer. A netrc file does not, because only
    // the lookup this protocol never does would say whether it holds an
    // entry for this host.
    const named_credential = options.credentials != null or
        url.user != null or url.password != null;
    if (p.unread.credentials and named_credential) {
        return Diagnostics.record(d, error.NotBuiltIn, .{
            .url = url_text,
            .message = credentials_unread_message,
        });
    }
}

/// Writes the request target for `url` into `out`: the path, then `?` and
/// the query when the url has one.
///
/// RFC 7616 signs this exact text in the `uri` parameter, and the request
/// line writes the same text. A digest response built from the path alone
/// does not match what a server computes, so every url with a query failed
/// against a real server, and the `uri` parameter contradicted the request
/// line beside it.
///
/// `url.path` is never empty: `zurl_core.url.parse` gives a url with no
/// path the value "/".
fn requestTarget(out: []u8, url: zurl_core.Url) error{NoSpaceLeft}![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    writer.writeAll(url.path) catch return error.NoSpaceLeft;
    if (url.query) |query| {
        writer.writeByte('?') catch return error.NoSpaceLeft;
        writer.writeAll(query) catch return error.NoSpaceLeft;
    }
    return writer.buffered();
}

/// Fills `out` with a fresh, hex-encoded client nonce, from `c.io`'s
/// cryptographically secure random source. Every real digest exchange
/// needs a value here that an eavesdropper cannot predict; a fixed string
/// would let a replay of an old response pass as a new one.
fn freshCnonce(c: *Client, out: *[cnonce_hex_len]u8) []const u8 {
    var raw: [cnonce_raw_len]u8 = undefined;
    Io.random(c.io, &raw);
    return std.fmt.bufPrint(out, "{x}", .{&raw}) catch unreachable; // out is sized to fit exactly.
}

/// Returns the nonce count for `nonce`: 1 for a nonce this `Client` has
/// not answered before, one more than last time for a nonce it has. RFC
/// 7616 requires this to strictly increase within one server nonce, so a
/// server can catch a replayed response.
fn nextNc(c: *Client, nonce: []const u8) u32 {
    if (nonce.len <= c.digest_nonce_buf.len and
        c.digest_nonce_len == nonce.len and
        std.mem.eql(u8, c.digest_nonce_buf[0..c.digest_nonce_len], nonce))
    {
        c.digest_nc += 1;
        return c.digest_nc;
    }

    c.digest_nc = 1;
    const stored = @min(nonce.len, c.digest_nonce_buf.len);
    @memcpy(c.digest_nonce_buf[0..stored], nonce[0..stored]);
    c.digest_nonce_len = stored;
    return c.digest_nc;
}

/// Divides the caller's headers into `c.header_storage`, which may follow
/// a redirect, and `c.secret_storage`, which may not.
///
/// A secret travels through `engine.Request.secrets`, and through nothing
/// else. The engine refuses one among the ordinary headers, because it
/// writes those again on every hop of a redirect chain: a secret there
/// reaches whichever host the first server named. So every
/// header the caller wrote whose name `engine.isOriginBound` knows is
/// lifted out of the ordinary list and sent through the secrets channel,
/// where the same rule governs it as governs a credential zurl built.
///
/// `engine.origin_bound_headers` is the whole set, so a name added there
/// is carried here with no edit to this function. `Authorization` is the
/// one name this function skips: `authorize.apply` already decides that
/// value, the caller's own header included, and `authorization` carries
/// its answer.
///
/// A header in `engine.refused_headers` ends the transfer. The engine
/// refuses it too, so nothing can send it; this reports why, where the
/// engine can only report that a header was bad.
fn splitHeaders(
    c: *Client,
    url: zurl_core.Url,
    headers: []const std.http.Header,
    authorization: ?[]const u8,
    d: ?*Diagnostics,
) Error!void {
    c.header_storage.clearRetainingCapacity();
    c.secret_storage.clearRetainingCapacity();
    c.header_storage.ensureTotalCapacity(c.allocator, headers.len) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
    // One slot past the caller's own headers, for the credential
    // `authorize.apply` built.
    c.secret_storage.ensureTotalCapacity(c.allocator, headers.len + 1) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});

    for (headers) |header| {
        if (zurl_http.engine.isRefused(header.name)) return zurl_http.errors.mapError(
            error.InvalidHeader,
            d,
            .{ .host = url.host, .message = refusedHeaderMessage(header.name) },
        );
        if (std.ascii.eqlIgnoreCase(header.name, "Authorization")) continue;
        if (zurl_http.engine.isOriginBound(header.name)) {
            c.secret_storage.appendAssumeCapacity(header);
        } else {
            c.header_storage.appendAssumeCapacity(header);
        }
    }

    // The name is lower case, which is the case the engine writes every
    // header it owns in. A field name has no case to a server, and keeping
    // it stable keeps the wire bytes stable.
    if (authorization) |value| {
        c.secret_storage.appendAssumeCapacity(.{ .name = "authorization", .value = value });
    }
}

/// Sends one request and returns the open `Exchange` for its response.
///
/// `secrets` go out beside `headers` on the wire, but they travel through
/// `engine.Request.secrets`, so the engine keeps them inside the origin
/// `url` names. A credential or a session cookie that follows a `302` to
/// whichever host the first server named is a secret given away. `headers`
/// must therefore carry no origin-bound name of its own; the engine
/// refuses one that does. The caller owns the returned `Exchange` and must
/// close it.
fn sendOnce(
    c: *Client,
    url: zurl_core.Url,
    options: Transfer.Options,
    headers: []const std.http.Header,
    secrets: []const std.http.Header,
    proxies: zurl_http.engine.ProxySet,
    d: ?*Diagnostics,
) Error!*zurl_http.engine.Exchange {
    const open_request: zurl_http.engine.Request = .{
        .method = options.method,
        .url = url,
        .headers = headers,
        .secrets = secrets,
        .redirects = options.redirects,
        // **Both lists, and not just the redirect one.** A target a server
        // chose has to pass `--proto-redir` and `--proto` alike. curl
        // refuses `--proto -all,http --proto-redir +file` and accepts
        // `--proto -all,http,file --proto-redir +file`, so `--proto`
        // narrows a redirect too. `zurl_core.redirect.Set.intersect`
        // carries every row that was measured.
        .redirect_protocols = options.redirect_protocols.intersect(options.protocols),
        .tls_min_version = options.tls_min_version,
        .tls_max_version = options.tls_max_version,
        .no_alpn = options.no_alpn,
        .http_version = options.http_version,
        // The caller's stop flag, carried through unchanged. Nothing here
        // raises it or reads it. See `Transfer.Options.stop`.
        .stop = options.stop,
        .user_agent = options.user_agent,
        .accept_encoding = options.accept_encoding,
        .body = options.body,
        // The three fields below are the caller's answer, carried through
        // unchanged. None of them has a fallback: nothing in this file
        // turns verification off, or lets a secret cross an origin, on
        // behalf of a caller that asked for neither.
        .trusted_secrets = options.location_trusted,
        .insecure = options.insecure,
        .tcp_no_delay = options.tcp_no_delay,
        // The jar goes through as it is. It is not a secret in the sense
        // `secrets` means: the engine asks it again for every hop, and the
        // jar's own domain rule answers for that hop's host. See
        // `zurl_http.engine.CookieJar`.
        .cookies = options.cookies,
        // The dial overrides go through unchanged. Nothing in this file
        // reads them: they move the dial alone, and the engine is the one
        // place that dials. See `zurl_http.engine.HostOverride`.
        .connect_to = options.connect_to,
        .auto_referer = options.auto_referer,
        // The redirect method policy goes through unchanged. The engine is
        // the one place that follows a chain, so it is the one place that
        // can rewrite a method. See `zurl_http.engine.RedirectMethods`.
        .redirect_methods = options.redirect_methods,
        // **The proxy set, carried through and never decided here.** The
        // engine reads it again for each hop, with that hop's own scheme and
        // host, because a redirect can change both. `zurl/proxy.zig` built
        // the credentials in it, and this file reads no field of them: the
        // proxy's credential and the origin's credential are built by two
        // different files and neither one reads the other's.
        .proxies = proxies,
    };

    const iface = c.http.interface();
    const exchange = iface.open(open_request) catch |err| switch (err) {
        error.ConnectTimeoutUnsupported => degraded: {
            // A build with no concurrency cannot race the connect against
            // `options.connect_timeout`; `h1.zig`'s own `openConnection`
            // already refuses rather than drop the bound silently. That
            // refusal is correct for the engine, taken alone, but a caller
            // who never asked for a bound at all (`Transfer.Options`
            // defaults to 15 seconds) should not have every transfer fail
            // as unreachable. Retry with no bound, and say so in `d`, so
            // the degradation is reported instead of silent.
            if (d) |dg| dg.message = connect_timeout_degraded_message;
            c.http.connect_timeout = .none;
            break :degraded iface.open(open_request) catch |retry_err|
                return zurl_http.errors.mapError(retry_err, d, .{
                    .host = url.host,
                    // The degraded message above is the one a user needs
                    // here: it says why the bound was dropped. The engine
                    // cause would replace it, so it is not read on this
                    // path.
                    .message = connect_timeout_degraded_message,
                });
        },
        // **The engine met a redirect it cannot follow and the caller
        // can.** The target goes into this client's own storage, and
        // `perform` reads it there and dispatches it. The error still
        // maps, so a `perform` that does not take the hop reports exactly
        // what that target reported before this path existed.
        //
        // The copy happens here and not in `perform`, because the engine
        // invalidates its own record on the next `open` and this is the
        // only moment that record is certainly the one this call made.
        error.RedirectToOtherProtocol => {
            if (c.http.redirectHandoff()) |target| c.recordHandoff(target);
            return zurl_http.errors.mapError(err, d, .{
                .host = url.host,
                .message = iface.cause(),
            });
        },
        // The engine's cause is the sentence for the fault it just
        // reported. Four different certificate faults are all exit 60, so
        // the code alone cannot say which check refused the peer. Null
        // whenever the fault carried no cause, and `mapError` then falls
        // back to the sentence its own table holds.
        else => return zurl_http.errors.mapError(err, d, .{
            .host = url.host,
            .message = iface.cause(),
        }),
    };

    // The connection is up. It may still be a slow one: a `TCP_NODELAY`
    // that did not take costs up to 40 milliseconds for each request. The
    // transfer runs, so this is not a fault, and `report.zig` writes a
    // message only beside a fault. So the sentence is recorded and never
    // printed, which is what curl does at info level, and a verbose mode
    // can print it later.
    //
    // A message the degraded path already wrote stays. That one says why
    // a bound was dropped, which a user needs more.
    if (d) |dg| {
        if (dg.message == null) dg.message = c.http.noDelayCause();
    }
    return exchange;
}

/// The built-in HTTP/1.1 and HTTPS protocol. `protocol.builtins` calls
/// this through the same `Protocol.VTable.perform` seam a registered
/// protocol uses; it is `pub` only so `protocol.zig` can reach it, not as
/// a second entry point for a caller. Use `perform` instead.
///
/// Sends at most two requests. The first carries whatever
/// `authorize.apply` builds with no challenge: `Basic` when credentials
/// exist, nothing when they do not. A `401` that answers with a
/// `WWW-Authenticate` challenge gets exactly one retry, built from that
/// challenge; a second `401` after that retry is returned as an ordinary
/// response, not retried again, so a server that never accepts the
/// credentials cannot loop this forever.
///
/// **The retry goes to the hop that issued the challenge.** For an
/// ordinary transfer that is the url the caller named. For one the engine
/// redirected, it is `engine.Head.effective_url`, and the digest `uri`
/// parameter is built from that hop's own target. Measured against curl
/// 8.21.0: over a chain ending in a `401 Digest`, curl's second request
/// went to the final hop and signed that hop's target.
///
/// **A challenge from a hop the credential may not reach is not answered
/// at all.** The engine resends every hop past the first with the secrets
/// dropped, unless `Transfer.Options.location_trusted` says otherwise, so
/// answering such a challenge would either send the credential to a hop
/// the redirect rules excluded or send a digest built under that hop's
/// realm and nonce back to the first hop, which issued no challenge. Both
/// are a credential given to the wrong party. curl answers no such
/// challenge either, measured. The `401` goes back as it came and
/// `Diagnostics.message` says why.
pub fn performHttp(c: *Client, url: zurl_core.Url, options: Transfer.Options, d: ?*Diagnostics) Error!Response {
    // `h1.Engine.connect_timeout` is a per-engine field, not a per-call
    // argument, because `engine.Engine.VTable.open` takes no timeout of
    // its own. Setting it here, right before the open it governs, is
    // what lets `Transfer.Options.connect_timeout` vary from one
    // `perform` to the next on the same `Client`.
    c.http.connect_timeout = options.connect_timeout;

    // No challenge from a redirect target has been answered yet, so the
    // url of the last one must not survive into this transfer's
    // `Response.effective_url`.
    c.challenge_url_len = 0;

    // **`--connect-timeout` bounds the dial and nothing after it.** A peer
    // that accepts the connection, answers a head, and then goes quiet held
    // this client for ever, because the rate rule above the reader counts
    // octets as they arrive and a read that never returns delivers none.
    //
    // This is the bound on one read. `h1.readTimeoutFor` narrows the 300
    // second ceiling by `--speed-time` when the caller named one, and 300
    // is curl's own `--speed-time` default and the number every other
    // protocol package of this repository already keeps. The clock starts
    // again at each read, so a slow transfer that still moves is never
    // stopped. See `h1.readTimeoutFor`.
    c.http.read_timeout = zurl_http.h1.readTimeoutFor(
        options.low_speed_limit,
        options.low_speed_time_s,
    );

    const method_name = @tagName(options.method);

    // Built once and used by both attempts. The request line carries the
    // path and the query together, so the digest `uri` parameter must too.
    var target_buf: [request_target_len]u8 = undefined;
    const target = requestTarget(&target_buf, url) catch
        return Diagnostics.record(d, error.InvalidUrl, .{
            .host = url.host,
            .message = request_target_oversize_message,
        });

    // A secret the caller wrote takes the same path as a credential zurl
    // built: the engine's `secrets` field, which keeps it inside the origin
    // the caller named. It therefore has to come out of the ordinary
    // headers, which `std` carries to every host in a redirect chain.
    const caller_authorization = authorize.callerAuthorization(options.headers);

    // Room for the challenge parameters that carry a quoted-pair, which
    // `selectChallenge` writes with the escapes taken off. Taking an
    // escape off only shortens a value, so a buffer as long as the
    // challenge text is always enough; the engine keeps no challenge
    // longer than this. A challenge that still does not fit reads as
    // unreadable, and `challenge_unreadable_message` reports it.
    //
    // Declared out here because the `Challenge` borrows from it and lives
    // until the retry is built.
    var challenge_scratch: [challenge_scratch_len]u8 = undefined;

    // The credential owns heap storage that `authorize.apply` sized from
    // the credential itself. It lives until this function returns, which
    // is exactly as long as the engine reads `secret_storage`: the engine
    // writes every hop of a chain inside `sendOnce` and keeps nothing
    // after that call comes back. `deinit` wipes the buffer before it
    // frees it, so no cleartext password goes back to the allocator.
    //
    // **`--digest` and `--anyauth` send nothing here.** Both ask the
    // server to name a scheme first. A preemptive `Basic` would put the
    // password on the wire in reversible base64 before the server had
    // asked for anything, which is the one thing those two flags exist to
    // stop. See `Transfer.AuthMode`.
    var first_authorization = if (!options.auth_mode.sendsPreemptiveCredential())
        null
    else
        authorize.apply(c.allocator, url, options, null, .{
            .method = method_name,
            .uri = target,
            .cnonce = "",
            .nc = 0,
        }) catch |err| return Diagnostics.record(d, mapAuthorizeError(err), .{ .host = url.host, .message = @errorName(err) });
    defer if (first_authorization) |*v| v.deinit(c.allocator);

    if (first_authorization) |v| {
        if (authorizationOversize(v.text)) return Diagnostics.record(d, error.CredentialTooLarge, .{
            .host = url.host,
            .message = credentialOversizeMessage(d, v.source, v.text.len),
        });
    }

    // **The proxy's credential, built once for this transfer.** It owns
    // heap storage, and it lives until this function returns, which is
    // exactly as long as the engine reads the set: the engine writes every
    // hop inside `sendOnce` and keeps nothing after that call comes back.
    // `deinit` wipes the buffer before it frees it.
    //
    // Built by `proxy.resolve` and never by `authorize.apply`. The two
    // credentials go to two different peers, and one builder for both would
    // need a flag to say which, and a flag can be wrong.
    var proxies = proxy.resolve(c.allocator, options) catch |err| return Diagnostics.record(
        d,
        mapProxyError(err),
        .{ .host = url.host, .message = @errorName(err) },
    );
    defer proxies.deinit(c.allocator);

    try c.splitHeaders(url, options.headers, if (first_authorization) |v| v.text else null, d);
    const exchange = try c.sendOnce(url, options, c.header_storage.items, c.secret_storage.items, proxies.set, d);
    c.current_exchange = exchange;

    retry: {
        if (exchange.head().status != 401) break :retry;
        // The caller's own header is the whole credential when there is
        // one. zurl answers no challenge on the caller's behalf, and curl
        // answers none for a `-H` header either. A retry would resend the
        // same header and buy nothing but a second request.
        if (caller_authorization != null) break :retry;
        // **A retry sends the request body again, so the body has to go
        // back to its first byte.** The engine puts a rewindable source
        // back itself, on every send. It cannot do that for a source with
        // no rewind, which is what a pipe gives, and a second send would
        // then carry whatever bytes were left over.
        //
        // Answer the `401` as an ordinary response instead, and say why in
        // `Diagnostics`. Recovery is never silent: a user who sees a `401`
        // with credentials on the command line has to learn that the
        // challenge went unanswered, and why.
        if (options.body) |source| {
            if (source.rewind == null) {
                if (d) |dg| dg.message = challenge_unanswerable_message;
                break :retry;
            }
        }
        // **The answer goes to the hop that asked, and never to the url
        // the caller named.** Measured against curl 8.21.0 over a chain
        // where `/start` answers `302` to `/final` and `/final` answers
        // `401 Digest`: with `-L --digest -u`, curl sent its second
        // request to `/final` with `uri="/final"`. It did not go back to
        // `/start`.
        //
        // zurl used to retry `url`, which is wrong twice. The `uri`
        // parameter of the digest is signed over the caller's target and
        // no server reading RFC 7616 section 3.4 accepts it against
        // another request line. And the credential is built under the
        // realm and the nonce the last hop chose, so sending it back to
        // the first hop hands a chosen-realm digest of the user's
        // password to a party that issued no challenge. That is the same
        // defect `h1.Engine.chain_challenge_untrusted` closed from the
        // other side, and it must not be reopened here.
        //
        // `effective_url` is null when the engine followed no redirect,
        // and the hop that asked is then the url the caller named.
        const challenge_hop = exchange.head().effective_url;
        if (challenge_hop != null and !options.location_trusted) {
            // A redirect target asked, and the credential may not travel
            // there: the engine resends every hop past the first with the
            // secrets dropped. A challenge from a hop that may not carry
            // the credential is not answered at all, which is what curl
            // does, measured: `-L --digest -u` across hosts sent one
            // request to each and no `Authorization` on either.
            //
            // The engine already withholds such a challenge. This is the
            // same rule at the second gate, because `h2.Exchange` does not
            // read that engine flag yet and a `401` can still arrive here
            // from a redirect target over an h2c upgrade.
            if (d) |dg| dg.message = challenge_redirect_untrusted_message;
            break :retry;
        }

        // A challenge the engine had to drop is a recovered fault, whether
        // or not a second challenge fit beside it. Report it either way,
        // or the caller sees a bare 401 with no reason for it.
        if (exchange.head().www_authenticate_oversize) {
            if (d) |dg| dg.message = challenge_oversize_message;
        }
        const challenge_text = exchange.head().www_authenticate orelse break :retry;
        const challenge = zurl_core.auth.selectChallenge(&challenge_scratch, challenge_text) orelse {
            // The server asked for something, and zurl could not read what.
            // Report it rather than answer the 401 with silence.
            if (d) |dg| dg.message = challenge_unreadable_message;
            break :retry;
        };
        // **A scheme the mode does not permit is never answered.** Only
        // `--digest` narrows this: a user who named it asked for a scheme
        // where the password never travels, so a server offering `Basic`
        // alone gets no answer and the `401` goes back as it came.
        // Recovery is never silent, so the reason is recorded.
        if (!options.auth_mode.answers(challenge.scheme)) {
            if (d) |dg| dg.message = challenge_scheme_refused_message;
            break :retry;
        }

        // Where the retry goes, and what the digest signs. Both are the
        // caller's url whenever the engine followed no redirect, which is
        // every ordinary transfer.
        var retry_url = url;
        var retry_target = target;
        var retry_target_buf: [request_target_len]u8 = undefined;
        if (challenge_hop) |hop_text| {
            // `--location-trusted`, checked above, so the credential is
            // permitted to reach this hop. The text is copied first: it is
            // borrowed from `exchange`, and the retry closes that exchange
            // before it sends anything.
            if (!c.recordChallengeUrl(hop_text)) {
                if (d) |dg| dg.message = challenge_hop_unreadable_message;
                break :retry;
            }
            const hop = c.challengeUrl().?;
            retry_url = zurl_core.url.parse(hop) catch {
                if (d) |dg| dg.message = challenge_hop_unreadable_message;
                c.challenge_url_len = 0;
                break :retry;
            };
            // The engine writes no userinfo into the url of a hop, and a
            // credential the caller typed into the url is still this
            // transfer's credential. `--location-trusted` is what lets it
            // follow, and curl carries it the same way.
            retry_url.user = url.user;
            retry_url.password = url.password;
            retry_target = requestTarget(&retry_target_buf, retry_url) catch {
                if (d) |dg| dg.message = request_target_oversize_message;
                c.challenge_url_len = 0;
                break :retry;
            };
        }

        var cnonce_storage: [cnonce_hex_len]u8 = undefined;
        var cnonce: []const u8 = "";
        var nc: u32 = 0;
        if (challenge.scheme == .digest) {
            cnonce = c.freshCnonce(&cnonce_storage);
            nc = c.nextNc(challenge.nonce orelse "");
        }

        var retry_authorization = authorize.apply(c.allocator, retry_url, options, challenge, .{
            .method = method_name,
            .uri = retry_target,
            .cnonce = cnonce,
            .nc = nc,
        }) catch |err| {
            exchange.close();
            c.current_exchange = null;
            return Diagnostics.record(d, mapAuthorizeError(err), .{ .host = url.host, .message = @errorName(err) });
        };
        defer if (retry_authorization) |*v| v.deinit(c.allocator);
        const answer = retry_authorization orelse break :retry;

        // A `Digest` value carries the realm, the nonce, and the opaque
        // token the server chose, so a retry can be longer than the
        // `Basic` value that went out first. It gets the same check.
        if (authorizationOversize(answer.text)) {
            exchange.close();
            c.current_exchange = null;
            return Diagnostics.record(d, error.CredentialTooLarge, .{
                .host = url.host,
                .message = credentialOversizeMessage(d, answer.source, answer.text.len),
            });
        }

        exchange.close();
        c.current_exchange = null;
        // The lists are rebuilt after the close, not before it: the first
        // exchange reads them until it closes.
        //
        // `retry_url` is the caller's url for every transfer the engine
        // did not redirect, and the hop that issued the challenge for one
        // it did. It borrows from `challenge_url_storage`, which belongs
        // to this client and outlives the exchange that named it.
        try c.splitHeaders(retry_url, options.headers, answer.text, d);
        c.current_exchange = try c.sendOnce(retry_url, options, c.header_storage.items, c.secret_storage.items, proxies.set, d);
    }

    const head = c.current_exchange.?.head();

    // The engine drops every secret rather than let one follow a redirect,
    // so an authenticated transfer that meets one arrives without its
    // credential. That looks exactly like a password the server refused.
    // Say which it was. A message already set names a fault that came
    // first, and it stays.
    if (head.credential_withheld) {
        if (d) |dg| {
            if (dg.message == null) dg.message = credential_withheld_message;
        }
    }

    const raw_body = c.current_exchange.?.bodyReader(&c.body_buffer);
    // `body_stack`'s `Progress` and its `max_size` limit both sit above
    // `raw_body`, which is already decoded: `Exchange.bodyReader` runs any
    // content decoding before this stack ever sees a byte. So both of them
    // already count decoded bytes, matching the bytes a download actually
    // writes to disk. `content_length`, in contrast, is the peer's
    // announced length before that decoding. When `body_decoded` is true,
    // that number describes a byte count `Progress.transferred` will never
    // reach, so it is reported as unknown (zero) rather than a total the
    // transfer contradicts.
    const progress_total: u64 = if (head.body_decoded) 0 else head.content_length orelse 0;
    body.Stack.init(&c.body_stack, raw_body, c.io, options, progress_total, .{
        .top = &c.body_stack_buffer,
    });
    c.body_stack_live = true;

    return .{
        .status = head.status,
        // The version the last hop answered in, which is the hop this body
        // came from. See `Response.http_version`.
        .http_version = head.wire_version,
        .content_length = head.content_length,
        .transfer_encoding = head.transfer_encoding,
        .body = c.body_stack.reader(),
        // Handed on, not copied. The engine keeps these bytes until the
        // next `Engine.open`, and the only call that opens one is the next
        // `perform` on this `Client`, which is exactly the life
        // `Response.headers` promises. A copy here would buy a caller
        // nothing and cost every transfer a memcpy of the whole head.
        .headers = head.headers,
        .final_headers = head.final_headers,
        .headers_oversize = head.headers_oversize,
        // Empty when the engine followed no redirect. `perform` fills the
        // url text the caller gave it, which `performHttp` never sees:
        // this function takes a parsed `zurl_core.Url`, and the text it
        // was parsed from belongs to the caller of `perform`.
        //
        // A `401` answered at a redirect target leaves the engine with no
        // redirect of its own to report, because the retry went straight
        // to that hop. The hop is still the url the body came from, so
        // `challengeUrl` fills it. The engine's own answer outranks it,
        // for a retry that met a further redirect.
        .effective_url = head.effective_url orelse c.challengeUrl() orelse "",
    };
}

/// Turns a bare `error.ReadFailed` from the current `Response.body` into
/// the named fault that caused it, and records that fault in `d`. See
/// `body.Stack.resolve` for the order it checks.
///
/// Call this right after a read from `Response.body` returns
/// `error.ReadFailed`, not as a general poll: the flags it reads all
/// latch, so a stale one from an earlier read cannot be told apart from a
/// fresh one. Valid only while the `Response` from the most recent
/// `perform` is still current; a later `perform` on this `Client`
/// rebuilds `body_stack` the same way it invalidates `Response.body`
/// itself.
///
/// Reports the generic `error.ReadError`, and reads nothing from
/// `body_stack`, when `body_stack_live` is false: the current `Response`
/// came from a protocol that never built `body_stack` for it, such as one
/// registered with `registerProtocol`, so `body_stack` may still hold
/// `undefined`.
/// Whether any peer answered any byte of the most recent HTTP transfer.
///
/// **Read this before sending the same request again.** A caller with a
/// retry of its own, such as `--retry`, must never resend a request the
/// peer already answered: the peer has acted on it, whatever the transfer
/// failed with afterwards, and a second copy would ask it to act twice.
///
/// This is `zurl_http.h1.Exchange.peer_answered` for the whole transfer,
/// every hop of a redirect chain included. It is the one signal for the
/// question, so a caller must not build a second one out of the error
/// name or the status.
///
/// False for a transfer that ran through a protocol registered with
/// `registerProtocol`, because such a protocol opens nothing through this
/// engine. False is the safe answer: it says no peer is known to have
/// answered, and a caller then falls back to its own rule.
///
/// Valid only beside the result of the most recent `perform`. Every
/// `perform` that reaches the HTTP engine clears it.
pub fn peerAnswered(c: *const Client) bool {
    return c.http.peerAnswered();
}

/// The value of response header `name` from the head of the most recent
/// transfer, or null when that head carries none.
///
/// **This is for the caller that has no `Response`.** `--fail` turns a
/// `4xx` or `5xx` into `error.HttpReturnedError`, so `perform` reports the
/// fault and hands back no `Response`, and a `--retry` that wants the
/// peer's own `Retry-After` has nowhere else to read it. Every other
/// caller reads `Response.header`, which answers from the same block by
/// the same rule.
///
/// Reads the final response's own head and never an earlier hop's, the
/// same way `Response.header` does.
///
/// **Lifetime.** Valid until the next `perform` on this `Client`, or until
/// `deinit`, whichever comes first.
pub fn finalHeader(c: *const Client, name: []const u8) ?[]const u8 {
    const exchange = c.current_exchange orelse return null;
    return Response.headerIn(exchange.head().final_headers orelse return null, name);
}

/// The trailer section the peer sent after the body, or null when it sent
/// none.
///
/// **Ask for this after the body has been read to its end.** A trailer
/// arrives behind the last body octet, so a call made before the body ended
/// answers null even for a response that carries one. That is not a fault
/// to report: a caller that streams a body and then asks reads the whole
/// answer, and a caller that never reads the body has nothing to ask
/// about.
///
/// The text is field lines and nothing else: one `name: value\r\n` for each
/// field, in the order they arrived, with no status line before them and no
/// empty line after them. That is what `curl -D` and `curl -i` append after
/// the body, measured against curl 8.21.0.
///
/// These fields are not in `Response.headers` and `Response.header` does
/// not find them, which is what curl does too: its `%header{}` answered
/// empty for a trailer field and its `%{size_header}` counted the head
/// block alone. See `zurl_http.engine.Exchange.trailers`.
///
/// **Lifetime.** Valid until the next `perform` on this `Client`, or until
/// `deinit`, whichever comes first.
pub fn responseTrailers(c: *const Client) ?[]const u8 {
    const exchange = c.current_exchange orelse return null;
    return exchange.trailers();
}

pub fn resolveBodyError(c: *const Client, d: ?*Diagnostics) Error {
    if (!c.body_stack_live) return Diagnostics.record(d, error.ReadError, .{});
    return c.body_stack.resolve(c.current_exchange, d);
}

const testing = std.testing;
const test_server = zurl_http.test_server;

test "perform fetches a body over the loopback server" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqual(@as(?u64, 7), response.content_length);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "the default user agent reaches the wire" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "user-agent: zurl/0.1\r\n") != null);
}

test "a caller's user_agent reaches the wire, and std's own default does not" {
    // `Transfer.Options.user_agent` used to be accepted and dropped:
    // `std.http.Client` wrote its own "zig/0.16.0 (std.http)" value no
    // matter what a caller set. curl sends exactly the string `-A` names.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .user_agent = "zurl-test/9.9" }, null);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "user-agent: zurl-test/9.9\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "std.http") == null);
}

test "an unknown scheme is UnsupportedProtocol, not a crash" {
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.UnsupportedProtocol,
        client.perform("ftp://127.0.0.1/file", .{}, &d),
    );
    try testing.expectEqualStrings("ftp://127.0.0.1/file", d.url().?);
}

test "fail_on_error turns a 404 into HttpReturnedError with the status recorded" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(
        error.HttpReturnedError,
        client.perform(url_text, .{ .fail_on_error = true }, &d),
    );
    try testing.expectEqual(@as(u16, 404), d.status.?);
}

test "fail_on_error false returns the 404 as a status" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 404), response.status);
}

fn fakePerform(
    ptr: ?*anyopaque,
    c: *Client,
    url: zurl_core.Url,
    options: Transfer.Options,
    d: ?*Diagnostics,
) Error!Response {
    _ = c;
    _ = url;
    _ = options;
    _ = d;
    const reader: *std.Io.Reader = @ptrCast(@alignCast(ptr.?));
    return .{ .status = 200, .content_length = 16, .transfer_encoding = .none, .body = reader };
}

test "a runtime registered protocol handles its own scheme" {
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var body_reader: std.Io.Reader = .fixed("registered-body");
    const vtable: protocol.Protocol.VTable = .{ .perform = fakePerform };
    try client.registerProtocol(.{
        .scheme = "test",
        .default_port = 9,
        .ptr = &body_reader,
        .vtable = &vtable,
    });

    // `zurl_core.url.parse` has no default port for a scheme it does not
    // know, so a URL of one that names no port is
    // `error.UnsupportedProtocol`. This client registered the scheme, so
    // the port is not needed here, and it is written out to show that a
    // named port still wins.
    const response = try client.perform("test://example.invalid:9/", .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("registered-body", contents);
}

test "resolveBodyError answers the generic fault for a response the decorator stack never built" {
    // A runtime-registered protocol returns its own body reader directly
    // and never touches `performHttp`, so `body_stack` never gets built for
    // this response. `resolveBodyError` must not read it anyway.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var body_reader: std.Io.Reader = .fixed("registered-body");
    const vtable: protocol.Protocol.VTable = .{ .perform = fakePerform };
    try client.registerProtocol(.{
        .scheme = "test",
        .default_port = 9,
        .ptr = &body_reader,
        .vtable = &vtable,
    });

    _ = try client.perform("test://example.invalid:9/", .{}, null);

    var d: Diagnostics = .{};
    try testing.expectEqual(zurl_core.Error.ReadError, client.resolveBodyError(&d));
}

test "the client loads certificate authorities exactly once across two transfers" {
    // `ensureCaBundle` runs at the hop that speaks TLS, before that hop
    // connects, so an `https` url and a closed port are enough: no live
    // server, and the test runs even in a build with no concurrency,
    // where `TestServer` cannot start.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    _ = client.perform("https://127.0.0.1:1/", .{}, null) catch {};
    try testing.expectEqual(@as(usize, 1), client.ca_load_count);

    _ = client.perform("https://127.0.0.1:1/", .{}, null) catch {};
    try testing.expectEqual(@as(usize, 1), client.ca_load_count);
}

test "a later transfer's trust inputs are read and never the first transfer's" {
    // **The guard that failed open.** The load ran once for the life of a
    // `Client` and every later `--cacert` was thrown away, so a second
    // transfer that pinned a root verified against the public root set the
    // first transfer loaded. `Multi` reaches it: jobs share a `Client`
    // slot when there are more jobs than slots, and each job carries its
    // own `Transfer.Options`.
    //
    // No live server: `ensureCaBundle` runs before the hop connects, so a
    // closed port is enough and this runs in every build configuration.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    _ = client.perform("https://127.0.0.1:1/", .{}, null) catch {};
    try testing.expectEqual(@as(usize, 1), client.ca_load_count);
    try testing.expect(client.http.ca_bundle.map.count() > 0);

    // A second transfer that names a root file it cannot read must fail,
    // and not run against the roots the first transfer left behind.
    try testing.expectError(error.CaCertBadFile, client.perform(
        "https://127.0.0.1:1/",
        .{ .ca = .{ .cacert = "/nonexistent/zurl-test-ca.pem" } },
        null,
    ));
    // The roots the caller replaced are gone. An explicit source replaces
    // the built-in bundle, so leaving the old ones in place would verify
    // against roots the caller took away. The count stays at one, because
    // this load did not finish.
    try testing.expectEqual(@as(usize, 0), client.http.ca_bundle.map.count());
    try testing.expectEqual(@as(usize, 1), client.ca_load_count);

    // A third transfer names the first inputs again, so it loads again.
    _ = client.perform("https://127.0.0.1:1/", .{}, null) catch {};
    try testing.expectEqual(@as(usize, 2), client.ca_load_count);
    try testing.expect(client.http.ca_bundle.map.count() > 0);

    // And the same inputs twice in a row still load once.
    _ = client.perform("https://127.0.0.1:1/", .{}, null) catch {};
    try testing.expectEqual(@as(usize, 2), client.ca_load_count);
}

test "the client has trust roots after it is used" {
    // Same reasoning as the test above: the load runs before the connect
    // of the TLS hop, so a closed port is enough, and this proves the
    // bundle loaded in every build configuration.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    // The connect itself fails, and the handshake never starts, so the
    // bundle holds what the load put there and nothing else.
    _ = client.perform("https://127.0.0.1:1/", .{}, null) catch {};
    try testing.expect(client.http.ca_bundle.map.count() > 0);
}

test "a certificate path that cannot be read does not fail a plain http transfer" {
    // Five sources reach one loader, so a fix for one of them says
    // nothing about the other four. curl reads no trust store for an
    // `http` url and exits 7, for the connect that failed. Every case
    // here must do the same.
    //
    // `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, and `SSL_CERT_DIR` come from the
    // environment. A stale value in a shell profile used to stop every
    // plain HTTP request this binary could make.
    const bad_file = "/nonexistent/zurl-test-ca.pem";
    const bad_dir = "/nonexistent/zurl-test-certs";
    const cases = [_]zurl_core.ca.Inputs{
        .{ .cacert = bad_file },
        .{ .capath = bad_dir },
        .{ .curl_ca_bundle = bad_file },
        .{ .ssl_cert_file = bad_file },
        .{ .ssl_cert_dir = bad_dir },
    };

    for (cases) |inputs| {
        var client: Client = .init(testing.allocator, testing.io);
        defer client.deinit();

        // Port 1 is closed on loopback, so the fault the transfer really
        // meets is a refused connection.
        try testing.expectError(
            error.CouldNotConnect,
            client.perform("http://127.0.0.1:1/", .{ .ca = inputs }, null),
        );
        // Nothing read the path at all, which is the whole point: the
        // transfer used no TLS.
        try testing.expectEqual(@as(usize, 0), client.ca_load_count);
    }
}

test "a certificate path that cannot be read fails an https transfer and names the path" {
    // The other half of the rule above. A transfer that does speak TLS
    // must still refuse to run with roots the caller asked for and did
    // not get, and the message must say which path was bad.
    //
    // `CURL_CA_BUNDLE` names a file, so this is curl's 77
    // (CURLE_SSL_CACERT_BADFILE), not the 35 this test pinned before this
    // task gave a file source its own code.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.CaCertBadFile, client.perform(
        "https://127.0.0.1:1/",
        .{ .ca = .{ .curl_ca_bundle = "/nonexistent/zurl-test-ca.pem" } },
        &d,
    ));
    try testing.expectEqualStrings(
        "zurl did not read the certificate file /nonexistent/zurl-test-ca.pem: FileNotFound",
        d.message.?,
    );
    try testing.expectEqual(@as(u32, 77), d.curl_code.?);
}

test "each certificate source reports the curl code this task assigns it" {
    // Five sources reach one loader, in `ensureCaBundle`. curl gives a
    // file-based source and a directory-based source two different exit
    // codes: 77 (CURLE_SSL_CACERT_BADFILE) for a certificate file it
    // could not read, `--cacert`, `CURL_CA_BUNDLE`, or `SSL_CERT_FILE`;
    // 60 (CURLE_PEER_FAILED_VERIFICATION) for a certificate directory it
    // could not scan, `--capath` or `SSL_CERT_DIR`. Measured against real
    // curl 8.21.0.
    //
    // Driven through one table so a sixth field added to
    // `zurl_core.ca.Inputs` has to earn a row here before this test
    // passes again.
    const bad_file = "/nonexistent/zurl-test-ca.pem";
    const bad_dir = "/nonexistent/zurl-test-certs";
    const cases = [_]struct { inputs: zurl_core.ca.Inputs, want: Error }{
        .{ .inputs = .{ .cacert = bad_file }, .want = error.CaCertBadFile },
        .{ .inputs = .{ .capath = bad_dir }, .want = error.PeerFailedVerification },
        .{ .inputs = .{ .curl_ca_bundle = bad_file }, .want = error.CaCertBadFile },
        .{ .inputs = .{ .ssl_cert_file = bad_file }, .want = error.CaCertBadFile },
        .{ .inputs = .{ .ssl_cert_dir = bad_dir }, .want = error.PeerFailedVerification },
    };

    for (cases) |case| {
        var client: Client = .init(testing.allocator, testing.io);
        defer client.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(case.want, client.perform(
            "https://127.0.0.1:1/",
            .{ .ca = case.inputs },
            &d,
        ));
        try testing.expectEqual(zurl_core.errors.curlCode(case.want), d.curl_code.?);
    }
}

/// Returns the absolute path of a `std.testing.tmpDir`, so a test can hand
/// it to `Transfer.Options.ca` as a `--capath` directory.
fn testTmpDirPath(tmp: *std.testing.TmpDir) ![]u8 {
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(testing.io, &buffer);
    return testing.allocator.dupe(u8, buffer[0..n]);
}

/// A PEM file whose armor holds a primitive DER element. The guard in
/// `zurl_tls.bundle` refuses it, so it stands for any entry of a
/// certificate directory that zurl cannot read as certificates.
const bad_pem_fixture = "-----BEGIN CERTIFICATE-----\nAgEA\n-----END CERTIFICATE-----\n";

test "one bad entry in a capath directory does not cost the client its other roots" {
    // The whole point of skipping an entry rather than failing the
    // directory. The connect still fails, because nothing listens on port
    // 1, and that is the fault the caller gets: the trust roots loaded.
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "roots.pem", .data = zurl_tls.bundle.test_pem });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "bad.pem", .data = bad_pem_fixture });
    const path = try testTmpDirPath(&tmp);
    defer testing.allocator.free(path);

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, client.perform(
        "https://127.0.0.1:1/",
        .{ .ca = .{ .capath = path } },
        &d,
    ));

    // Recovery is never silent: the skip waits here until a caller reads
    // it, and the command line prints it to standard error.
    const skipped = client.takeCaSkips().?;
    try testing.expect(std.mem.indexOf(u8, skipped, "bad.pem") != null);
    try testing.expect(std.mem.indexOf(u8, skipped, "CertificateFieldHasInvalidLength") != null);

    // Handed out once. The roots load one time for the life of a client,
    // so a run of many urls must not report the same skip for every url.
    try testing.expectEqual(@as(?[]const u8, null), client.takeCaSkips());
}

test "a capath directory with no usable entry fails and names what it skipped" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "bad.pem", .data = bad_pem_fixture });
    const path = try testTmpDirPath(&tmp);
    defer testing.allocator.free(path);

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var d: Diagnostics = .{};
    // 60 is curl's own code for a certificate directory that did not
    // scan. The directory holds no root, and `ca.resolve` leaves the
    // embedded bundle out as soon as a source is named, so this transfer
    // has nothing to verify against and must not go on.
    try testing.expectError(error.PeerFailedVerification, client.perform(
        "https://127.0.0.1:1/",
        .{ .ca = .{ .capath = path } },
        &d,
    ));
    try testing.expectEqual(@as(?u32, 60), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "NoUsableCertificateFile") != null);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "bad.pem") != null);

    // The failure message already carried the skips to the user, so the
    // command line must not print them a second time.
    try testing.expectEqual(@as(?[]const u8, null), client.takeCaSkips());
}

test "the failure message survives a second transfer that fills another diagnostics" {
    // `Diagnostics.message` points into `message_storage` here, so each
    // `Diagnostics` owns its own sentence. A `Client`-owned buffer would
    // have let the second transfer rewrite what the first reported.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var first: Diagnostics = .{};
    _ = client.perform(
        "https://127.0.0.1:1/",
        .{ .ca = .{ .cacert = "/nonexistent/zurl-test-first.pem" } },
        &first,
    ) catch {};

    var second: Diagnostics = .{};
    _ = client.perform(
        "https://127.0.0.1:1/",
        .{ .ca = .{ .cacert = "/nonexistent/zurl-test-second.pem" } },
        &second,
    ) catch {};

    try testing.expect(std.mem.indexOf(u8, first.message.?, "zurl-test-first.pem") != null);
    try testing.expect(std.mem.indexOf(u8, second.message.?, "zurl-test-second.pem") != null);
}

test "a connect timeout that this build cannot enforce degrades instead of failing every transfer" {
    // `Transfer.Options.connect_timeout` defaults to 15 seconds, so an
    // ordinary `perform` call with no explicit options used to take the
    // `std.Io.Select` race path on every transfer. In a build with no
    // concurrency that race cannot start, `h1.connect` refused with
    // `error.ConnectTimeoutUnsupported`, and every transfer failed as
    // `CouldNotConnect`, whether or not the peer was reachable. This test
    // needs no `TestServer`, so a forced no-concurrency `Io` is enough to
    // see that configuration, on any build.
    var no_concurrency: std.Io.Threaded = .init(testing.allocator, .{ .concurrent_limit = .nothing });
    defer no_concurrency.deinit();

    var client: Client = .init(testing.allocator, no_concurrency.io());
    defer client.deinit();

    var d: Diagnostics = .{};
    // Port 1 is closed, so the real reason this fails is a refused
    // connection, not a bound the build could not race.
    try testing.expectError(error.CouldNotConnect, client.perform("http://127.0.0.1:1/", .{}, &d));
    try testing.expectEqualStrings(connect_timeout_degraded_message, d.message.?);
}

test "a truncated body surfaces as PartialFile through the decorator stack, not a generic read failure" {
    // The decorator stack sits between `Response.body` and the engine's
    // own truncation check (`engine.Exchange.check`). This proves that
    // stacking does not swallow it: a short body still resolves to the
    // same named fault it would without the stack in the way.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhi",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectError(error.ReadFailed, response.body.allocRemaining(testing.allocator, .unlimited));

    var d: Diagnostics = .{};
    try testing.expectEqual(zurl_core.Error.PartialFile, client.resolveBodyError(&d));
    try testing.expect(d.message != null);
}

test "a body larger than max_size fails the transfer as FileSizeExceeded" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .max_size = 3 }, null);
    try testing.expectError(
        error.ReadFailed,
        response.body.allocRemaining(testing.allocator, .unlimited),
    );

    var d: Diagnostics = .{};
    try testing.expectEqual(zurl_core.Error.FileSizeExceeded, client.resolveBodyError(&d));
}

// The two tests below are the reason Task 9 exists: a digest challenge is
// untested plumbing until something actually retries against it.

test "a 401 with a digest challenge is retried once and then succeeds" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:secret@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    // A single connection would mean the retry never fired: the script's
    // first entry is a 401, so a status of 200 here is only reachable by
    // opening a second connection with a real `Authorization` header.
    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("ok", contents);
}

test "--digest sends no password until the server has asked for Digest" {
    // **The defect the flag exists to close.** With the default mode the
    // first request already carries `Authorization: Basic`, which is the
    // password in reversible base64 on a request nobody asked it of. A
    // user who names `--digest` asked for a scheme where the password
    // never travels, so nothing may go out before the challenge does.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:secret@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .auth_mode = .digest }, null);
    try testing.expectEqual(@as(u16, 200), response.status);

    // The first request carried no credential at all.
    const first = server.requestHead(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(first));
    try testing.expect(std.mem.indexOf(u8, first, "secret") == null);

    // The second carried exactly one, and it is a Digest one, so the
    // password itself never reached the wire.
    const second = server.requestHead(1) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(second));
    try testing.expect(std.mem.indexOf(u8, second, "Digest ") != null);
    try testing.expect(std.mem.indexOf(u8, second, "secret") == null);
}

test "--digest answers no Basic challenge, and says why" {
    // A server that offers `Basic` and nothing else gets no answer. That
    // is not a gap: answering it would send the password the flag exists
    // to keep off the wire, which is the same rule `--proxy-digest`
    // follows. The `401` goes back as it came, and recovery is never
    // silent, so `Diagnostics` says what happened.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"test\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:secret@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{ .auth_mode = .digest }, &d);
    try testing.expectEqual(@as(u16, 401), response.status);
    try testing.expectEqualStrings(challenge_scheme_refused_message, d.message.?);

    // One request went out, and it carried nothing.
    try testing.expectEqual(@as(usize, 1), server.accepts());
    const first = server.requestHead(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(first));
    try testing.expect(std.mem.indexOf(u8, first, "secret") == null);
}

test "--anyauth sends nothing first and then answers whatever the server named" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"test\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:secret@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .auth_mode = .any }, null);
    try testing.expectEqual(@as(u16, 200), response.status);

    const first = server.requestHead(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(first));
    const second = server.requestHead(1) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(second));
    try testing.expect(std.mem.indexOf(u8, second, "Basic ") != null);
}

test "the default mode still sends Basic with the first request" {
    // The behaviour every transfer before these flags had, and the one
    // `--basic` names. It must not have moved.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:secret@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);

    const first = server.requestHead(0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(first));
    try testing.expect(std.mem.indexOf(u8, first, "Basic ") != null);
}

test "a second 401 after retrying is not retried again" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:secret@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    // The server script holds exactly two responses. A third retry would
    // try to open a third connection, which nothing is listening to
    // answer, and this test would hang rather than fail cleanly. Reaching
    // this assertion at all is what proves the loop stopped.
    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 401), response.status);
}

test "the digest retry carries one authorization header, and no base64 of the password" {
    // The point of a `Digest` response is that the password never
    // travels. `std.http.Client` used to add its own
    // `authorization: Basic base64(user:password)` from the url's
    // userinfo, so the retry carried the password in reversible base64
    // beside the digest response, and a server reading the first
    // `Authorization` header saw `Basic` and ignored the digest.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const first = server.requestHead(0).?;
    const retry = server.requestHead(1).?;

    // "Ym9iOmh1bnRlcjI=" is base64("bob:hunter2").
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(first));
    try testing.expect(std.mem.indexOf(u8, first, "authorization: Basic Ym9iOmh1bnRlcjI=") != null);

    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(retry));
    try testing.expect(std.mem.indexOf(u8, retry, "authorization: Digest ") != null);
    try testing.expect(std.mem.indexOf(u8, retry, "Ym9iOmh1bnRlcjI=") == null);
    try testing.expect(std.mem.indexOf(u8, retry, "hunter2") == null);
}

test "a credential does not follow a redirect to another origin" {
    // Two loopback host names, so this is a real origin change by any
    // rule, a rule that compares host names and not ports included. The
    // credential used to ride the ordinary headers, which every hop of a
    // chain carries, so the password arrived at an origin the caller never
    // named.
    var landing: test_server.TestServer = undefined;
    try landing.startOn("127.0.0.2", &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nlanded",
    });
    defer landing.stop();

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:{d}/landed\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        .{landing.port()},
    );
    defer testing.allocator.free(redirect);

    // Two entries: the first answers the request that carries the
    // credential, the second answers the credential-free resend that
    // follows the chain.
    var origin: test_server.TestServer = undefined;
    try origin.startOn("127.0.0.1", &.{ redirect, redirect });
    defer origin.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/start",
        .{origin.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("landed", contents);

    // The origin the caller named gets the credential.
    const first = origin.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(first));
    try testing.expect(std.mem.indexOf(u8, first, "Ym9iOmh1bnRlcjI=") != null);

    // The resend that follows the chain carries none, so nothing past the
    // first hop can see the credential.
    const resend = origin.requestHead(1).?;
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(resend));

    // The other origin is what this test exists for.
    const landed = landing.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, landed, "/landed") != null);
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(landed));
    try testing.expect(std.mem.indexOf(u8, landed, "Ym9iOmh1bnRlcjI=") == null);
    try testing.expect(std.mem.indexOf(u8, landed, "hunter2") == null);
}

test "options.redirects = .unfollowed reports the 3xx status instead of following, matching curl with no -L" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .redirects = .unfollowed }, null);
    try testing.expectEqual(@as(u16, 302), response.status);

    // Only one request went out. A followed redirect would have sent a
    // second one to `/elsewhere`.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "options.redirects = .{ .follow = n } reaches the final body, matching curl with -L" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .redirects = .{ .follow = 10 } }, null);
    try testing.expectEqual(@as(u16, 200), response.status);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "a credential still reaches a request that answers without a redirect" {
    // The guard above must not cost an ordinary authenticated transfer its
    // credential, and must not cost it a second request either.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(server.requestHead(0).?));
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

/// A token the length of the ones a binary cache and a forge hand out.
/// The netrc file that broke zurl held four of about this size.
const long_token_len = 1200;

test "a netrc token of 1200 characters authenticates and reaches the wire whole" {
    // The defect: `authorize.apply` kept a 256-byte buffer for a decoded
    // credential and a 2048-byte buffer for the value it built, so a
    // token of this length answered `error.NoSpaceLeft`, which reached
    // the user as `InvalidUrl`, exit 3. curl sends the same credential
    // and gets a 200.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/nix-cache-info", .{server.port()});
    defer testing.allocator.free(url_text);

    const token = "t" ** long_token_len;
    const netrc_text = try std.fmt.allocPrint(
        testing.allocator,
        "machine 127.0.0.1 login cache password {s}\n",
        .{token},
    );
    defer testing.allocator.free(netrc_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{ .netrc_text = netrc_text }, &d);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    // Exactly one credential header, holding exactly the value the
    // credential builds. A truncated token would still be one header, so
    // the value itself has to be compared.
    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(head));

    const expected_len = zurl_core.auth.basicValueSize(.{ .user = "cache", .password = token });
    const expected_buf = try testing.allocator.alloc(u8, expected_len);
    defer testing.allocator.free(expected_buf);
    const expected = try zurl_core.auth.basicValue(expected_buf, .{ .user = "cache", .password = token });
    try testing.expect(std.mem.indexOf(u8, head, expected) != null);
}

/// Builds a credential whose `Basic` value cannot fit one `Authorization`
/// header line, and gives back the netrc text that carries it.
///
/// The password length comes from `authorization_line_len_max`, so this
/// stays oversize if the bound ever moves. The marker at the front is
/// what a test looks for when it proves no message holds the secret.
const oversize_marker = "SUPERSECRETTOKENMARKER";

fn oversizeNetrc(gpa: Allocator) ![]u8 {
    const padding = try gpa.alloc(u8, authorization_line_len_max);
    defer gpa.free(padding);
    @memset(padding, 'x');
    return std.fmt.allocPrint(
        gpa,
        "machine 127.0.0.1 login cache password {s}{s}\n",
        .{ oversize_marker, padding },
    );
}

test "a credential too long for a header line is its own error and not a bad url" {
    // The second defect: `NoSpaceLeft` mapped to `InvalidUrl`, exit 3.
    // The url here is well formed, and the fault is a netrc credential, so
    // a user reading "malformed url" looks at the wrong thing. The new
    // name carries curl's own code for an over-long credential.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const netrc_text = try oversizeNetrc(testing.allocator);
    defer testing.allocator.free(netrc_text);

    var d: Diagnostics = .{};
    try testing.expectError(
        error.CredentialTooLarge,
        client.perform(url_text, .{ .netrc_text = netrc_text }, &d),
    );
    try testing.expectEqual(@as(u32, 43), d.curl_code.?);
    try testing.expect(zurl_core.errors.curlCode(error.CredentialTooLarge) != zurl_core.errors.curlCode(error.InvalidUrl));

    // The refusal comes before any connect, so the server saw nothing and
    // the secret never left this process.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "the oversize credential message names the source and holds no secret" {
    // A diagnostic is printed, logged, and pasted into bug reports. It
    // names which of the three credential sources was too long, and how
    // long the header line would be, and nothing else.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const padding = try testing.allocator.alloc(u8, authorization_line_len_max);
    defer testing.allocator.free(padding);
    @memset(padding, 'x');
    const secret = try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{ oversize_marker, padding });
    defer testing.allocator.free(secret);

    const netrc_text = try std.fmt.allocPrint(
        testing.allocator,
        "machine example.com login cache password {s}\n",
        .{secret},
    );
    defer testing.allocator.free(netrc_text);

    const url_userinfo = try std.fmt.allocPrint(
        testing.allocator,
        "http://cache:{s}@example.com/",
        .{secret},
    );
    defer testing.allocator.free(url_userinfo);

    const Case = struct {
        options: Transfer.Options,
        url: []const u8,
        names: []const u8,
    };
    const cases = [_]Case{
        .{
            .options = .{ .netrc_text = netrc_text },
            .url = "http://example.com/",
            .names = "the netrc file",
        },
        .{
            .options = .{ .credentials = .{ .user = "cache", .password = secret } },
            .url = "http://example.com/",
            .names = "the -u option",
        },
        .{
            .options = .{},
            .url = url_userinfo,
            .names = "the user name and password in the url",
        },
    };

    for (cases) |case| {
        var d: Diagnostics = .{};
        try testing.expectError(error.CredentialTooLarge, client.perform(case.url, case.options, &d));
        const message = d.message.?;
        try testing.expect(std.mem.indexOf(u8, message, case.names) != null);
        // Not the secret, and not one recognisable piece of it.
        try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, message, oversize_marker));
        try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, message, "xxxxxxxx"));
        // The url in a diagnostic is masked, so the userinfo case does
        // not leak the password through it either.
        if (d.url()) |masked| {
            try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, masked, oversize_marker));
        }
    }
}

test "the header line bound comes from the engine and not from a number written here" {
    // A constant chosen here is the mistake this fix removes. The bound
    // is the longest header line the engine reads, which is what curl's
    // own `CURL_MAX_HTTP_HEADER` buffer holds.
    try testing.expectEqual(zurl_http.h1.head_field_len_max - 1, authorization_line_len_max);
    try testing.expectEqual(@as(usize, "authorization: \r\n".len), authorization_line_overhead);

    // A 1200-character token is far inside the bound, so nothing refuses
    // the credential this defect was reported for.
    const value_len = zurl_core.auth.basicValueLen(.{ .user = "cache", .password = "t" ** long_token_len });
    try testing.expect(!authorizationOversize("x" ** 8));
    try testing.expect(authorization_line_overhead + value_len < authorization_line_len_max);
}

test "a caller's authorization header wins over the url userinfo" {
    // curl sends the header the caller wrote and builds none of its own.
    // zurl used to send both, its own first, so a server honoured the
    // password and threw away the token the caller asked for.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{.{ .name = "Authorization", .value = "Bearer caller-token" }};
    const response = try client.perform(url_text, .{ .headers = &headers }, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(head));
    try testing.expect(std.mem.indexOf(u8, head, "Bearer caller-token") != null);
    // "Ym9iOmh1bnRlcjI=" is base64("bob:hunter2").
    try testing.expect(std.mem.indexOf(u8, head, "Ym9iOmh1bnRlcjI=") == null);
    try testing.expect(std.mem.indexOf(u8, head, "hunter2") == null);
}

test "a caller's authorization header does not follow a redirect to another origin" {
    // The caller's header used to ride `extra_headers`, which `std` carries
    // to whichever host the chain reaches, so a bearer token arrived at an
    // origin the caller never named.
    var landing: test_server.TestServer = undefined;
    try landing.startOn("127.0.0.2", &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nlanded",
    });
    defer landing.stop();

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:{d}/landed\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        .{landing.port()},
    );
    defer testing.allocator.free(redirect);

    var origin: test_server.TestServer = undefined;
    try origin.startOn("127.0.0.1", &.{ redirect, redirect });
    defer origin.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/start",
        .{origin.port()},
    );
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{.{ .name = "Authorization", .value = "Bearer super-secret-token" }};
    const response = try client.perform(url_text, .{ .headers = &headers }, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    // The origin the caller named still gets the token, exactly once.
    const first = origin.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(first));
    try testing.expect(std.mem.indexOf(u8, first, "Bearer super-secret-token") != null);

    // The resend that follows the chain carries none.
    const resend = origin.requestHead(1).?;
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(resend));

    // The other origin is what this test exists for.
    const landed = landing.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, landed, "/landed") != null);
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(landed));
    try testing.expect(std.mem.indexOf(u8, landed, "super-secret-token") == null);
}

test "a caller's cookie header reaches the origin the url names" {
    // The rule that keeps a cookie inside one origin must not cost an
    // ordinary transfer the cookie it asked to send.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{.{ .name = "Cookie", .value = "session=super-secret-session" }};
    const response = try client.perform(url_text, .{ .headers = &headers }, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(head, "Cookie"));
    try testing.expect(std.mem.indexOf(u8, head, "session=super-secret-session") != null);
    // One request answered it. No resend, because nothing redirected.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "a caller's cookie header does not follow a redirect to another origin" {
    // curl keeps a `-H Cookie:` inside the origin the url names, exactly
    // as it keeps an `Authorization`. This header used to ride
    // `extra_headers`, which `std` writes again on every hop, so a session
    // cookie arrived at a host the caller never named.
    var landing: test_server.TestServer = undefined;
    try landing.startOn("127.0.0.2", &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nlanded",
    });
    defer landing.stop();

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:{d}/landed\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        .{landing.port()},
    );
    defer testing.allocator.free(redirect);

    var origin: test_server.TestServer = undefined;
    try origin.startOn("127.0.0.1", &.{ redirect, redirect });
    defer origin.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{origin.port()});
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{.{ .name = "Cookie", .value = "session=super-secret-session" }};
    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{ .headers = &headers }, &d);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("landed", contents);

    // The origin the caller named still gets the cookie, exactly once.
    const first = origin.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(first, "Cookie"));
    try testing.expect(std.mem.indexOf(u8, first, "session=super-secret-session") != null);

    // The resend that follows the chain carries none.
    const resend = origin.requestHead(1).?;
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(resend, "Cookie"));

    // The other origin is what this test exists for.
    const landed = landing.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, landed, "/landed") != null);
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(landed, "Cookie"));
    try testing.expect(std.mem.indexOf(u8, landed, "super-secret-session") == null);

    // A dropped secret is reported, never silent.
    try testing.expectEqualStrings(credential_withheld_message, d.message.?);
}

test "a port change is another origin, so a secret does not follow it" {
    // curl calls a redirect another origin when the host, the scheme, or
    // the port changes. `std.http.Client.Request.redirect` reads no port
    // at all, so a rule written on top of it would keep a secret here.
    // zurl compares nothing: it withholds every secret on each redirect it
    // follows, so a port change costs the secret like any other hop.
    var landing: test_server.TestServer = undefined;
    try landing.startOn("127.0.0.1", &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nlanded",
    });
    defer landing.stop();

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{d}/landed\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        .{landing.port()},
    );
    defer testing.allocator.free(redirect);

    var origin: test_server.TestServer = undefined;
    try origin.startOn("127.0.0.1", &.{ redirect, redirect });
    defer origin.stop();
    try testing.expect(origin.port() != landing.port());

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    // A url with userinfo beside the cookie, so both kinds of secret run
    // through the one rule in one transfer.
    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/start",
        .{origin.port()},
    );
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{.{ .name = "Cookie", .value = "session=super-secret-session" }};
    const response = try client.perform(url_text, .{ .headers = &headers }, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("landed", contents);

    const first = origin.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(first, "Cookie"));
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(first));

    const resend = origin.requestHead(1).?;
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(resend, "Cookie"));
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(resend));

    // The same host, another port: another origin, and it gets nothing.
    const landed = landing.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, landed, "/landed") != null);
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(landed, "Cookie"));
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(landed));
    try testing.expect(std.mem.indexOf(u8, landed, "super-secret-session") == null);
    try testing.expect(std.mem.indexOf(u8, landed, "Ym9iOmh1bnRlcjI=") == null);
}

test "a scheme change is another origin, so a secret does not follow it" {
    // The target port has no listener, so the redirect to `https` fails at
    // the connect. A plain test server there would read a TLS ClientHello
    // it cannot answer, and both sides would wait for the other forever.
    // What this test reads is the request the origin got, which is where
    // the secret either stops or does not.
    const closed_port = try test_server.closedPort("127.0.0.2");

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.2:{d}/landed\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        .{closed_port},
    );
    defer testing.allocator.free(redirect);

    var origin: test_server.TestServer = undefined;
    try origin.startOn("127.0.0.1", &.{ redirect, redirect });
    defer origin.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{origin.port()});
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{.{ .name = "Cookie", .value = "session=super-secret-session" }};
    // The chain ends at a port nothing answers, so the transfer fails.
    try testing.expectError(
        error.CouldNotConnect,
        client.perform(url_text, .{ .headers = &headers }, null),
    );

    // The origin the caller named got the cookie once.
    const first = origin.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(first, "Cookie"));

    // The resend that follows the chain into `https` carries none, so the
    // secret is already gone before the new scheme is reached.
    const resend = origin.requestHead(1).?;
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(resend, "Cookie"));
    try testing.expect(std.mem.indexOf(u8, resend, "super-secret-session") == null);
}

test "a redirect from http to https still gets trust roots at the tls hop" {
    // The scheme the caller names is not the scheme of every hop, so the
    // trust roots cannot depend on it. This chain starts on `http`, which
    // reads no certificate path at all, and lands on `https`, which needs
    // one.
    //
    // The target port has no listener, so the `https` hop fails at the
    // connect. That is enough: the roots load before the connect of the
    // hop that opens them.
    const closed_port = try test_server.closedPort("127.0.0.2");

    const redirect = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.2:{d}/landed\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        .{closed_port},
    );
    defer testing.allocator.free(redirect);

    var origin: test_server.TestServer = undefined;
    try origin.startOn("127.0.0.1", &.{ redirect, redirect });
    defer origin.stop();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{origin.port()});
    defer testing.allocator.free(url_text);

    {
        var client: Client = .init(testing.allocator, testing.io);
        defer client.deinit();

        try testing.expectError(error.CouldNotConnect, client.perform(url_text, .{}, null));
        // A chain that stays on `http` leaves this at zero, which the
        // plain-http test above pins. So the one load counted here
        // happened at the `https` hop and nowhere earlier.
        try testing.expectEqual(@as(usize, 1), client.ca_load_count);
        try testing.expect(client.http.ca_bundle.map.count() > 0);
    }

    // The same chain with a certificate path that cannot be read. The
    // `https` hop reports the trust roots it did not get, where the run
    // above reported the connect. Only a hop that runs the load can tell
    // those two apart.
    //
    // `--cacert` names a file, so this is curl's 77
    // (CURLE_SSL_CACERT_BADFILE), not the 35 this test pinned before this
    // task gave a file source its own code.
    {
        var client: Client = .init(testing.allocator, testing.io);
        defer client.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(error.CaCertBadFile, client.perform(
            url_text,
            .{ .ca = .{ .cacert = "/nonexistent/zurl-test-ca.pem" } },
            &d,
        ));
        try testing.expectEqualStrings(
            "zurl did not read the certificate file /nonexistent/zurl-test-ca.pem: FileNotFound",
            d.message.?,
        );
    }
}

test "a proxy-authorization header is refused, and nothing goes on the wire" {
    // zurl connects to no proxy, so this header has no destination. It
    // used to travel to the origin server, and on to every host a redirect
    // named. curl keeps proxy headers apart with `--proxy-header`.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{
        .{ .name = "Proxy-Authorization", .value = "Basic super-secret-proxy-cred" },
    };
    var d: Diagnostics = .{};
    try testing.expectError(
        error.WriteError,
        client.perform(url_text, .{ .headers = &headers }, &d),
    );
    try testing.expectEqualStrings(proxy_authorization_refused_message, d.message.?);

    // The refusal comes before any connect, so the server saw nothing.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));

    // A field name has no case, so neither has the refusal.
    const lower = [_]std.http.Header{
        .{ .name = "proxy-authorization", .value = "Basic super-secret-proxy-cred" },
    };
    try testing.expectError(
        error.WriteError,
        client.perform(url_text, .{ .headers = &lower }, null),
    );
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "a framing header from the caller is refused, and nothing goes on the wire" {
    // `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, and
    // `Expect` are valid tokens with valid values, so they used to reach
    // the wire beside the engine's own copies. Two `Host` headers, or a
    // `Content-Length: 5` on a request with no body, lets a peer read one
    // request as two on a pooled connection.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const framing = [_]std.http.Header{
        .{ .name = "Host", .value = "evil.example" },
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Connection", .value = "close" },
        .{ .name = "Expect", .value = "100-continue" },
    };
    for (framing) |header| {
        const one = [_]std.http.Header{header};
        var d: Diagnostics = .{};
        try testing.expectError(
            error.WriteError,
            client.perform(url_text, .{ .headers = &one }, &d),
        );
        // The message names the header the caller wrote, the way the
        // proxy-header message names its own.
        try testing.expectEqualStrings(refusedHeaderMessage(header.name), d.message.?);
        var prefix_buf: [64]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, "zurl writes the {s} header", .{header.name});
        try testing.expect(std.mem.startsWith(u8, d.message.?, prefix));
    }

    // The refusal comes before any connect, so the server saw nothing.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "a CRLF in the user agent ends the transfer instead of injecting a header" {
    // `-A` fills this from the command line, so it is untrusted input. It
    // used to reach `std`'s `.override`, which writes the value with no
    // check at all, so `evil/1\r\nX-Injected: yes` put a second header on
    // the wire.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    try testing.expectError(
        error.WriteError,
        client.perform(url_text, .{ .user_agent = "evil/1\r\nX-Injected: yes" }, null),
    );

    // The refusal comes before any connect, so the server saw nothing.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "a body-bearing method runs the transfer instead of ending it" {
    // **This test replaces a refusal that is now false.** `Options.method`
    // used to end a transfer with `error.WriteError` for `POST`, `PUT`,
    // and `PATCH`, because no engine below could frame a request body.
    // `Options.body` frames one now, so each of those methods runs.
    //
    // The measurement, against curl 8.21.0 on a loopback listener:
    // `curl -X POST URL` with no data sends `POST /x HTTP/1.1` and no
    // framing header at all, and the peer answers it.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    for ([_]std.http.Method{ .POST, .PUT, .PATCH }, 0..) |method, index| {
        const response = try client.perform(url_text, .{ .method = method }, null);
        const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(contents);
        try testing.expectEqual(@as(u16, 200), response.status);

        var line_buffer: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buffer, "{s} / HTTP/1.1\r\n", .{@tagName(method)});
        const head = server.requestHead(index).?;
        try testing.expect(std.mem.startsWith(u8, head, line));
        // No body means no framing header, exactly as curl sends it.
        try testing.expectEqual(@as(usize, 0), test_server.TestServer.countHeaders(head, "content-length"));
        try testing.expectEqualStrings("", server.requestBody(index).?);
    }

    // A method with no request body still works on the same client.
    const response = try client.perform(url_text, .{ .method = .HEAD }, null);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expect(std.mem.startsWith(u8, server.requestHead(3).?, "HEAD / HTTP/1.1\r\n"));
}

test "the digest uri signs the query, not the path alone" {
    // The request line writes "path?query", so RFC 7616's `uri` parameter
    // must hold the same text. A response built from the path alone does
    // not match what the server computes, so digest failed against any
    // real server whenever the url had a query.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/dir/index.html?q=1",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const retry = server.requestHead(1).?;
    try testing.expect(std.mem.startsWith(u8, retry, "GET /dir/index.html?q=1 HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, retry, "uri=\"/dir/index.html?q=1\"") != null);

    // Recompute the response here, from MD5 alone, the way RFC 7616
    // section 3.4.1 defines it. This does not call `auth.digestValue`, so
    // it is a check of that code and not a restatement of it. The cnonce
    // is random per transfer, so it is read back from what was sent.
    const cnonce = try fieldFromHeader(retry, "cnonce=\"");
    const ha1 = md5Hex(&.{"bob:test:hunter2"});
    const ha2 = md5Hex(&.{"GET:/dir/index.html?q=1"});
    const expected = md5Hex(&.{ &ha1, ":abc123:00000001:", cnonce, ":auth:", &ha2 });

    const sent = try fieldFromHeader(retry, "response=\"");
    try testing.expectEqualStrings(&expected, sent);

    // The old value, built from the path alone, must not be what was sent.
    const wrong_ha2 = md5Hex(&.{"GET:/dir/index.html"});
    const wrong = md5Hex(&.{ &ha1, ":abc123:00000001:", cnonce, ":auth:", &wrong_ha2 });
    try testing.expect(!std.mem.eql(u8, &wrong, sent));
}

test "the request line and the digest uri hold the same escaped target" {
    // `zurl_core.url.parse` leaves the path and the query percent-encoded.
    // The engine used to tag both `.raw`, so `std.Uri` escaped the `%`
    // again and the request line read "/a%2520b/c" while the `uri`
    // parameter read "/a%20b/c". A server checks its own request line, so
    // it rejected both. The two must be one text.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/a%20b/c?x=%26y",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const retry = server.requestHead(1).?;

    // Both texts come off the wire, and are compared with each other. A
    // test that only checked each against a literal would still pass while
    // the two disagreed with the server.
    const target = try requestLineTarget(retry);
    const signed = try fieldFromHeader(retry, "uri=\"");
    try testing.expectEqualStrings(target, signed);
    try testing.expectEqualStrings("/a%20b/c?x=%26y", target);

    // The escape survives once, not twice.
    try testing.expect(std.mem.indexOf(u8, retry, "%2520") == null);

    const cnonce = try fieldFromHeader(retry, "cnonce=\"");
    const ha1 = md5Hex(&.{"bob:test:hunter2"});
    const ha2 = md5Hex(&.{ "GET:", target });
    const expected = md5Hex(&.{ &ha1, ":abc123:00000001:", cnonce, ":auth:", &ha2 });
    try testing.expectEqualStrings(&expected, try fieldFromHeader(retry, "response=\""));
}

test "a plain request line carries the escape once, whatever the credential" {
    // The double escape was a request-line defect first. It reaches every
    // transfer, not only one that signs a digest response.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/a%20b/c?x=%26y",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    try testing.expectEqualStrings("/a%20b/c?x=%26y", try requestLineTarget(server.requestHead(0).?));
}

test "a credential the engine withholds on a resend is reported, not dropped in silence" {
    // The engine keeps a credential inside the origin the url names, so a
    // redirect the caller asked to follow costs the credential. The
    // transfer used to end with no word of it, and a `401` at the end of
    // such a chain reads as a password the server refused.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/start",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{}, &d);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    try testing.expectEqualStrings(credential_withheld_message, d.message.?);

    // The resend really did travel without the credential. The message
    // must describe what happened, not stand in for it.
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(server.requestHead(1).?));
}

test "a transfer that keeps its credential reports nothing about withholding one" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{}, &d);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    try testing.expectEqual(@as(?[]const u8, null), d.message);
}

test "a 304 answer to an authenticated conditional GET reaches the caller" {
    // A `304` is a 3xx that no client follows. The engine used to resend
    // on any 3xx to get the credential off the chain, so the answer the
    // server gave was thrown away and the caller received a 200 and a body
    // instead of the 304 that said the copy was still good.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/cached",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{.{ .name = "If-None-Match", .value = "\"v1\"" }};
    const response = try client.perform(url_text, .{ .headers = &headers }, null);
    try testing.expectEqual(@as(u16, 304), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("", contents);

    // One request, and it carried the credential.
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(server.requestHead(0).?));
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "an oversize digest challenge beside a basic one is not answered with basic" {
    // The engine keeps a `Basic` value that fits and drops a `Digest`
    // value that does not. Answering the `Basic` challenge sends the
    // password in reversible base64 to a server that had offered a scheme
    // where the password never travels, and the length of a realm decided
    // which happened.
    const long_realm = "r" ** 1100;
    const challenge = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"small\"\r\n" ++
        "WWW-Authenticate: Digest realm=\"" ++ long_realm ++ "\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n";
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        challenge,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{}, &d);
    try testing.expectEqual(@as(u16, 401), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    // The challenge zurl could not read is reported, and no second
    // request went out.
    try testing.expectEqualStrings(challenge_oversize_message, d.message.?);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "an oversize basic challenge beside a digest one still gets a digest answer" {
    // The oversize flag must not cost a challenge that fits. Only the
    // dropped `Digest` case has to stop the exchange.
    const long_realm = "r" ** 1100;
    const challenge = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"" ++ long_realm ++ "\"\r\n" ++
        "WWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n";
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        challenge,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{}, &d);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const retry = server.requestHead(1).?;
    try testing.expect(std.mem.indexOf(u8, retry, "authorization: Digest ") != null);
    try testing.expect(std.mem.indexOf(u8, retry, "Ym9iOmh1bnRlcjI=") == null);
    // A dropped header is still a recovered fault, and still reported.
    try testing.expectEqualStrings(challenge_oversize_message, d.message.?);
}

/// The request target in `head`'s request line: the text between the
/// method and the HTTP version.
///
/// A test compares this with the digest `uri` parameter beside it. RFC
/// 7616 signs the request target, so the two texts must be one text, and
/// reading both off the wire is the only way to know that they are.
fn requestLineTarget(head: []const u8) ![]const u8 {
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse return error.TestUnexpectedResult;
    const line = head[0..line_end];
    const after_method = std.mem.indexOfScalar(u8, line, ' ') orelse return error.TestUnexpectedResult;
    const rest = line[after_method + 1 ..];
    const before_version = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.TestUnexpectedResult;
    return rest[0..before_version];
}

/// The value of a quoted digest parameter in `head`, between `prefix` and
/// the next quote. A test helper, so a missing parameter is a test failure
/// and not a silent empty string.
fn fieldFromHeader(head: []const u8, prefix: []const u8) ![]const u8 {
    const start = std.mem.indexOf(u8, head, prefix) orelse return error.TestUnexpectedResult;
    const rest = head[start + prefix.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return error.TestUnexpectedResult;
    return rest[0..end];
}

/// The lower-case hex MD5 of `parts` joined in order. A test helper that
/// leans on `std.crypto` alone, so it can check `zurl_core.auth`'s output
/// rather than repeat it.
fn md5Hex(parts: []const []const u8) [32]u8 {
    var hash: std.crypto.hash.Md5 = .init(.{});
    for (parts) |part| hash.update(part);
    var digest: [16]u8 = undefined;
    hash.final(&digest);
    var out: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&digest}) catch unreachable; // out is sized to fit exactly.
    return out;
}

test "requestTarget joins the path and the query the way the request line does" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("/", try requestTarget(&buf, try zurl_core.url.parse("http://h/")));
    try testing.expectEqualStrings(
        "/dir/index.html?q=1",
        try requestTarget(&buf, try zurl_core.url.parse("http://h/dir/index.html?q=1")),
    );
    // An empty query still writes the "?", the same as the request line.
    try testing.expectEqualStrings("/p?", try requestTarget(&buf, try zurl_core.url.parse("http://h/p?")));
    // A fragment never reaches the wire, so it never reaches the digest.
    try testing.expectEqualStrings("/p?a=b", try requestTarget(&buf, try zurl_core.url.parse("http://h/p?a=b#frag")));

    var small: [3]u8 = undefined;
    try testing.expectError(
        error.NoSpaceLeft,
        requestTarget(&small, try zurl_core.url.parse("http://h/dir/index.html?q=1")),
    );
}

test "a malformed challenge is reported instead of answered with silence" {
    // `Negotiate` is a scheme zurl does not build, so `selectChallenge`
    // gives back nothing. The transfer keeps the 401, and the reason must
    // reach the caller.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{}, &d);
    try testing.expectEqual(@as(u16, 401), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    try testing.expectEqualStrings(challenge_unreadable_message, d.message.?);
}

test "a challenge too long for the engine is reported, not read as no challenge" {
    // The engine drops a `WWW-Authenticate` value it cannot hold, and used
    // to report the same `null` a response with no challenge reports. A
    // caller then saw a bare 401 with no reason for it.
    const realm = "r" ** 2048;
    const response_text = try std.fmt.allocPrint(
        testing.allocator,
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{s}\", nonce=\"n\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        .{realm},
    );
    defer testing.allocator.free(response_text);

    var server: test_server.TestServer = undefined;
    try server.start(&.{response_text});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{}, &d);
    try testing.expectEqual(@as(u16, 401), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    try testing.expectEqualStrings(challenge_oversize_message, d.message.?);
}

test "a server that offers basic before digest gets a digest answer" {
    // Answering `Basic` here would put the password on the wire in
    // reversible base64, against a server that had offered a scheme where
    // the password never travels.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"first\"\r\n" ++
            "WWW-Authenticate: Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const retry = server.requestHead(1).?;
    try testing.expect(std.mem.indexOf(u8, retry, "authorization: Digest ") != null);
    try testing.expect(std.mem.indexOf(u8, retry, "realm=\"test\"") != null);
    try testing.expect(std.mem.indexOf(u8, retry, "Ym9iOmh1bnRlcjI=") == null);
}

test "a single header that lists basic before digest still gets a digest answer" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\n" ++
            "WWW-Authenticate: Basic realm=\"first\", Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const retry = server.requestHead(1).?;
    try testing.expect(std.mem.indexOf(u8, retry, "authorization: Digest ") != null);
    try testing.expect(std.mem.indexOf(u8, retry, "Ym9iOmh1bnRlcjI=") == null);
}

test "nextNc starts at 1 for a new nonce and increments when the nonce repeats" {
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    try testing.expectEqual(@as(u32, 1), client.nextNc("nonce-a"));
    try testing.expectEqual(@as(u32, 2), client.nextNc("nonce-a"));
    try testing.expectEqual(@as(u32, 3), client.nextNc("nonce-a"));
    try testing.expectEqual(@as(u32, 1), client.nextNc("nonce-b"));
}

test "freshCnonce produces a different value on each call" {
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var buf1: [cnonce_hex_len]u8 = undefined;
    var buf2: [cnonce_hex_len]u8 = undefined;
    const a = client.freshCnonce(&buf1);
    const b = client.freshCnonce(&buf2);

    try testing.expectEqual(@as(usize, cnonce_hex_len), a.len);
    try testing.expect(!std.mem.eql(u8, a, b));
}

test "a url with userinfo reaches diagnostics with its password redacted" {
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.UnsupportedProtocol,
        client.perform("ftp://alice:s3cret@127.0.0.1/file", .{}, &d),
    );
    try testing.expectEqualStrings("ftp://alice:***@127.0.0.1/file", d.url().?);
    try testing.expect(std.mem.indexOf(u8, d.url().?, "s3cret") == null);
}

test "a second transfer's diagnostics does not overwrite an earlier one" {
    // The masked url used to live in one buffer per `Client`, so two
    // `perform` calls aliased it: the first `Diagnostics.url` read back as
    // the tail of the second url spliced onto the head of the first. Each
    // `Diagnostics` now owns the url it recorded.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var first: Diagnostics = .{};
    try testing.expectError(
        error.UnsupportedProtocol,
        client.perform("ftp://bob:hunter2@example.com/first", .{}, &first),
    );
    try testing.expectEqualStrings("ftp://bob:***@example.com/first", first.url().?);

    var second: Diagnostics = .{};
    try testing.expectError(
        error.UnsupportedProtocol,
        client.perform("ftp://alice:s3cret@other.example.com/a/much/longer/second/path", .{}, &second),
    );

    // Both must still read back whole, and neither may hold the other's
    // password.
    try testing.expectEqualStrings("ftp://bob:***@example.com/first", first.url().?);
    try testing.expectEqualStrings(
        "ftp://alice:***@other.example.com/a/much/longer/second/path",
        second.url().?,
    );
    try testing.expect(std.mem.indexOf(u8, first.url().?, "hunter2") == null);
    try testing.expect(std.mem.indexOf(u8, first.url().?, "s3cret") == null);
    try testing.expect(std.mem.indexOf(u8, second.url().?, "s3cret") == null);
}

test "a CRLF in the url path ends the transfer instead of injecting a header" {
    // `zurl_core.url.parse` used to accept a control byte in the path, and
    // `h1.zig` passes the path to `std` as `.percent_encoded`, which writes
    // it verbatim. So "/a\r\nX-Path-Injected: yes" reached the wire as a
    // request line plus a header of the url's choosing. For a caller like
    // `fix`, the url comes from a lockfile or a manifest.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/a\r\nX-Path-Injected: yes",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, client.perform(url_text, .{}, &d));

    // The refusal comes before any connect, so the server saw nothing.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "a redirect target that carries a control byte ends the transfer" {
    // Reproduced through `perform` with default options, because
    // `redirects` defaults to following. The server answered
    // `Location: /a\nX-Injected-By-Server: yes`, and the second connection
    // received a request line plus a header of the server's choosing.
    // `perform` returned 200, with no error and no diagnostic.
    // **A NUL ends the transfer one step earlier than the other two, and
    // under another name.** The engine refuses a head carrying a NUL
    // octet before it reads a `location` out of it, per
    // `engine.refuseNulInHead`, which all three engines now ask. curl
    // 8.21.0 answers such a response with exit 8 and this build answers
    // `WeirdServerReply`, the name that carries 8. A carriage return and a
    // line feed reach the `location` check instead, which is `InvalidUrl`.
    //
    // Either way no second request goes out, which is what this test is
    // really for.
    const Case = struct { control: []const u8, want: anyerror };
    const cases = [_]Case{
        .{ .control = "\n", .want = error.InvalidUrl },
        .{ .control = "\r", .want = error.InvalidUrl },
        .{ .control = "\x00", .want = error.WeirdServerReply },
    };
    var buf: [256]u8 = undefined;

    for (cases) |case| {
        const control = case.control;
        const redirect = try std.fmt.bufPrint(
            &buf,
            "HTTP/1.1 302 Found\r\nLocation: /a{s}X-Injected-By-Server: yes\r\n" ++
                "Content-Length: 0\r\nConnection: close\r\n\r\n",
            .{control},
        );

        var server: test_server.TestServer = undefined;
        try server.start(&.{
            redirect,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        });
        defer server.stop();

        var client: Client = .init(testing.allocator, testing.io);
        defer client.deinit();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
        defer testing.allocator.free(url_text);

        var d: Diagnostics = .{};
        try testing.expectError(case.want, client.perform(url_text, .{}, &d));
        try testing.expectEqualStrings("127.0.0.1", d.host.?);
        try testing.expect(d.curl_code != null);

        // Nothing carried the injected line to a peer.
        try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
    }
}

test "an empty user agent omits the header instead of sending a bare one" {
    // curl with `-A ""` sends no `User-Agent` at all. zurl wrote
    // `user-agent: ` with nothing after it.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .user_agent = "" }, null);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "user-agent:") == null);
}

test "a raw space in the url path ends the transfer instead of splitting the request line" {
    // `hasControlByte` stopped one byte short of 0x20, so the url
    // `http://127.0.0.1:33029/a b HTTP/1.1` reached the wire as
    // `GET /a b HTTP/1.1 HTTP/1.1`: the url chose the version token.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/a b HTTP/1.1",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, client.perform(url_text, .{}, &d));

    // The refusal comes before any connect, so the server saw nothing.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "a percent-encoded space still reaches the wire escaped" {
    // The guard above must not cost a url that names a resource with a
    // space in its name. curl encodes the space; zurl sends what it read.
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/a%20b", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    try testing.expect(std.mem.startsWith(u8, server.requestHead(0).?, "GET /a%20b HTTP/1.1\r\n"));
}

test "a caller reads Content-Type off the response" {
    // This is what `-w %{content_type}` needs. Nothing carried it before.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n" ++
            "Content-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    try testing.expectEqualStrings("application/json; charset=utf-8", response.header("Content-Type").?);
    try testing.expectEqualStrings("application/json; charset=utf-8", response.header("content-type").?);
    try testing.expect(!response.headers_oversize);

    // The body still reads after the head has been looked at.
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("ok", contents);
}

test "the effective url is the url the caller named when nothing redirected" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/a?b=c", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{}, null);
    // Byte for byte the text the caller gave, which is what curl 8.21.0
    // reports for `%{url_effective}` on a transfer that followed nothing.
    try testing.expectEqualStrings(url_text, response.effective_url);
}

test "the effective url is the final hop after a redirect chain" {
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /one\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /two?q=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .redirects = .{ .follow = 5 } }, null);
    const want = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/two?q=1", .{server.port()});
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, response.effective_url);
}

test "the response headers hold every hop of a followed redirect" {
    var server: test_server.TestServer = undefined;
    const first = "HTTP/1.1 302 Found\r\nLocation: /body\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    try server.start(&.{
        first,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);

    const response = try client.perform(url_text, .{ .redirects = .{ .follow = 2 } }, null);
    const second = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\n";
    try testing.expectEqualStrings(first ++ second, response.headers.?);
    try testing.expectEqualStrings(second, response.final_headers.?);
    // The lookup reads the final block, so it answers for the body that
    // arrived and not for the redirect that pointed at it.
    try testing.expectEqualStrings("text/plain", response.header("Content-Type").?);
}

test "the response headers belong to the client, and the next perform takes them back" {
    // The lifetime rule, pinned. `Response.headers` borrows memory the
    // `Client` and its engine own, exactly as `Response.body` does, so a
    // caller must read it before the next `perform`.
    //
    // This is what makes the rule safe to state: the next `perform`
    // overwrites the text, it does not free it. A caller that breaks the
    // rule reads the wrong headers, which a test can see. It does not read
    // memory that has gone away, which no test could look at.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nX-Which: first\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        "HTTP/1.1 404 Not Found\r\nX-Which: second\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);

    const first = try client.perform(url_text, .{}, null);
    try testing.expectEqualStrings("first", first.header("X-Which").?);
    const kept = first.headers.?;

    // The second `perform` closes the first exchange and opens another.
    const second = try client.perform(url_text, .{}, null);
    try testing.expectEqualStrings("second", second.header("X-Which").?);

    // The text the first response pointed at now describes the second
    // response. The slice is still readable, and it is no longer an
    // answer about the transfer that handed it out.
    try testing.expect(std.mem.indexOf(u8, kept, "X-Which: first") == null);
    try testing.expect(std.mem.indexOf(u8, kept, "404 Not Found") != null);
}

test "a registered protocol that reports no head still reports the url the caller named" {
    // The defaults on `Response`: a protocol that fills none of the head
    // fields says so, and `perform` still answers the effective url,
    // because only `perform` has the url text.
    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    var body_reader: std.Io.Reader = .fixed("shadowed!");
    const vtable: protocol.Protocol.VTable = .{ .perform = struct {
        fn perform(
            ptr: ?*anyopaque,
            c: *Client,
            url: zurl_core.Url,
            options: Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Response {
            _ = c;
            _ = url;
            _ = options;
            _ = d;
            const reader: *std.Io.Reader = @ptrCast(@alignCast(ptr.?));
            return .{ .status = 200, .content_length = 9, .transfer_encoding = .none, .body = reader };
        }
    }.perform };
    try client.registerProtocol(.{
        .scheme = "http",
        .default_port = 80,
        .ptr = &body_reader,
        .vtable = &vtable,
    });

    const response = try client.perform("http://127.0.0.1:1/x", .{}, null);
    try testing.expectEqual(@as(?[]const u8, null), response.headers);
    try testing.expectEqual(@as(?[]const u8, null), response.final_headers);
    try testing.expect(!response.headers_oversize);
    try testing.expectEqualStrings("http://127.0.0.1:1/x", response.effective_url);
}

test "a challenge from a redirect target is answered at that target, not at the url the caller named" {
    // Measured against curl 8.21.0. `/start` answers `302` to `/final`,
    // `/final` answers `401 Digest`, and `curl -L --location-trusted
    // --digest -u alice:secret` sent its second request to `/final` with
    // `uri="/final"`. It did not go back to `/start`.
    //
    // zurl retried `url`, the url the caller named. That is wrong twice:
    // the digest signs a target no server would accept against the
    // request line it arrives on, and a digest built under the realm and
    // the nonce the last hop chose goes back to a hop that issued no
    // challenge at all.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"hop\", nonce=\"n1\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/start",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    // `--location-trusted`, so the credential is permitted to reach the
    // hop. Without it the challenge is not answered at all, which the
    // test below pins.
    const response = try client.perform(url_text, .{
        .auth_mode = .digest,
        .location_trusted = true,
        .credentials = .{ .user = "alice", .password = "secret" },
    }, null);
    try testing.expectEqual(@as(u16, 200), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("ok", contents);

    // Three requests: the chain, then the answer to the challenge.
    const answer = server.requestHead(2) orelse return error.TestUnexpectedResult;
    try testing.expect(std.mem.startsWith(u8, answer, "GET /final "));
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(answer));
    // The digest signs the target the request line carries, which RFC
    // 7616 section 3.4 asks of it.
    try testing.expect(std.mem.indexOf(u8, answer, "uri=\"/final\"") != null);
    try testing.expect(std.mem.indexOf(u8, answer, "uri=\"/start\"") == null);
    try testing.expect(std.mem.indexOf(u8, answer, "secret") == null);

    // And the hop is what the caller is told the body came from.
    try testing.expect(std.mem.endsWith(u8, response.effective_url, "/final"));
}

test "a challenge from a redirect target the credential may not reach is not answered" {
    // The mirror of the rule above, and the one that holds the secret in.
    // The engine resends every hop past the first with the secrets
    // dropped, so the hop that issued this challenge may not carry the
    // credential. Answering it would either send the credential there or
    // send a digest built under that hop's realm and nonce back to the
    // first hop. Both give a credential to the wrong party.
    //
    // Measured: `curl -L --digest -u alice:secret` over the same chain
    // sent one request to each url and no `Authorization` on either.
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"hop\", nonce=\"n1\", qop=\"auth\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var client: Client = .init(testing.allocator, testing.io);
    defer client.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/start",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    var d: Diagnostics = .{};
    const response = try client.perform(url_text, .{
        .auth_mode = .digest,
        .credentials = .{ .user = "alice", .password = "secret" },
    }, &d);
    try testing.expectEqual(@as(u16, 401), response.status);
    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    // Recovery is never silent: the caller is told why the 401 went back
    // unanswered.
    try testing.expectEqualStrings(challenge_redirect_untrusted_message, d.message.?);

    // Two requests and no third. Neither carried a credential.
    try testing.expect(server.requestHead(2) == null);
    for ([_]usize{ 0, 1 }) |index| {
        const head = server.requestHead(index) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(head));
        try testing.expect(std.mem.indexOf(u8, head, "secret") == null);
    }
}
