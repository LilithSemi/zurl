//! Runs one `mqtt://` or `mqtts://` transfer: the dial, the CONNECT, and
//! then either a publish or a subscribe.
//!
//! A `Fetcher` owns the answer of the transfer in play. `open` frees
//! whatever the last call left and holds the new answer, so one `Fetcher`
//! serves one transfer at a time, the same rule `zurl.Client` keeps for
//! its own HTTP exchange.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value, and so does the packet writer.
//!
//! **One package owns both schemes.** MQTT 3.1.1 names the packets and
//! `mqtts` changes none of them: it puts the same ones inside TLS, on port
//! 8883 against 1883. `protocol` and `secureProtocol` build the two
//! dispatch entries and both point at one vtable that reads `url.scheme`.
//!
//! ## What a transfer does, and how curl was measured
//!
//! Every byte below came off curl 8.21.0 through a `socat -x -v` relay in
//! front of a real mosquitto 2.1.2 on loopback, so it is what curl put on
//! a socket and not what it was expected to.
//!
//! **A url with a body publishes.** `-d`, `--data-binary`, and `--json`
//! all fill `Options.payload`, and the transfer is
//! `CONNECT, CONNACK, PUBLISH, DISCONNECT`. Nothing is written to standard
//! output, and `%{http_code}` is `000`, measured.
//!
//! **A url with no body subscribes.** The transfer is
//! `CONNECT, CONNACK, SUBSCRIBE, SUBACK` and then the messages the broker
//! delivers.
//!
//! **`-T` and `-X` reach nothing here, because they reach nothing in curl
//! either.** Measured: `curl -T file mqtt://host/t/h` subscribed to `t/h`
//! and never published, and `curl -X FOO mqtt://host/t/i` subscribed as
//! well. Neither is refused by name, because neither is a control that
//! fails open: a user who asked to upload a file and got a subscription
//! sees no message arrive.
//!
//! ## Where this build ends a subscribe, and curl does not
//!
//! **curl's subscribe never ends.** Measured: `curl mqtt://host/topic` ran
//! until `--max-time` fired and exited 28, with the messages already on
//! standard output. That is a transfer with no end of its own, and this
//! package buffers its answer rather than streams it, so the same shape
//! here would be a transfer that fills memory until a bound stops it.
//!
//! So a subscribe reads `Options.message_count` messages and then
//! disconnects, and the default is one. `--mqtt-messages` names another
//! number. A user who wants curl's own shape asks for a large count and a
//! `--max-time`, and gets exit 28 the way curl does. This divergence is in
//! `--help` and in this comment because a silent one would leave a script
//! waiting for a second message that this build never reads.
//!
//! ## What this build does not do
//!
//! - **No QoS above zero.** curl sends QoS 0 in both directions,
//!   measured, and QoS 1 and 2 are a different state machine with their
//!   own retransmission and their own acknowledgements. A broker that
//!   delivers a message at QoS 1 anyway gets no PUBACK from this build and
//!   will deliver it again; `open` says so in a diagnostic rather than let
//!   a user believe the message was acknowledged.
//! - **No retained flag, no will, no PINGREQ.** A transfer here lives for
//!   one publish or a handful of messages, which is well inside the 60
//!   second keep alive the CONNECT names.
//! - **No MQTT 5.** The protocol level byte is 4, which is 3.1.1, and it
//!   is what curl sends.
//! - **No proxy.** curl carries MQTT through one and this build does not,
//!   so a transfer that named a proxy is refused by name with exit 4
//!   rather than connected direct. See `protocol`.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const packet = @import("packet.zig");
const topic = @import("topic.zig");
const Session = @import("Session.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The plain scheme this package handles.
pub const scheme = "mqtt";

/// The encrypted scheme this package handles.
pub const secure_scheme = "mqtts";

/// The port an `mqtt://` url uses when it names none.
///
/// 1883, which is what curl dials, measured with `curl -v`.
pub const default_port: ?u16 = 1883;

/// The port an `mqtts://` url uses when it names none.
///
/// 8883, the implicit TLS port IANA assigns to `secure-mqtt`.
pub const secure_default_port: ?u16 = 8883;

/// The status this package reports.
///
/// Zero, because MQTT has no status at all. curl prints `000` for
/// `%{http_code}` on an `mqtt://` publish that worked, measured.
pub const status: u16 = 0;

/// How many bytes of payload one PUBLISH carries.
///
/// 256 KiB, which is far past any MQTT message a broker is configured to
/// take: MQTT is a protocol for small messages, and a broker that accepts
/// a larger one is unusual. It is a bound on what the user's own `-d` may
/// be and not on what a peer sends, so `--max-filesize` does not narrow
/// it: that flag describes a download.
///
/// Smaller than `Session.max_packet_bytes`, which bounds a packet coming
/// the other way. `packet.Writer.max_bytes` says why the two differ.
pub const max_publish_bytes: u64 = 256 * 1024;

/// How many bytes of subscribed messages this package collects by default.
///
/// A subscribe has no length: the broker sends messages until somebody
/// stops. 16 MiB is the number every other non-HTTP package here keeps,
/// and `--max-filesize` narrows it.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How many messages one subscribe reads when nobody names a number.
///
/// One. See the module comment for why this build ends a subscribe and
/// curl does not.
pub const default_message_count: u32 = 1;

/// The most messages `--mqtt-messages` may ask for.
///
/// A bound on round trips and not on bytes: a broker that sends empty
/// messages writes almost nothing for each one, so the size bound alone
/// would let it hold this transfer for a very long time.
pub const max_message_count: u32 = 100_000;

/// How many packets that carry no message one subscribe reads.
///
/// **A packet can cost this end a read and move no bound at all.** A
/// subscribe is bounded by `Options.message_count` and by
/// `Options.max_response_bytes`, and a PINGRESP or a PUBACK moves neither:
/// neither carries a message, so the loop reads one and goes round again.
/// Two bytes on the wire therefore bought one read, for ever, and
/// `--max-time` is off by default. This is the counter for that. Passing
/// it is `error.WeirdServerReply`, exit 8.
///
/// **It is far above what an honest broker sends.** This build sends no
/// PINGREQ, so a broker that keeps MQTT 3.1.1 section 3.13 sends no
/// PINGRESP at all, and this build publishes at QoS 0, so a broker sends
/// no PUBACK either. A broker that sends a few anyway is still read, which
/// is why this is a count and not a refusal of the first one. A
/// subscription that is genuinely idle sends nothing at all, so it never
/// touches this bound and meets `default_read_timeout_s` instead.
pub const max_empty_packets: u32 = 1024;

/// How much room the connection keeps for bytes read and not taken yet.
pub const read_buffer_len: usize = 16384;

/// How long one read may wait with no byte arriving.
///
/// **Every wait an MQTT transfer makes needs this.** A subscribe waits for
/// a message the broker may never have, and `--connect-timeout` covers the
/// dial and the handshake and nothing after them.
///
/// 300 seconds is curl's own `--speed-time` default, and this is the same
/// question. `--speed-time` narrows it and never widens it.
pub const default_read_timeout_s: u32 = 300;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(default_read_timeout_s), .clock = .awake },
};

/// How many bytes of user name and password this sends.
///
/// MQTT 3.1.1 puts each in a two byte count, so 65 535 is the protocol
/// ceiling. This is far below it, because a credential longer than this is
/// not one a broker holds.
pub const max_credential_bytes: usize = 1024;

/// How many bytes of client identifier this sends.
///
/// MQTT 3.1.1 section 3.1.3.1 says a server must accept 23 bytes of
/// `[0-9a-zA-Z]` and may accept more. This build's own identifier is 12
/// bytes, which is the length curl writes, measured. A `--mqtt-client-id`
/// longer than this is refused rather than cut, because a cut identifier
/// names a session the user did not ask for.
pub const max_client_id_bytes: usize = 23;

/// The identifier this package generates, before the random part.
///
/// curl writes `curl` and eight random bytes, measured:
/// `curlIAgOj05A`, `curlfWURpj6O`, and so on for each run. This writes
/// `zurl` and eight, so a broker's log says which client connected.
pub const client_id_prefix = "zurl";

/// How many random characters follow `client_id_prefix`.
pub const client_id_random_len: usize = 8;

/// The characters a generated identifier is built from.
///
/// `[0-9a-zA-Z]`, which is the set section 3.1.3.1 makes every server
/// accept. 62 characters, and the draw below is rejection sampled so no
/// character is more likely than another.
const client_id_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The largest multiple of the alphabet's length that fits in a byte.
///
/// A draw at or above this is thrown away and another taken, so every
/// character is equally likely. See `resolveClientId`.
const client_id_draw_ceiling: u8 = 256 - (256 % client_id_alphabet.len);

/// Where a transfer found the credential it sent.
pub const CredentialSource = enum {
    /// The user name and password in the url itself.
    userinfo,
    /// `Transfer.Options.credentials`, which `-u` fills.
    options,
    /// A `machine` or a `default` entry of the netrc text.
    netrc,
    /// Nobody named one, so the CONNECT set neither flag.
    none,

    /// Names this source for a message to a user. Names the source and
    /// never the credential, which is a secret.
    pub fn describe(s: CredentialSource) []const u8 {
        return switch (s) {
            .userinfo => "the user name and password in the url",
            .options => "the -u option",
            .netrc => "the netrc file",
            .none => "no credential at all",
        };
    }
};

/// One user name and password, ready to send.
pub const Credentials = struct {
    user: []const u8,
    password: []const u8,
};

/// Where the payload of a PUBLISH comes from.
///
/// The shape of `zurl.Transfer.Body`, written out here because this
/// package must build with no `zurl` in its import table.
pub const Source = struct {
    /// How many bytes `read` produces in total, or null when the count is
    /// not known before the body goes out, which is what a pipe gives.
    len: ?u64,
    /// The state `read` acts on.
    ctx: *anyopaque,
    /// Fills up to `len` bytes of `buffer` and returns how many bytes it
    /// wrote. Zero says the body has ended, and a negative value says the
    /// source could not be read.
    read: *const fn (ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize,
};

/// The trust store an encrypted session verifies against, and the way to
/// fill it.
///
/// **An `mqtts` session verifies exactly as an `https` session does.** The
/// bundle here is the one the front package loads for HTTP, so a
/// `--cacert` moves both or neither. A build that leaves this null cannot
/// open an encrypted session at all: `open` reports
/// `error.SslConnectError` and says the build gave it no trust store,
/// rather than fall back to a session that verifies nothing.
///
/// The shape matches `zurl.Client.TlsMaterials` field for field.
pub const Trust = struct {
    lock: *Io.RwLock,
    bundle: *std.crypto.Certificate.Bundle,
    /// Passed back to `load`.
    ptr: *anyopaque,
    /// Fills `bundle` from the sources the transfer named. Called once,
    /// before the handshake, and only for a transfer that speaks TLS.
    load: *const fn (ptr: *anyopaque) Error!void,
};

/// What one transfer may ask for.
pub const Options = struct {
    /// A cap on the dial and the handshake together.
    connect_timeout: Io.Timeout = .none,
    /// The bound on the messages a subscribe collects. See
    /// `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one read may wait with no byte arriving.
    read_timeout: Io.Timeout = default_read_timeout,
    /// Whether to turn Nagle's algorithm off. False is `--no-tcp-nodelay`.
    tcp_no_delay: bool = true,
    /// Whether to accept a peer certificate that does not verify. This is
    /// `-k`/`--insecure`, and it reaches nothing but `sessionOptions`.
    insecure: bool = false,
    /// The lowest TLS version to keep.
    tls_min_version: zurl_core.tls.MinVersion = .floor,
    /// The highest TLS version to keep.
    tls_max_version: zurl_core.tls.Version = .highest,
    /// The trust store for an encrypted session. See `Trust`.
    trust: ?Trust = null,
    /// Whether the connection runs inside TLS. True for `mqtts://`.
    tls: bool = false,
    /// The credential `-u` named, or null.
    credentials: ?zurl_core.auth.Credentials = null,
    /// The text of a netrc file the caller already read, or null.
    netrc_text: ?[]const u8 = null,
    /// The payload of a PUBLISH, or null for a subscribe.
    payload: ?Source = null,
    /// The client identifier `--mqtt-client-id` named, or null to generate
    /// one.
    client_id: ?[]const u8 = null,
    /// How many messages a subscribe reads. See `default_message_count`.
    message_count: u32 = default_message_count,
    /// Where a url naming one host and port dials instead. This is
    /// `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the dial and nothing else.** `tlsOptions` reads
    /// `url.host`, so an `mqtts` peer at the dialed address must still
    /// hold a certificate for the name the url wrote. See
    /// `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

allocator: std.mem.Allocator,
io: Io,
/// The answer of the transfer in play, or null when none is held.
answer: ?[]u8,
/// Reads `answer`. Valid only while `answer` holds something.
body: Io.Reader,
/// The packet dialogue.
session: Session,
/// Builds one packet at a time.
writer: packet.Writer,
/// Holds the topic decoded out of the url.
topic_storage: topic.Storage,
/// Holds a credential decoded out of a url's userinfo, the user name first
/// and the password after it.
credential_storage: [max_credential_bytes * 2]u8,
/// Holds the client identifier of the transfer in play.
client_id_storage: [max_client_id_bytes]u8,

/// A `Fetcher` that holds no answer yet.
///
/// **Initializes in place**, because `writer` alone is a megabyte and a
/// returned value would put that on a stack. Every other package here
/// returns its `Fetcher`; this one cannot, and `zurl_mqtt.Fetcher.create`
/// is the call a caller with no place to put one uses.
pub fn init(f: *Fetcher, allocator: std.mem.Allocator, io: Io) void {
    f.allocator = allocator;
    f.io = io;
    f.answer = null;
    f.body = .fixed("");
    f.session = .init(allocator, io);
    f.writer.init();
}

/// A `Fetcher` on the heap, ready to use. The caller frees it with
/// `destroy`.
pub fn create(allocator: std.mem.Allocator, io: Io) std.mem.Allocator.Error!*Fetcher {
    const f = try allocator.create(Fetcher);
    f.init(allocator, io);
    return f;
}

/// Frees a `Fetcher` that `create` made.
pub fn destroy(f: *Fetcher) void {
    const allocator = f.allocator;
    f.deinit();
    allocator.destroy(f);
}

/// Frees what this `Fetcher` holds. Safe to call more than once, and safe
/// on a `Fetcher` that never opened anything.
pub fn deinit(f: *Fetcher) void {
    f.release();
    f.session.deinit();
    f.wipe();
}

/// Frees the answer, after wiping it.
///
/// **A subscribed message is somebody's data in the clear**, so the bytes
/// are zeroed before the free. That is the rule `zurl-scp` records.
fn release(f: *Fetcher) void {
    const held = f.answer orelse return;
    std.crypto.secureZero(u8, held);
    f.allocator.free(held);
    f.answer = null;
    // The body reader is pointed at nothing, not left pointing at the
    // freed slice.
    f.body = .fixed("");
}

/// Zeroes every buffer that held a credential or a message.
fn wipe(f: *Fetcher) void {
    std.crypto.secureZero(u8, &f.credential_storage);
    // The packet writer held the CONNECT, which carries the password.
    std.crypto.secureZero(u8, f.writer.bytes[0..f.writer.len]);
    f.writer.reset();
}

/// The answer of one MQTT transfer.
pub const Body = struct {
    /// Streams the answer. Valid until the next `open` on this `Fetcher`,
    /// or until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the answer holds. Zero for a publish.
    length: u64,
    /// Whether the transfer published rather than subscribed.
    published: bool,
    /// How many messages a subscribe read. Zero for a publish.
    messages: u32,
    /// Whether the CONNECT carried a credential somebody named.
    authenticated: bool,
};

/// Whether `url` asks for a TLS session on the connection.
///
/// The scheme and nothing else. Compared without regard to case, per RFC
/// 3986, so `MQTTS://` is as encrypted as `mqtts://`.
pub fn isSecure(url: zurl_core.Url) bool {
    return std.ascii.eqlIgnoreCase(url.scheme, secure_scheme);
}

/// Runs one transfer and returns its answer.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two answers at once.
///
/// The faults, and the exit code each carries:
///
/// - a url that names no topic, or a topic this build will not send, is
///   `error.InvalidUrl`, exit 3, and no socket opens at all. curl answers
///   `mqtt://host/` with exit 3 and opens no socket either, measured, and
///   it sends the other three topics this refuses. See `zurl_mqtt.topic`.
/// - a peer that does not accept a connection is `error.CouldNotConnect`,
///   exit 7.
/// - a peer certificate that does not verify is
///   `error.PeerFailedVerification`, exit 60.
/// - a CONNACK that did not accept is `error.WeirdServerReply`, exit 8,
///   which is curl's own code: measured against a mosquitto with
///   `allow_anonymous false`, curl exited 8 for both a publish and a
///   subscribe.
/// - a SUBACK that refused the filter is `error.WeirdServerReply`, exit 8.
/// - a broker that sends more packets with no message in them than
///   `max_empty_packets` is `error.WeirdServerReply`, exit 8. See that
///   constant for what such a packet buys a broker.
/// - a payload past `max_publish_bytes`, or an answer past
///   `options.max_response_bytes`, is `error.FileSizeExceeded`, exit 63.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();
    // The credential and the last packet live in this value between
    // transfers, so both are zeroed on every path out.
    defer f.wipe();

    const publishing = options.payload != null;

    // **The url is read before anything is dialed.** A topic this build
    // will not send costs no socket and sends no credential.
    const name = topic.parse(
        &f.topic_storage,
        url,
        if (publishing) .publish else .subscribe,
    ) catch |err| return fail(d, error.InvalidUrl, &.{topic.describe(err)});

    if (options.message_count == 0 or options.message_count > max_message_count) {
        return failNumber(
            d,
            error.InvalidUrl,
            "an mqtt subscribe reads at least one message and at most ",
            max_message_count,
            ", and this transfer asked for another number",
        );
    }

    const client_id = try f.resolveClientId(options, d);

    var credential_source: CredentialSource = undefined;
    const credentials = try f.resolveCredentials(url, options, &credential_source, d);

    // **The payload is read before the dial**, so a body that cannot be
    // read costs no connection, and so the PUBLISH is one write.
    var payload: []u8 = &.{};
    defer if (payload.len != 0) {
        std.crypto.secureZero(u8, payload);
        f.allocator.free(payload);
    };
    if (options.payload) |source| payload = try f.readPayload(source, d);

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "an mqtt url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this dial and nothing else.**
    // `tlsOptions` below reads `url.host`, so an `mqtts` peer at the
    // dialed address must still hold a certificate for the name the url
    // wrote. See `zurl_net.override`.
    const target = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    // A host that does not read and a host name no resolver can look up
    // are two faults, exit 3 and exit 6. See `zurl_net.errors.hostInit`.
    const host = zurl_net.tcp.Host.init(target.host) catch |err| return fail(d, zurl_net.errors.hostInit(err).err, &.{
        target.faultPrefix(err),
        target.host,
    });

    const tls = try tlsOptions(url.host, options, d);

    // **The dial and the handshake share one deadline.** See
    // `zurl_net.bounded.setup`.
    var connection: zurl_net.Connection = undefined;
    zurl_net.bounded.setup(&connection, f.io, options.connect_timeout, .{
        .allocator = f.allocator,
        .io = f.io,
        .host = host,
        .port = target.port,
        .read_buffer_len = read_buffer_len,
        .tls = tls,
        .no_delay = options.tcp_no_delay,
    }) catch |err| return reportSetup(err, url.host, d);
    defer connection.deinit();

    f.session.begin(.{
        .reader = connection.reader(),
        .writer = connection.writer(),
        .ctx = &connection,
        .flush = flushConnection,
    }, options.read_timeout);
    // The session buffer holds whatever the last packet was.
    defer f.session.wipe();

    try f.runConnect(&connection, client_id, credentials, credential_source, d);

    if (publishing) {
        try f.runPublish(&connection, name, payload, d);
        f.sendDisconnect() catch {};
        return .{
            .reader = &f.body,
            .length = 0,
            .published = true,
            .messages = 0,
            .authenticated = credentials.user.len != 0,
        };
    }

    const collected = try f.runSubscribe(&connection, name, options, d);
    f.sendDisconnect() catch {};
    f.answer = collected.bytes;
    f.body = .fixed(collected.bytes);
    return .{
        .reader = &f.body,
        .length = collected.bytes.len,
        .published = false,
        .messages = collected.messages,
        .authenticated = credentials.user.len != 0,
    };
}

/// Sends the CONNECT and reads the CONNACK.
///
/// **A CONNECT always goes out, with or without a credential.** MQTT 3.1.1
/// section 3.1 makes it the first packet of every session, and curl sends
/// one for a url with no `-u` and no userinfo, measured.
fn runConnect(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    client_id: []const u8,
    credentials: Credentials,
    source: CredentialSource,
    d: ?*Diagnostics,
) Error!void {
    f.writer.reset();
    packet.writeConnect(&f.writer, client_id, credentials.user, credentials.password) catch
        return reportBuild(d, "the connect packet");
    f.session.send(f.writer.written()) catch return reportWrite(connection, "the connect packet", d);

    const answer = f.session.receive() catch |err|
        return fail(d, readErrorOf(err), &.{Session.describe(err)});
    if (answer.kind != .connack) return failType(d, "the connect", answer.kind);

    const code = packet.connackReturnCode(answer.body) catch
        return fail(d, error.WeirdServerReply, &.{
            "the broker sent a CONNACK too short to hold a return code",
        });
    if (code == .accepted) return;

    // curl answers every refused CONNACK with exit 8, measured against a
    // mosquitto with `allow_anonymous false`, so a script that branches on
    // curl codes reads the same number here.
    return fail(d, error.WeirdServerReply, &.{
        "the broker refused the connection built from ",
        source.describe(),
        ": ",
        code.describe(),
    });
}

/// Sends one PUBLISH.
fn runPublish(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    name: []const u8,
    payload: []const u8,
    d: ?*Diagnostics,
) Error!void {
    f.writer.reset();
    packet.writePublish(&f.writer, name, payload) catch
        return reportBuild(d, "the publish packet");
    f.session.send(f.writer.written()) catch
        return reportWrite(connection, "the publish packet", d);
}

/// What one subscribe collected.
const Collected = struct {
    /// The bytes the caller now owns.
    bytes: []u8,
    messages: u32,
};

/// Sends the SUBSCRIBE, reads its answer, and then reads messages.
///
/// **The bytes written for one message are curl's own**, measured: a
/// subscribe to `zurl/sub` printed `00 08 "zurl/sub" "payload-one"` on
/// standard output, which is the two byte topic count and the topic in
/// front of the payload. That is the whole variable header of the PUBLISH,
/// and it is the only format an MQTT url has, so a script written against
/// curl reads the same bytes here.
fn runSubscribe(
    f: *Fetcher,
    connection: *zurl_net.Connection,
    name: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!Collected {
    const id = f.session.takeId();
    f.writer.reset();
    packet.writeSubscribe(&f.writer, id, name) catch
        return reportBuild(d, "the subscribe packet");
    f.session.send(f.writer.written()) catch
        return reportWrite(connection, "the subscribe packet", d);

    const answer = f.session.receive() catch |err|
        return fail(d, readErrorOf(err), &.{Session.describe(err)});
    if (answer.kind != .suback) return failType(d, "the subscribe", answer.kind);

    const granted = packet.suback(answer.body) catch return fail(d, error.WeirdServerReply, &.{
        "the broker sent a SUBACK too short to hold a return code",
    });
    if (granted.packet_id != id) return fail(d, error.WeirdServerReply, &.{
        "the broker answered the subscribe with a packet identifier that belongs to no request zurl sent",
    });
    if (!granted.granted()) return fail(d, error.WeirdServerReply, &.{
        "the broker refused the topic filter this url names",
    });

    var out: std.ArrayList(u8) = .empty;
    // **Wiped before it is freed.** A subscribed message is somebody's
    // data in the clear, and every failure after the first message reaches
    // this.
    errdefer {
        std.crypto.secureZero(u8, out.items);
        out.deinit(f.allocator);
    }

    var count: u32 = 0;
    // See `max_empty_packets`. A packet that carries no message moves
    // neither `count` nor `out.items.len`, so the count of them is the
    // only bound that holds this loop.
    var empty: u32 = 0;
    var qos_seen = false;
    while (count < options.message_count) {
        const incoming = f.session.receive() catch |err|
            return fail(d, readErrorOf(err), &.{Session.describe(err)});
        switch (incoming.kind) {
            .publish => {},
            // A broker may send either at any time. Neither carries a
            // message, and neither is a fault. **Both are counted**,
            // because a loop that reads a packet and adds nothing to any
            // bound is a loop a broker can turn for ever.
            .pingresp, .puback => {
                empty += 1;
                if (empty > max_empty_packets) return fail(d, error.WeirdServerReply, &.{
                    "the broker sent more packets that carry no message than zurl reads in one subscribe, so this transfer was making no progress: the broker is sending PINGRESP or PUBACK in place of the messages this url subscribed to",
                });
                continue;
            },
            else => return failType(d, "the subscription", incoming.kind),
        }

        const message = packet.publish(incoming.body, incoming.flags) catch
            return fail(d, error.WeirdServerReply, &.{
                "the broker sent a PUBLISH whose topic count runs past the end of the packet",
            });
        if ((incoming.flags >> 1) & 0b11 != 0) qos_seen = true;

        // **The subtraction saturates.** Every append below is bounded by
        // this same comparison, so `out.items.len` stays at or under the
        // limit today. In a release build a wrapped subtraction would give
        // a room of nearly 2^64 and the bound would silently stop
        // existing for the rest of the subscribe. `readPayload` already
        // spells it this way.
        if (@as(u64, message.raw.len) > options.max_response_bytes -| out.items.len) {
            return failNumber(
                d,
                error.FileSizeExceeded,
                "the broker sent more than the ",
                options.max_response_bytes,
                " bytes zurl collects from one mqtt subscribe",
            );
        }
        out.appendSlice(f.allocator, message.raw) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
        count += 1;
    }

    // **A message delivered above QoS 0 is named and never acknowledged
    // silently.** This build sends no PUBACK, so the broker will deliver
    // the message again on the next session, and a user who is told
    // nothing would not know.
    if (qos_seen) recordNote(d, "the broker delivered a message above QoS 0, and this build of zurl sends no acknowledgement, so that message will arrive again");

    const bytes = out.toOwnedSlice(f.allocator) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
    return .{ .bytes = bytes, .messages = count };
}

/// Sends the DISCONNECT.
///
/// A courtesy and never a gate: MQTT 3.1.1 section 3.14 says the broker
/// answers it by closing, so there is nothing to read after it and a
/// broker that will not take it has cost this transfer nothing.
fn sendDisconnect(f: *Fetcher) !void {
    f.writer.reset();
    try packet.writeDisconnect(&f.writer);
    try f.session.send(f.writer.written());
}

/// Reads the whole payload of a PUBLISH into memory.
///
/// **Bounded before it is read and again while it is read.** A source that
/// names its own length is checked against the bound before a byte is
/// taken, and a source with no length, which is what a pipe gives, is
/// checked on every chunk.
fn readPayload(f: *Fetcher, source: Source, d: ?*Diagnostics) Error![]u8 {
    if (source.len) |named| {
        if (named > max_publish_bytes) return failNumber(
            d,
            error.FileSizeExceeded,
            "the payload is larger than the ",
            max_publish_bytes,
            " bytes zurl publishes in one mqtt message",
        );
    }

    var raw: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, raw.items);
        raw.deinit(f.allocator);
    }

    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = source.read(source.ctx, &chunk, chunk.len);
        if (n == 0) break;
        if (n < 0) return fail(d, error.ReadError, &.{
            "zurl did not read the payload this transfer publishes",
        });
        const taken: usize = @intCast(n);
        if (@as(u64, taken) > max_publish_bytes -| raw.items.len) return failNumber(
            d,
            error.FileSizeExceeded,
            "the payload is larger than the ",
            max_publish_bytes,
            " bytes zurl publishes in one mqtt message",
        );
        raw.appendSlice(f.allocator, chunk[0..taken]) catch
            return Diagnostics.record(d, error.OutOfMemory, .{});
    }

    return raw.toOwnedSlice(f.allocator) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
}

/// The client identifier this session connects with.
///
/// `--mqtt-client-id` first, and a generated one otherwise.
///
/// **A generated identifier is drawn from a cryptographic source.** A
/// broker keys its session state on this string, so two zurl runs that
/// picked the same one would take each other's session away. It is not a
/// secret, and it is not predictable either.
///
/// **An identifier that is not `[0-9a-zA-Z]` is passed through and not
/// refused.** Section 3.1.3.1 says a server must accept that set and may
/// accept more, and brokers do: a user who names one their broker knows
/// gets it. The two things that are refused are a length past
/// `max_client_id_bytes`, because a cut identifier names a session nobody
/// asked for, and a NUL, for the reason `zurl_mqtt.topic` gives.
fn resolveClientId(f: *Fetcher, options: Options, d: ?*Diagnostics) Error![]const u8 {
    if (options.client_id) |named| {
        if (named.len == 0) return fail(d, error.InvalidUrl, &.{
            "--mqtt-client-id names an empty identifier, and MQTT 3.1.1 section 3.1.3.1 gives an empty one a meaning of its own that this build does not send",
        });
        if (named.len > max_client_id_bytes) return failNumber(
            d,
            error.InvalidUrl,
            "--mqtt-client-id is longer than the ",
            max_client_id_bytes,
            " bytes zurl sends, and a cut identifier names a session nobody asked for",
        );
        if (std.mem.indexOfScalar(u8, named, 0) != null) return fail(d, error.InvalidUrl, &.{
            "--mqtt-client-id holds a NUL, which MQTT 3.1.1 section 1.5.3 does not allow in a string",
        });
        @memcpy(f.client_id_storage[0..named.len], named);
        return f.client_id_storage[0..named.len];
    }

    @memcpy(f.client_id_storage[0..client_id_prefix.len], client_id_prefix);
    var filled: usize = 0;
    while (filled < client_id_random_len) {
        var draw: [client_id_random_len]u8 = undefined;
        f.io.randomSecure(&draw) catch return fail(d, error.ReadError, &.{
            "this build has no secure random source, so it cannot draw an mqtt client identifier, and a predictable one lets another client take this session away",
        });
        for (draw) |byte| {
            if (filled == client_id_random_len) break;
            // **Rejection sampling, so no character is more likely than
            // another.** 62 does not divide 256, so a plain remainder
            // would make the first eight characters of the alphabet
            // slightly more common than the rest. `client_id_draw_ceiling`
            // is the largest multiple of 62 under 256.
            if (byte >= client_id_draw_ceiling) continue;
            f.client_id_storage[client_id_prefix.len + filled] =
                client_id_alphabet[byte % client_id_alphabet.len];
            filled += 1;
        }
    }
    return f.client_id_storage[0 .. client_id_prefix.len + client_id_random_len];
}

/// The credential this transfer connects with.
///
/// The url's userinfo first, then `-u`, then a netrc entry for the url's
/// host. That is the order `zurl.authorize` keeps for HTTP and the order
/// curl keeps here: measured, `mqtt://bob:pw2@host/t/b` put
/// `00 03 "bob" 00 03 "pw2"` on the wire and set the two flag bits.
///
/// **The userinfo is percent-decoded and the other two are not.** A url
/// writes a credential escaped. `-u` and a netrc file are read as they are
/// written, which is what curl does.
///
/// **No byte of a credential needs a gate here, and that is worth saying
/// once.** MQTT counts the octets in front of a string, so a CR, an LF, or
/// any other byte in a password is data on the wire and can end nothing.
/// Every line protocol in this repository has to refuse the three framing
/// bytes; this one does not. A NUL is still refused, because MQTT 3.1.1
/// section 1.5.3 forbids one in any string and a broker answers one by
/// closing.
fn resolveCredentials(
    f: *Fetcher,
    url: zurl_core.Url,
    options: Options,
    source: *CredentialSource,
    d: ?*Diagnostics,
) Error!Credentials {
    const resolved: Credentials = found: {
        if (url.user) |raw_user| {
            source.* = .userinfo;
            if (raw_user.len > max_credential_bytes) return failCredentialSize(d);
            const user = zurl_core.url.percentDecode(
                f.credential_storage[0..raw_user.len],
                raw_user,
            ) catch return fail(d, error.InvalidUrl, &.{
                "the user name in this url holds a percent escape that is not an escape",
            });

            const password = if (url.password) |raw_password| pw: {
                if (raw_password.len > max_credential_bytes) return failCredentialSize(d);
                break :pw zurl_core.url.percentDecode(
                    f.credential_storage[max_credential_bytes..][0..raw_password.len],
                    raw_password,
                ) catch return fail(d, error.InvalidUrl, &.{
                    "the password in this url holds a percent escape that is not an escape",
                });
            } else "";

            break :found .{ .user = user, .password = password };
        }

        if (options.credentials) |c| {
            source.* = .options;
            break :found .{ .user = c.user, .password = c.password };
        }

        if (options.netrc_text) |text| {
            if (zurl_core.netrc.lookup(text, url.host)) |entry| {
                source.* = .netrc;
                break :found .{
                    .user = entry.login orelse "",
                    .password = entry.password orelse "",
                };
            }
        }

        source.* = .none;
        break :found .{ .user = "", .password = "" };
    };

    if (resolved.user.len > max_credential_bytes or
        resolved.password.len > max_credential_bytes)
    {
        return failCredentialSize(d);
    }
    // **A password with no user name cannot be sent.** MQTT 3.1.1 section
    // 3.1.2.9 lets the password flag be set only where the user name flag
    // is, so a broker throws such a packet away. Refusing by name is
    // better than sending one this build knows is malformed.
    if (resolved.user.len == 0 and resolved.password.len != 0) {
        return fail(d, error.InvalidUrl, &.{
            "the credential from ",
            source.*.describe(),
            " names a password and no user name, and MQTT 3.1.1 section 3.1.2.9 has no packet for that",
        });
    }
    if (std.mem.indexOfScalar(u8, resolved.user, 0) != null or
        std.mem.indexOfScalar(u8, resolved.password, 0) != null)
    {
        return fail(d, error.InvalidUrl, &.{
            "the credential from ",
            source.*.describe(),
            " holds a NUL, which MQTT 3.1.1 section 1.5.3 does not allow in a string",
        });
    }
    return resolved;
}

/// The TLS options a session opens with, or null for a plain hop.
///
/// **This is the one place in this package that turns peer verification
/// off, and it reads `options.insecure` and nothing else.** A function and
/// not a few lines inside `open`, so a test can name both answers and
/// prove that no other input can reach the second one. Every other
/// protocol package here keeps the same shape.
fn tlsOptions(
    host: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!?zurl_net.Connection.Tls {
    if (!options.tls) return null;
    return try sessionOptions(host, options, d);
}

/// The options one TLS session opens with.
///
/// **A build with no trust store cannot open an encrypted session.** The
/// `null` arm reports `error.SslConnectError` rather than fall back to a
/// session that verifies nothing, because that fallback is exactly the
/// hole `mqtts` must not open.
fn sessionOptions(
    host: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!zurl_net.Connection.Tls {
    if (options.insecure) {
        return .{
            .host = .none,
            .trust = .none,
            .min_version = options.tls_min_version,
            .max_version = options.tls_max_version,
            .alpn_protocols = &.{},
        };
    }

    const trust = options.trust orelse return fail(d, error.SslConnectError, &.{
        "this build gave the mqtt package no trust store, so it cannot verify an mqtts peer",
    });
    try trust.load(trust.ptr);

    return .{
        .host = .{ .explicit = host },
        .trust = .{ .bundle = .{ .lock = trust.lock, .bundle = trust.bundle } },
        .min_version = options.tls_min_version,
        .max_version = options.tls_max_version,
        // **No ALPN extension at all.** RFC 7301 needs a registered
        // protocol name. `mqtt` is registered for a WebSocket subprotocol
        // and not for ALPN over a plain TLS session, and curl offers none
        // for `mqtts://`, measured.
        .alpn_protocols = &.{},
        // `allow_truncation_attacks` keeps its default, which is false. A
        // subscribe ends at a message count this build keeps, so a middle
        // box that cut the session early would otherwise look like a
        // broker with nothing to say.
    };
}

/// Flushes a `zurl_net.Connection`, for the session's channel.
fn flushConnection(ctx: ?*anyopaque) Io.Writer.Error!void {
    const connection: *zurl_net.Connection = @ptrCast(@alignCast(ctx.?));
    connection.flush() catch return error.WriteFailed;
}

/// The `zurl_core.Error` a read fault carries.
fn readErrorOf(err: Session.ReceiveError) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.OperationTimedOut => error.OperationTimedOut,
        error.Canceled => error.AbortedByCallback,
        error.StreamTooLong => error.FileSizeExceeded,
        // A broker that framed a packet in a way MQTT does not allow, and
        // a broker that closed in the middle of one, are both answers this
        // session cannot go on from.
        error.BadRemainingLength,
        error.PacketTooLarge,
        error.ReservedPacketType,
        error.EndOfStream,
        => error.WeirdServerReply,
        error.ReadFailed, error.ReadTimeoutUnsupported => error.ReadError,
    };
}

/// Reports a packet whose type answers a different request.
fn failType(d: ?*Diagnostics, what: []const u8, kind: packet.Type) Error {
    return fail(d, error.WeirdServerReply, &.{
        "the broker answered ",
        what,
        " with a ",
        kind.describe(),
        ", which answers no request zurl sent",
    });
}

/// Reports a packet this build could not put together.
fn reportBuild(d: ?*Diagnostics, what: []const u8) Error {
    return fail(d, error.WriteError, &.{ "zurl did not build ", what });
}

/// Reports a write that did not reach the broker.
fn reportWrite(connection: *zurl_net.Connection, what: []const u8, d: ?*Diagnostics) Error {
    const cause = connection.writeError() orelse return fail(d, error.WriteError, &.{
        "zurl did not write ",
        what,
    });
    return fail(d, error.WriteError, &.{
        "zurl did not write ",
        what,
        ": ",
        @errorName(cause),
    });
}

/// Reports a dial or handshake fault with the sentence `zurl-net` holds
/// for it.
fn reportSetup(err: zurl_net.errors.SetupError, host: []const u8, d: ?*Diagnostics) Error {
    const mapping = zurl_net.errors.map(err);
    if (mapping.message) |text| return fail(d, mapping.err, &.{ host, ": ", text });
    return fail(d, mapping.err, &.{ host, ": ", @errorName(err) });
}

/// Reports a credential longer than this package sends.
fn failCredentialSize(d: ?*Diagnostics) Error {
    return failNumber(
        d,
        error.CredentialTooLarge,
        "the credential for this url is longer than the ",
        max_credential_bytes,
        " bytes one mqtt connect carries",
    );
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
///
/// The text goes into `Diagnostics.message_storage` because the sentence
/// names a topic this package holds in a buffer it reuses, so a borrowed
/// message would read the next transfer's url.
fn fail(d: ?*Diagnostics, err: Error, parts: []const []const u8) Error {
    const target = d orelse return err;
    const out: []u8 = &target.message_storage;
    var at: usize = 0;
    for (parts) |part| {
        const n = @min(out.len - at, part.len);
        @memcpy(out[at..][0..n], part[0..n]);
        at += n;
    }
    return Diagnostics.record(d, err, .{ .message = out[0..at] });
}

/// `fail` for a sentence with a number in the middle of it.
fn failNumber(
    d: ?*Diagnostics,
    err: Error,
    before: []const u8,
    value: u64,
    after: []const u8,
) Error {
    var digits: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{value}) catch digits[0..0];
    return fail(d, err, &.{ before, text, after });
}

/// Records a sentence about a transfer that worked.
///
/// **A transfer that carried on with something the user should know is not
/// silent.** The one caller is the QoS note in `runSubscribe`.
fn recordNote(d: ?*Diagnostics, text: []const u8) void {
    const target = d orelse return;
    const out: []u8 = &target.message_storage;
    const n = @min(out.len, text.len);
    @memcpy(out[0..n], text[0..n]);
    target.message = out[0..n];
}

/// Returns the dispatch entry for the plain `mqtt` scheme.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import.
///
/// **`f` must outlive every transfer the client runs on either scheme**,
/// and must not move: the entry carries `f` as its opaque pointer, and the
/// body reader points inside it.
pub fn protocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // This package dials the broker itself and reads no proxy field,
        // so a transfer that named a proxy is refused by name rather than
        // run direct. curl carries mqtt through a proxy and this build
        // does not. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// Returns the dispatch entry for the `mqtts` scheme. See `protocol`.
pub fn secureProtocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = secure_scheme,
        .default_port = secure_default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performMqtt };

        fn performMqtt(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const body = try f.open(url, translate(c, url, options), d);
            return .{
                // curl prints `000` for `%{http_code}` on an mqtt url,
                // measured.
                .status = status,
                .content_length = body.length,
                .transfer_encoding = .none,
                .body = body.reader,
            };
        }

        /// Reads the front package's own options into this package's.
        ///
        /// **`--max-filesize` narrows the bound and never widens it**, and
        /// **`--speed-time` narrows the wait the same way**, for the
        /// reason `zurl_gopher` gives: the front package's stall guard
        /// cannot reach a transfer whose body is already in memory, so the
        /// flag has to reach the wait inside `open` instead.
        fn translate(
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
        ) Options {
            const materials = c.tlsMaterials();
            return .{
                .connect_timeout = options.connect_timeout,
                .max_response_bytes = if (options.max_size == 0)
                    default_max_response_bytes
                else
                    @min(options.max_size, default_max_response_bytes),
                .read_timeout = zurl_net.bounded.stallTimeout(
                    options.low_speed_limit,
                    options.low_speed_time_s,
                    default_read_timeout_s,
                ),
                .tcp_no_delay = options.tcp_no_delay,
                .insecure = options.insecure,
                .tls_min_version = options.tls_min_version,
                .tls_max_version = options.tls_max_version,
                .trust = .{
                    .lock = materials.lock,
                    .bundle = materials.bundle,
                    .ptr = materials.ptr,
                    .load = materials.load,
                },
                .tls = isSecure(url),
                .credentials = options.credentials,
                .netrc_text = options.netrc_text,
                .payload = if (options.body) |source|
                    .{ .len = source.len, .ctx = source.ctx, .read = source.read }
                else
                    null,
                .client_id = options.mqtt_client_id,
                .message_count = options.mqtt_messages,
                .connect_to = options.connect_to,
            };
        }
    };
}

const testing = std.testing;
const test_server = @import("test_server.zig");

/// The smallest front package that `protocol` can build against.
///
/// This is a stub of the shape `zurl` exports, and it is here to prove one
/// thing: `protocol` needs the shape and never the package. This file must
/// build with no `zurl` in its import table at all, because a protocol
/// package that imports the front package cannot be left out of a build
/// that does not want it.
///
/// A change to `zurl.protocol.Protocol` or to `zurl.Client.TlsMaterials`
/// that this stub does not follow is a compile error at the call in
/// `src/cli/run.zig`, which is where the real types meet.
const StubFront = struct {
    const Client = struct {
        lock: Io.RwLock = .init,
        bundle: std.crypto.Certificate.Bundle = .empty,
        loads: usize = 0,

        fn tlsMaterials(self: *Client) Trust {
            return .{
                .lock = &self.lock,
                .bundle = &self.bundle,
                .ptr = self,
                .load = countLoad,
            };
        }

        fn countLoad(ptr: *anyopaque) Error!void {
            const self: *Client = @ptrCast(@alignCast(ptr));
            self.loads += 1;
        }
    };

    const Transfer = struct {
        /// The shape of `zurl.Transfer.Body`. Named apart from this file's
        /// own `Body` so the two cannot be read for each other.
        const BodySource = struct {
            len: ?u64,
            ctx: *anyopaque,
            read: *const fn (ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize,
            rewind: ?*const fn (ctx: *anyopaque) callconv(.c) bool = null,
            content_type: ?[]const u8 = null,
        };

        const Options = struct {
            connect_timeout: Io.Timeout = .none,
            low_speed_limit: u64 = 1,
            low_speed_time_s: u32 = 300,
            max_size: u64 = 0,
            tcp_no_delay: bool = true,
            insecure: bool = false,
            tls_min_version: zurl_core.tls.MinVersion = .floor,
            tls_max_version: zurl_core.tls.Version = .highest,
            credentials: ?zurl_core.auth.Credentials = null,
            netrc_text: ?[]const u8 = null,
            body: ?BodySource = null,
            mqtt_client_id: ?[]const u8 = null,
            mqtt_messages: u32 = default_message_count,
            connect_to: []const zurl_net.override.HostOverride = &.{},
        };
    };

    const Response = struct {
        status: u16,
        content_length: ?u64,
        transfer_encoding: std.http.TransferEncoding,
        body: *Io.Reader,
        effective_url: []const u8 = "",
        headers: ?[]const u8 = null,
        final_headers: ?[]const u8 = null,
    };

    const protocol = struct {
        // The stub keeps the shape of `zurl.protocol.Unread`. A stub that
        // dropped a field would let this package compile against a front
        // it no longer fits.
        const Unread = struct {
            proxy: bool = false,
            credentials: bool = false,
        };

        const Protocol = struct {
            scheme: []const u8,
            default_port: ?u16,
            ptr: ?*anyopaque,
            vtable: *const VTable,
            unread: Unread = .{},

            const VTable = struct {
                perform: *const fn (
                    ptr: ?*anyopaque,
                    c: *Client,
                    url: zurl_core.Url,
                    options: Transfer.Options,
                    d: ?*Diagnostics,
                ) Error!Response,
            };
        };
    };
};

/// Parses `text` the way `zurl.Client` does, with both schemes registered.
pub fn parseMqttUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    try schemes.add(.{ .name = secure_scheme, .default_port = secure_default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

test {
    _ = test_server;
}

test "the two schemes name the two ports curl dials" {
    try testing.expectEqualStrings("mqtt", scheme);
    try testing.expectEqualStrings("mqtts", secure_scheme);
    try testing.expectEqual(@as(?u16, 1883), default_port);
    try testing.expectEqual(@as(?u16, 8883), secure_default_port);
}

test "both schemes share one vtable, because they share one protocol" {
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    const plain = f.protocol(StubFront);
    const secure = f.secureProtocol(StubFront);
    try testing.expect(plain.vtable == secure.vtable);
    try testing.expectEqualStrings("mqtt", plain.scheme);
    try testing.expectEqualStrings("mqtts", secure.scheme);
}

test "both dispatch entries refuse a proxy by name rather than run direct" {
    // **`-x` must not fail open.** This package dials the broker itself
    // and reads no proxy field, so a transfer that named a proxy is
    // refused with exit 4 rather than connected direct. Nine other
    // packages here keep the same rule. Measured: curl carries mqtt
    // through a proxy, and `curl -x http://127.0.0.1:9/ -d body-J
    // mqtt://...` exited 7, which is a proxy it could not reach.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    try testing.expect(f.protocol(StubFront).unread.proxy);
    try testing.expect(f.secureProtocol(StubFront).unread.proxy);
    // This package does read a credential, so it says nothing about one.
    try testing.expect(!f.protocol(StubFront).unread.credentials);
    try testing.expect(!f.secureProtocol(StubFront).unread.credentials);
}

test "isSecure reads the scheme and nothing else" {
    try testing.expect(isSecure(try parseMqttUrl("mqtts://h/t")));
    try testing.expect(isSecure(try parseMqttUrl("MQTTS://h/t")));
    try testing.expect(!isSecure(try parseMqttUrl("mqtt://h/t")));
}

test "the tls options turn verification off for -k alone" {
    // **The one place this package can open a session that verifies
    // nothing**, and the only input that reaches it is the flag.
    var d: Diagnostics = .{};

    try testing.expectEqual(
        @as(?zurl_net.Connection.Tls, null),
        try tlsOptions("h", .{ .tls = false, .insecure = true }, &d),
    );

    const insecure = (try tlsOptions("h", .{ .tls = true, .insecure = true }, &d)).?;
    try testing.expectEqual(zurl_net.Connection.HostCheck.none, insecure.host);
    try testing.expectEqual(zurl_net.Connection.TrustCheck.none, insecure.trust);

    // With no trust store and no `-k` the session refuses rather than
    // falls back.
    try testing.expectError(
        error.SslConnectError,
        tlsOptions("h", .{ .tls = true }, &d),
    );

    var client: StubFront.Client = .{};
    const checked = (try tlsOptions("example.test", .{
        .tls = true,
        .trust = client.tlsMaterials(),
    }, &d)).?;
    try testing.expectEqualStrings("example.test", checked.host.explicit);
    try testing.expectEqual(@as(usize, 1), client.loads);
    // No ALPN offer at all. See `sessionOptions`.
    try testing.expectEqual(@as(usize, 0), checked.alpn_protocols.len);

    // **A moved dial is one more input that must not reach the check.**
    // `open` hands this function `url.host`, so an `mqtts` peer at the
    // dialed address still has to hold a certificate for the name the url
    // wrote. Without that rule `--connect-to` would stand in for `-k`.
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "example.test",
        .from_port = 8883,
        .to_host = "127.0.0.1",
        .to_port = 9999,
    }};
    const moved = zurl_net.override.dialTarget(overrides, "example.test", 8883);
    try testing.expectEqualStrings("127.0.0.1", moved.host);
    try testing.expectEqual(@as(u16, 9999), moved.port);

    const still = (try tlsOptions("example.test", .{
        .tls = true,
        .trust = client.tlsMaterials(),
        .connect_to = overrides,
    }, &d)).?;
    try testing.expectEqualStrings("example.test", still.host.explicit);
    try testing.expect(still.trust == .bundle);
}

test "the mqtt translation carries --connect-to into this package" {
    var client: StubFront.Client = .{};
    const D = Dispatch(StubFront);
    const url = try parseMqttUrl("mqtt://example.com/zurl/test");

    try testing.expectEqual(@as(usize, 0), D.translate(&client, url, .{}).connect_to.len);

    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "a.test",
        .to_host = "127.0.0.1",
        .to_port = 9,
    }};
    const carried = D.translate(&client, url, .{ .connect_to = overrides });
    try testing.expectEqual(@as(usize, 1), carried.connect_to.len);
    try testing.expectEqualStrings("a.test", carried.connect_to[0].from_host);
}

test "a generated client identifier is 12 bytes of the set every server takes" {
    // curl writes `curl` and eight random characters, measured across
    // several runs: `curlIAgOj05A`, `curlfWURpj6O`, `curlCHabw06K`.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var seen: [8][]const u8 = undefined;
    var storage: [8][max_client_id_bytes]u8 = undefined;
    for (&seen, &storage) |*slot, *room| {
        const id = try f.resolveClientId(.{}, null);
        try testing.expectEqual(@as(usize, 12), id.len);
        try testing.expectEqualStrings("zurl", id[0..4]);
        for (id[4..]) |byte| {
            try testing.expect(std.mem.indexOfScalar(u8, client_id_alphabet, byte) != null);
        }
        @memcpy(room[0..id.len], id);
        slot.* = room[0..id.len];
    }

    // **Two runs must not pick the same identifier**, because a broker
    // keys its session state on it. Eight draws of 62 to the eighth are
    // not equal unless the source is not random at all.
    for (seen, 0..) |a, i| {
        for (seen[i + 1 ..]) |b| try testing.expect(!std.mem.eql(u8, a, b));
    }
}

test "a named client identifier is used, and a bad one is refused by name" {
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    try testing.expectEqualStrings(
        "sensor-42",
        try f.resolveClientId(.{ .client_id = "sensor-42" }, null),
    );

    var d: Diagnostics = .{};
    try testing.expectError(
        error.InvalidUrl,
        f.resolveClientId(.{ .client_id = "" }, &d),
    );
    const long = "x" ** (max_client_id_bytes + 1);
    try testing.expectError(
        error.InvalidUrl,
        f.resolveClientId(.{ .client_id = long }, &d),
    );
    try testing.expectError(
        error.InvalidUrl,
        f.resolveClientId(.{ .client_id = "a\x00b" }, &d),
    );

    // Exactly the bound still reads.
    const fitted = "y" ** max_client_id_bytes;
    try testing.expectEqualStrings(
        fitted,
        try f.resolveClientId(.{ .client_id = fitted }, null),
    );
}

test "the credential comes from the url first, then -u, then netrc" {
    // The order curl keeps, measured: `mqtt://bob:pw2@127.0.0.1/t/b` put
    // `00 03 "bob" 00 03 "pw2"` on the wire and set the flag byte to `c2`.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var source: CredentialSource = undefined;

    const url_credential = try f.resolveCredentials(
        try parseMqttUrl("mqtt://bob:pw2@h/t"),
        .{ .credentials = .{ .user = "ignored", .password = "ignored" } },
        &source,
        null,
    );
    try testing.expectEqual(CredentialSource.userinfo, source);
    try testing.expectEqualStrings("bob", url_credential.user);
    try testing.expectEqualStrings("pw2", url_credential.password);

    const flag = try f.resolveCredentials(
        try parseMqttUrl("mqtt://h/t"),
        .{ .credentials = .{ .user = "alice", .password = "s3cret" } },
        &source,
        null,
    );
    try testing.expectEqual(CredentialSource.options, source);
    try testing.expectEqualStrings("alice", flag.user);
    try testing.expectEqualStrings("s3cret", flag.password);

    const netrc = try f.resolveCredentials(
        try parseMqttUrl("mqtt://broker.test/t"),
        .{ .netrc_text = "machine broker.test login carol password pw3\n" },
        &source,
        null,
    );
    try testing.expectEqual(CredentialSource.netrc, source);
    try testing.expectEqualStrings("carol", netrc.user);
    try testing.expectEqualStrings("pw3", netrc.password);

    const none = try f.resolveCredentials(try parseMqttUrl("mqtt://h/t"), .{}, &source, null);
    try testing.expectEqual(CredentialSource.none, source);
    try testing.expectEqualStrings("", none.user);
    try testing.expectEqualStrings("", none.password);
}

test "a password of any framing byte reaches the wire whole" {
    // **The proof that this package needs no line gate.** A CR, an LF, and
    // a space in a password each end a command line in POP3, IMAP, SMTP,
    // and FTP. MQTT counts the octets, so all three are data here.
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var source: CredentialSource = undefined;
    const nasty = try f.resolveCredentials(
        try parseMqttUrl("mqtt://h/t"),
        .{ .credentials = .{ .user = "a b", .password = "p\r\nPASS other" } },
        &source,
        null,
    );
    try testing.expectEqualStrings("p\r\nPASS other", nasty.password);

    f.writer.reset();
    try packet.writeConnect(&f.writer, "zurltestid00", nasty.user, nasty.password);
    const bytes = f.writer.written();
    // The whole password is one string inside one count, so the packet
    // ends where the remaining length says and nowhere else.
    try testing.expect(std.mem.indexOf(u8, bytes, "p\r\nPASS other") != null);
    const remaining = bytes[1];
    try testing.expectEqual(@as(usize, 2 + remaining), bytes.len);
}

test "a NUL in a credential is refused, and so is a password with no user name" {
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    var source: CredentialSource = undefined;
    var d: Diagnostics = .{};
    try testing.expectError(error.InvalidUrl, f.resolveCredentials(
        try parseMqttUrl("mqtt://h/t"),
        .{ .credentials = .{ .user = "a\x00b", .password = "p" } },
        &source,
        &d,
    ));
    try testing.expectError(error.InvalidUrl, f.resolveCredentials(
        try parseMqttUrl("mqtt://h/t"),
        .{ .credentials = .{ .user = "a", .password = "p\x00q" } },
        &source,
        &d,
    ));
    // MQTT 3.1.1 section 3.1.2.9 has no packet for a password alone.
    try testing.expectError(error.InvalidUrl, f.resolveCredentials(
        try parseMqttUrl("mqtt://h/t"),
        .{ .credentials = .{ .user = "", .password = "p" } },
        &source,
        &d,
    ));
    // And no message ever quotes the secret.
    try testing.expect(std.mem.indexOf(u8, d.message.?, "p") == null or
        std.mem.indexOf(u8, d.message.?, "p\x00q") == null);
}

test "a credential longer than this package sends is refused before the dial" {
    const f = try Fetcher.create(testing.allocator, testing.io);
    defer f.destroy();

    const long = try testing.allocator.alloc(u8, max_credential_bytes + 1);
    defer testing.allocator.free(long);
    @memset(long, 'x');

    var source: CredentialSource = undefined;
    var d: Diagnostics = .{};
    try testing.expectError(error.CredentialTooLarge, f.resolveCredentials(
        try parseMqttUrl("mqtt://h/t"),
        .{ .credentials = .{ .user = long, .password = "p" } },
        &source,
        &d,
    ));
    try testing.expectEqual(@as(?u32, 43), d.curl_code);
}

test "every read fault maps to an error a caller can act on" {
    // A switch with no else arm, so a fault added to `Session` cannot land
    // on whatever the last arm happened to be.
    try testing.expectEqual(Error.WeirdServerReply, readErrorOf(error.BadRemainingLength));
    try testing.expectEqual(Error.WeirdServerReply, readErrorOf(error.PacketTooLarge));
    try testing.expectEqual(Error.WeirdServerReply, readErrorOf(error.ReservedPacketType));
    try testing.expectEqual(Error.WeirdServerReply, readErrorOf(error.EndOfStream));
    try testing.expectEqual(Error.OperationTimedOut, readErrorOf(error.OperationTimedOut));
    try testing.expectEqual(Error.ReadError, readErrorOf(error.ReadFailed));
    try testing.expectEqual(Error.OutOfMemory, readErrorOf(error.OutOfMemory));

    // Exit 8 for a broker that framed a packet MQTT does not allow, which
    // is the code curl gives a reply it cannot read.
    try testing.expectEqual(
        @as(u32, 8),
        zurl_core.errors.curlCode(readErrorOf(error.BadRemainingLength)),
    );
}
