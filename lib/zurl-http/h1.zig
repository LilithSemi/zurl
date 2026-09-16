//! An `engine.Engine` over `zurl-net`, speaking HTTP/1.1.
//!
//! This engine owns its connections. It dials through `zurl_net.tcp`, it
//! puts TLS on the socket through `zurl_net.Connection`, it writes the
//! request head itself, and it reads the response through
//! `std.http.Reader`. Nothing here goes through `std.http.Client`.
//!
//! It also keeps the pool. `Pool` holds the connections a finished
//! exchange handed back, keyed by `Origin`, so a second request to one
//! origin pays no dial and no TLS handshake. Read `Origin` before any
//! edit to that path: it is the rule that stops one origin's request, and
//! the credential on it, going out on another origin's socket.
//!
//! That ownership is the reason the file has this shape.
//! `std.http.Client` imports std's own TLS, so the ECDSA-over-TLS-1.2
//! patch in `zurl-tls/Client.zig` could not be reached through it, and an
//! ECDSA server answered every request with exit 35. It also collapses
//! every TLS fault into `error.TlsInitializationFailed`, so an expired
//! certificate, a wrong host name, and an untrusted root all reached a
//! user as exit 35 where curl gives exit 60. `zurl_net.errors` keeps those
//! apart, and this file passes the name and the cause on unchanged.
//!
//! What still comes from `std`, outside `std.http.Client`:
//! `std.http.Reader` for `receiveHead` and the content-length and chunked
//! framing, `std.http.Client.Response.Head.parse` for the head bytes,
//! `std.http.HeaderIterator` for a lookup by name, and
//! `std.http.Decompress` for the content encodings. Each one is a plain
//! function or a plain struct over bytes, and none of them opens a
//! connection.
//!
//! A later phase adds a second engine beside this one for ALPN and client
//! certificates; the front package only ever sees `engine.Engine`.

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");
const engine = @import("engine.zig");
/// The HTTP/2 half of the engine.
///
/// **This file owns the dial, so this file reads the ALPN answer.** A
/// client learns which protocol it speaks only once the peer answers the
/// offer, and only the code that opened the connection has that answer. So
/// `sendOn` reads `zurl_net.Connection.alpnProtocol` and hands the request
/// to `h2` for a peer that chose `h2`. Everything above `sendOn` is
/// protocol independent and is not repeated over there: the redirect
/// chain, the credential rule, the header validation, the cookie jar
/// calls, and the connection pool all run for both protocols.
const h2 = @import("h2.zig");
/// The HTTP/3 half of the engine.
///
/// **This file owns the route to it, the way it owns the route to `h2`.**
/// The difference is where the choice is made. HTTP/2 is chosen by the
/// peer, out of an ALPN offer on a stream socket, so `sendOn` reads the
/// answer back. HTTP/3 is chosen before any packet goes out, because it
/// runs on a UDP socket and not on the TCP one this file dials: a client
/// that did not ask for QUIC never opens a QUIC socket at all. So
/// `openOnce` reads `Request.http_version` and takes the QUIC path before
/// it dials, and everything above that line still runs once for all three
/// protocols: the redirect chain, the credential rule, the header
/// validation, and the cookie jar calls.
const h3 = @import("h3.zig");
const testing = std.testing;

/// A connection pool several engines share. See `Engine.shared_pool`.
///
/// It is the same type an engine makes for itself. What a shared one does
/// differently is written on `Pool`.
pub const SharedPool = Pool;

/// Makes a pool that more than one engine may use.
///
/// The caller owns it and must call `destroySharedPool` after every engine
/// that joined it has been deinitialised, and after every exchange on it
/// has been closed.
///
/// `io` must be the `std.Io` of every engine that joins, because the pool
/// locks and waits on it.
pub fn createSharedPool(
    allocator: std.mem.Allocator,
    io: std.Io,
) std.mem.Allocator.Error!*SharedPool {
    const pool = try Pool.create(allocator, io);
    pool.shared = true;
    return pool;
}

/// Gives the caller's own hold on a shared pool back, and frees the pool
/// when it was the last one.
pub fn destroySharedPool(pool: *SharedPool) void {
    pool.destroy();
}

/// How large a redirect target's URL text may be. RFC 9110 recommends at
/// least 8000 bytes for this. Also doubles as the cap on the `location`
/// text that `Head` reports: a target that does not fit is dropped rather
/// than truncated, so a caller never acts on a cut-off URL.
const redirect_buffer_len = 8192;

/// Scratch space for the flate sliding window. Gzip and deflate both
/// decode through `std.compress.flate`, and this is the largest window
/// that format has. It sits inside the exchange, so an identity answer and
/// a flate answer cost the same and neither allocates.
///
/// Zstd needs a far larger window and gets one of its own. See
/// `zstd_buffer_len`.
const decompress_buffer_len = std.compress.flate.max_window_len;

/// The window this engine gives a zstd stream.
///
/// **8 MiB, which is the ceiling RFC 8878 section 3.1.1.1.2 sets for a
/// zstd stream that travels as a content coding.** A decoder is permitted
/// to refuse a frame that asks for more, and a frame that asks for more
/// than this reaches `error.WindowOversize` inside
/// `std.compress.zstd.Decompress` rather than an allocation of the peer's
/// choosing. It is also the value `std.http.Decompress` builds its zstd
/// decoder with, so the two agree.
const zstd_window_len = std.compress.zstd.default_window_len;

/// Scratch space for one zstd stream: the sliding window, plus room for one
/// whole block on top of it. `std.compress.zstd.Decompress.init` asserts
/// exactly this much.
///
/// **This one is allocated, and only for an answer that is really zstd.**
/// It is 8.1 MiB, which no exchange may carry inline, and a transfer that
/// meets no zstd body never pays a byte of it. `Exchange.zstd_buffer` holds
/// it, `openOnce` takes it once the `Content-Encoding` header says zstd,
/// and `closeImpl` frees it.
const zstd_buffer_len = zstd_window_len + std.compress.zstd.block_size_max;

/// How many zstd windows one pool may hold at the same time.
///
/// **The size of a window is already right, and the count of them was not
/// bounded at all.** `zstd_buffer_len` is 8.1 MiB because RFC 8878 section
/// 3.1.1.1.2 sets 8 MiB as the ceiling for a zstd stream that travels as a
/// content coding, so the size cannot come down without refusing frames a
/// compliant server may send. What a server does choose is how many of
/// these exist at once: every exchange whose `Content-Encoding` says
/// `zstd` takes one for the life of that exchange, and nothing counted
/// them. A `-Z` run where each worker met a server answering `zstd` held
/// one window per worker, and the total rose with `--parallel-max`.
///
/// So the count is what gets the bound. Eight is `pool_dialing_max` and
/// the default `-Z` worker count, so an ordinary parallel run never
/// reaches it, and the ceiling it sets is about 65 MiB. That is a real
/// number on a 256 MB device, and it is the whole of what this coding may
/// cost there.
///
/// **The count sits on the pool and not on the engine**, because a `-Z`
/// run gives every worker its own `Engine` and one shared `Pool`. A count
/// per engine would have read one for every worker and bounded nothing.
/// `Exchange` already holds the pool by pointer, for the same reason: the
/// address of an `Engine` is not stable and the pool does not move.
///
/// A transfer that finds the count full reports `error.OutOfMemory`, which
/// is the engine declining the allocation rather than the allocator
/// failing it. Recovery is never silent, and this is the nearest name
/// `engine.OpenError` holds. A user reaches it only by raising
/// `--parallel-max` above the default and meeting a `zstd` answer on every
/// one of those transfers.
const zstd_windows_max: usize = pool_dialing_max;

/// The `Accept-Encoding` value this engine sends, and the whole set of
/// content encodings it reads.
///
/// **This is curl's own list with `br` struck out.** Measured against curl
/// 8.21.0 on a loopback listener, `curl --compressed` sends
/// `Accept-Encoding: deflate, gzip, br, zstd`. zurl decodes three of those
/// four, so it sends the same list in the same order and drops the one it
/// cannot read. The value is therefore a subsequence of curl's, and a
/// server that picks by the order the client wrote picks the same coding
/// for both tools whenever it does not offer `br`.
///
/// **`br` is absent on purpose, and offering it would be worse than
/// leaving it out.** Brotli is not in the Zig standard library, so a
/// decoder would be a dependency this project does not have, and its
/// static dictionary alone is over 100 KiB against a 2.6 MiB stripped
/// binary. A client that advertises `br` and cannot decode it asks a
/// server for octets it must then refuse, which turns a working transfer
/// into `error.BadContentEncoding`. Measured against Cloudflare,
/// `--compressed` gets `content-encoding: br` for curl and
/// `content-encoding: gzip` for zurl, and the decoded octets are the same.
///
/// `zstd` needed no new dependency at all, because `std.compress.zstd`
/// ships a decoder. Measured, the whole of this change cost 86 KiB of
/// stripped ReleaseFast binary: 2,546,408 octets before and 2,634,232
/// after, the zstd decoder included.
///
/// `acceptsContentEncoding` reads the same set from the other side, so the
/// engine never advertises a coding it cannot decode, and never decodes
/// one it did not ask for.
pub const accept_encoding_value = "deflate, gzip, zstd";

/// How many `100 Continue` answers this engine reads before it gives up
/// on a peer.
///
/// A `100` is not the response: RFC 9110 section 15.2.1 says a client
/// must be ready for one and then wait for the real status. So the
/// engine reads past it, which is what `std.http.Client` does with
/// `handle_continue`. `std` loops with no bound at all, so a peer that
/// sends `100` forever hangs the transfer with nothing to read. This
/// bounds that loop. Eight is far past what any peer sends and short
/// enough that a stuck transfer ends.
const continue_heads_max = 8;

/// How long one read of this engine may wait with no octet arriving.
///
/// `engine.default_read_timeout_s` is the rule and the number, because all
/// three engines keep the same bound. It is named again here because the
/// front package and this engine's own tests reach it through this file.
/// See `Exchange.readTimeout` for what the rate watchdog above the engine
/// cannot report.
pub const default_read_timeout_s: u32 = engine.default_read_timeout_s;

/// `default_read_timeout_s`, as a `std.Io.Timeout`.
pub const default_read_timeout: std.Io.Timeout = engine.default_read_timeout;

/// The value `Engine.read_timeout` takes for a transfer that named
/// `--speed-limit` and `--speed-time`.
///
/// `engine.readTimeoutFor` holds the rule, and all three engines take
/// their bound from it. This is the name the `zurl` module already calls,
/// kept so one flag reaches every engine through one function.
pub fn readTimeoutFor(low_speed_limit: u64, low_speed_time_s: u32) std.Io.Timeout {
    return engine.readTimeoutFor(low_speed_limit, low_speed_time_s);
}

/// Scratch space for an owned copy of a `WWW-Authenticate` header value. A
/// digest challenge fits in a few hundred bytes; this is generous room
/// past that for a long realm or a long opaque token.
const www_authenticate_buffer_len = 1024;

/// Scratch space for one redirect chain, split four ways by
/// `followChain`: the url text of the hop that is open, the working memory
/// `std.Uri.resolveInPlace` needs, the text of the target the next hop
/// asks for, and the url of the hop before this one, which
/// `Request.auto_referer` sends as the `Referer`. Each part is
/// `redirect_buffer_len`, so each holds a url as long as RFC 9110 asks a
/// client to accept.
///
/// Allocated on the first redirect and freed with the chain, so a transfer
/// that meets no redirect pays nothing for any of the four.
const chain_storage_len = redirect_buffer_len * 4;

/// Where the auto `Referer` text sits inside the chain scratch. The last
/// part, so the three `nextTarget` reads and writes are untouched.
const chain_referer_start = redirect_buffer_len * 3;

/// Scratch space for the transfer framing, chunk headers included. The
/// caller's own buffer goes to the counting reader in front of this one, so
/// the engine keeps its framing space to itself.
///
/// This is body framing and not head framing, so it is independent of
/// `head_len_max`. A chunk header is a few bytes, so this is generous
/// already.
const transfer_buffer_len = 8192;

/// The largest chunk size this engine accepts on a chunked response body.
///
/// **A chunk size is not a `u64`.** `std.http.Reader` reads the size field
/// into a `u64` and then computes `cp.chunk_len + 2 - n` to hold the two
/// octets of the terminating CRLF beside the data still to come. Zig adds
/// before it subtracts, so a size of `2^64-1` or `2^64-2` overflows that
/// addition: a panic in a checked build, and a wrapped length that reads
/// the rest of the connection as body in a build without the check. Four
/// octets from a peer decide which. `guardChunkSize` refuses the size
/// before `std` reads it.
///
/// The number is curl's own. curl 8.21.0 holds a chunk size in a signed
/// `curl_off_t` and refuses one that does not fit. Measured against curl
/// 8.21.0 over a loopback server, one chunk, size field as written:
/// `7fffffffffffffff` gives exit 18, a truncated transfer, so the size was
/// accepted; `8000000000000000` gives exit 56 and
/// `* invalid chunk size: '8000000000000000'`. So a size is refused when
/// it passes this number, not when it reaches it.
///
/// It is far below `maxInt(u64)`, so the addition above cannot overflow.
pub const chunk_size_max: u64 = std.math.maxInt(i64);

/// How many octets the chunk size field may hold, leading zeroes counted.
///
/// **The second bound, and the one that makes the first one reachable.**
/// The guard reads the size field without consuming it, so it cannot look
/// further ahead than the read buffer holds. A peer that writes the size
/// with a long run of leading zeroes would push the digits that matter
/// past any window and leave `chunk_size_max` untested. This bound closes
/// that: the size field ends within a known number of octets or the
/// response is refused.
///
/// The number is curl's own again. Measured against curl 8.21.0, a size
/// field of `7fffffffffffffff` with leading zeroes: 16 octets in all gives
/// exit 18, and 17 octets gives exit 56 and
/// `* chunk hex-length longer than 16`. So the field is refused when it
/// passes this number.
///
/// Sixteen hexadecimal digits hold every value a `u64` can take, so no
/// legal size field needs more.
pub const chunk_size_digits_max = 16;

/// How large one line of a response head may be, the CRLF included.
///
/// curl keeps two separate bounds on a response head, not one. This is the
/// first: the bound on a single line. curl reads one line at a time into a
/// buffer of `CURL_MAX_HTTP_HEADER` bytes, which curl 8.21.0 declares as
/// `100*1024` in `lib/urldata.h`, and refuses a line that fills it. curl
/// answers such a line with exit 100, `CURLE_TOO_LARGE`.
///
/// A line is refused when its on-wire length reaches this number, and not
/// when it passes it. curl's buffer holds a terminator beside the line, so
/// the longest line curl accepts is one byte shorter than the bound.
/// Measured against curl 8.21.0: a header line of 102399 bytes gives exit
/// 0 and a line of 102400 bytes gives exit 100.
///
/// `std.http.Reader` keeps no per-line bound of its own, so
/// `hasOversizeField` enforces this one over the head that `receiveHead`
/// returns. See `head_len_max` for the second bound, which is larger.
pub const head_field_len_max = 100 * 1024;

/// How large a whole response head may be, status line through the empty
/// line.
///
/// This is curl's second bound on a response head, and it is the larger of
/// the two. curl counts every byte of the head together and refuses a head
/// past `MAX_HTTP_RESP_HEADER_SIZE`, which curl 8.21.0 declares as
/// `300*1024` in `lib/http.h`. curl answers such a head with exit 56,
/// `CURLE_RECV_ERROR`, and not with the exit 100 that one long line gets.
///
/// The two bounds are independent. A head of many short lines that comes to
/// more than `head_field_len_max` bytes is legal, and curl reads it. Only
/// this bound refuses it. An earlier zurl kept one bound of 102400 bytes
/// and refused such a head, which curl accepts.
///
/// Measured against curl 8.21.0, with a head built of 100-byte lines: a
/// head of 307200 bytes gives exit 0 and a head of 307201 bytes gives exit
/// 56. So a head is refused when it passes this number, not when it
/// reaches it.
///
/// `Engine.init` writes this into `Engine.read_buffer_len`, which is what
/// makes it the real bound and not a claim about one. That one number
/// sizes the connection's read buffer and fills
/// `std.http.Reader.max_head_len`, and `receiveHead` answers a longer head
/// with `error.HttpHeadersOversize`. One constant fills both jobs, so the
/// two numbers cannot drift apart.
///
/// `std.http.Client` defaults the same buffer to 8192. That refused every
/// response with a large header block: many `Set-Cookie` lines, a long
/// `Content-Security-Policy`, or verbose tracing headers.
pub const head_len_max = 300 * 1024;

/// The shortest header line this file counts on when it sizes
/// `head_fields_max`. A name, a colon, a space, a one-byte value, and a
/// CRLF come to six bytes, and 16 leaves generous room under that for a
/// head of nothing but short lines.
const head_field_len_min = 16;

/// How many header lines one response head may carry and still reach the
/// head log.
///
/// Derived from `head_len_max`, so a head that fits the byte bound is
/// still described by this one. It is `head_len_max / head_field_len_min`,
/// which is the count of lines a full-size head reaches only when every
/// line in it is shorter than an ordinary header line. So this bound bites
/// for a head built to be counted rather than read, and an ordinary head
/// of a few hundred lines never reaches it.
///
/// It is here so the work of a lookup by name over a kept head is bounded
/// by a count as well as by a byte length: the two bounds fail
/// independently, and a caller needs neither of them to hold for the other
/// to protect it.
pub const head_fields_max = head_len_max / head_field_len_min;

/// How many full-size heads one redirect chain may log.
///
/// A chain may make many more hops than this (`--max-redirs` accepts any
/// `u16`), so the number of hops cannot bound the log on its own and the
/// byte count must. Real heads are a few hundred bytes, so eight full-size
/// heads is a great many real ones.
const head_log_hops_min = 8;

/// How large the head log may grow, over every hop of one chain together.
///
/// Derived from `head_len_max`, so one legal head always fits. A chain
/// bound smaller than the per-head bound would drop the log of a single
/// response that this engine had just read whole, which is why the two
/// numbers must not be written down apart from each other.
///
/// This is the cap and not the cost. `Engine.growHeadLog` starts the log
/// at `head_log_initial_len` and doubles it, so a chain of ordinary heads
/// never allocates the cap. The cap is 2.4 MiB, which only a chain of
/// eight full-size heads reaches, and the log is on the heap.
///
/// A chain that passes this bound loses the whole log, not its tail. See
/// `Engine.logHead`.
pub const head_log_len = head_len_max * head_log_hops_min;

/// The first size the head log allocates. An ordinary response head is a
/// few hundred bytes, so one allocation of this size holds every head of
/// an ordinary chain.
const head_log_initial_len = 8192;

/// How many idle connections one engine keeps ready to serve again.
///
/// The number is a memory budget, not a copy of curl's. curl keeps five,
/// over sockets whose buffers are a few tens of kilobytes. One idle
/// connection here holds `head_len_max` of read buffer, because that is
/// the room a legal response head needs, and a TLS connection holds two
/// record buffers and one more record's worth beside it. That is about
/// 350 KiB for each idle TLS connection, over twenty times what curl
/// holds, so matching curl's count would not match curl's cost.
///
/// Four is what that budget buys. The worst case is the parallel command
/// line: `src/cli/run.zig` gives each of its eight workers a `Client` of
/// its own, and each `Client` owns one engine and one pool, so eight full
/// pools hold about 11 MiB. That is under five per cent of the 256 MB
/// board this project targets, and it is a ceiling that only a command
/// naming four origins for every worker reaches.
///
/// Four also covers what a pool is for. A `Client` runs one transfer at a
/// time, so a redirect chain and a run of urls on one origin need one
/// idle connection, and a second origin in the rotation needs a second.
/// Anything above one only helps a command line that moves between
/// origins, and four origins in rotation is already an unusual command.
///
/// A pool that is full closes its oldest idle connection to take a new
/// one. See `Pool.put`.
pub const pool_idle_max = 4;

comptime {
    // The bounds above must stay in one relationship, and a comment saying
    // so does not stop the next edit. So the build checks it.
    //
    // The line bound must be reachable inside the head bound. A head that
    // carries a line of `head_field_len_max` bytes is at least that large
    // itself, so a line bound over `head_len_max` could never fire: the
    // head bound would refuse the head first, and a user would read exit
    // 56 where curl reports exit 100.
    if (head_field_len_max > head_len_max) @compileError(
        "h1.zig: `head_field_len_max` is over `head_len_max`, so the line bound never fires",
    );

    // One legal head must fit the chain log. A `head_log_len` under
    // `head_len_max` drops the log of a single response the engine read
    // whole, which reads to a user as a response with no headers at all.
    if (head_log_len < head_len_max) @compileError(
        "h1.zig: `head_log_len` is under `head_len_max`, so one legal head cannot fit the chain log",
    );

    // The field bound must be reachable inside the byte bound. A
    // `head_fields_max` that a head at `head_len_max` cannot reach is a
    // bound that never fires, which is worse than no bound: a reader
    // believes the count is checked when nothing checks it. The shortest
    // header line a peer can send is `a:\r\n`, four bytes.
    if (head_fields_max * 4 > head_len_max) @compileError(
        "h1.zig: `head_fields_max` cannot be reached inside `head_len_max`, so the count bound never fires",
    );

    // The log grows from `head_log_initial_len` by doubling, so a first
    // size over the cap would allocate past the bound on the first head.
    if (head_log_initial_len > head_log_len) @compileError(
        "h1.zig: `head_log_initial_len` is over `head_log_len`, so the first head allocates past the cap",
    );
}

pub const Options = struct {
    /// A cap on how long connecting to the peer may take, the TLS
    /// handshake included. `.none` waits forever.
    ///
    /// The engine dials for itself, so it holds this bound around the dial
    /// and the handshake together. See `openConnection` for how, and for
    /// why both must sit inside one raced task.
    connect_timeout: std.Io.Timeout = .none,
    /// How long one read from the peer may wait with no octet arriving.
    ///
    /// **This one defaults to a real bound, where `connect_timeout`
    /// defaults to none.** A caller that names no connect bound still
    /// reaches the peer or fails, because the operating system gives up on
    /// a dial by itself. Nothing gives up on a read: a peer that holds an
    /// open socket and writes nothing holds the transfer for as long as it
    /// likes. So the default here is `default_read_timeout`, and a caller
    /// narrows it rather than turning it on.
    ///
    /// `--speed-time` is the flag that narrows it.
    /// `zurl_net.bounded.stallTimeout` turns that flag and `--speed-limit`
    /// into this value, which is how every other protocol package in this
    /// tree reads the pair. A front package writes
    /// `Engine.read_timeout` before each transfer, the way it writes
    /// `Engine.connect_timeout`.
    ///
    /// `.none` waits for as long as the peer likes and is for a caller
    /// that keeps a bound of its own outside this engine.
    read_timeout: std.Io.Timeout = default_read_timeout,
};

/// An HTTP/1.1 (and HTTP/1.1-over-TLS) engine over `zurl-net`.
pub const Engine = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    connect_timeout: std.Io.Timeout,
    /// How long one read from the peer may wait with no octet arriving.
    /// See `Options.read_timeout`.
    ///
    /// A per-engine field and not a per-request one, for the same reason
    /// `connect_timeout` is: `engine.Engine.VTable.open` takes no bound of
    /// its own. The owner writes it before each `open`, so one engine
    /// serves transfers with different bounds one after another.
    ///
    /// Each `Exchange` copies it at `sendOn`, so a bound the owner changes
    /// during a transfer cannot move the deadline of a body that is
    /// already being read.
    read_timeout: std.Io.Timeout,
    /// How many reads ran with no bound because this build could not watch
    /// a clock while the read was in flight.
    ///
    /// **This is the record of a recovery that has no other trace.** A
    /// build with no concurrency cannot race a read against a deadline,
    /// and refusing the read instead would leave such a build with no HTTP
    /// at all. So the read runs unbounded and this counts it. The same
    /// build enforces no `--connect-timeout` and no `--max-time` either,
    /// so the clock is missing from the whole transfer and not from this
    /// engine alone.
    ///
    /// Saturating, and never cleared inside one transfer. `init` starts it
    /// at zero and one engine counts for its whole life. Read it through
    /// `readBoundsDropped`.
    read_bounds_dropped: usize,
    /// The trust roots every TLS hop verifies the peer against, and the
    /// lock that guards them.
    ///
    /// The engine loads none of this. `tls_setup` names the owner that
    /// does, and `zurl_net.Connection` borrows both for the length of one
    /// handshake and never after, so one bundle serves every connection
    /// this engine opens. Freed by `deinit`.
    ca_bundle: std.crypto.Certificate.Bundle,
    ca_bundle_lock: std.Io.RwLock,
    /// The trust roots the hop to an `https` proxy verifies that proxy
    /// against, and the lock that guards them.
    ///
    /// **A second bundle, and never the first one.** `--proxy-cacert` and
    /// `--proxy-capath` name these roots, and `--cacert` and `--capath` name
    /// the ones above. One bundle for both would verify each peer against
    /// the other's roots at whichever hop loaded last, and a `CONNECT`
    /// tunnel puts both peers in one transfer, so that is not a rare
    /// arrangement. `proxy_tls_setup` fills this one and `tls_setup` fills
    /// the other. Freed by `deinit`.
    ///
    /// Empty on every transfer that names no `https` proxy, because
    /// `proxy_tls_setup` runs only before a hop that puts TLS on the
    /// connection to a proxy.
    proxy_ca_bundle: std.crypto.Certificate.Bundle,
    proxy_ca_bundle_lock: std.Io.RwLock,
    /// How much room each connection keeps for bytes that arrived and were
    /// not read yet, which is what bounds a whole response head.
    ///
    /// `init` writes `head_len_max` here, and `openOnce` writes the same
    /// number into `std.http.Reader.max_head_len`. One field fills both
    /// jobs, so the buffer and the bound cannot drift apart.
    read_buffer_len: usize,
    /// Why the last `open` failed, when the fault carried a cause that its
    /// name alone does not say.
    ///
    /// `zurl_net.errors.map` writes the sentence, and this is where it
    /// waits for the caller. `engine.Engine.open` gives back an error name
    /// and no room for a sentence, and the sentence is the whole point of
    /// the connection setup this engine owns: an expired certificate and
    /// an untrusted root are both exit 60, so only the sentence tells a
    /// user which check refused the peer.
    ///
    /// Every `open` clears this first, so a sentence from an earlier
    /// transfer can never attach to a later fault. Null whenever the fault
    /// has no cause beyond its name. The text is a constant of
    /// `zurl-net`, so it outlives any caller.
    open_cause: ?[]const u8,
    /// Why `TCP_NODELAY` did not take on the last connection this engine
    /// dialed, when it did not take.
    ///
    /// A request answered on a pooled connection dials nothing, so it
    /// leaves this null. The option was already set on that socket when it
    /// was dialed.
    ///
    /// Null on every ordinary run, because the option takes. It is not a
    /// failure: the transfer runs either way, and only pays a stall of up
    /// to 40 milliseconds for each request. See `zurl_net.tcp.setNoDelay`.
    ///
    /// Every `open` clears this first, the way it clears `open_cause`, so
    /// a fault of one transfer cannot attach to a later one. Read it
    /// through `noDelayCause`.
    no_delay_error: ?zurl_net.tcp.NoDelayError,
    /// How many hops asked for HTTP/3, could not get it, and went out over
    /// TCP instead.
    ///
    /// **This is the record of a recovery that has no other trace.**
    /// `--http3` asks for QUIC and takes TCP when QUIC does not answer, the
    /// way curl does, and the transfer then succeeds with nothing to
    /// report. A count that a caller can read is what keeps that from being
    /// silent. It never becomes an error and it never becomes a message: a
    /// fallback is the flag working as asked. `--http3-only` never adds to
    /// it, because that flag takes no other answer.
    ///
    /// Saturating, and never cleared inside one transfer: a redirect chain
    /// may fall back at more than one hop. `init` starts it at zero, and
    /// one engine counts for its whole life.
    h3_fallbacks: usize,
    /// Who fills `ca_bundle`, and when. `openOnce` calls this at each hop
    /// that speaks TLS, and never for a hop that does not. See
    /// `engine.TlsSetup`.
    ///
    /// `init` leaves this null, because the owner of an engine usually
    /// cannot name itself yet: `zurl.Client` holds its engine by value and
    /// `zurl.Client.init` returns that whole value, so the address the
    /// hook needs does not exist until the caller has somewhere to keep
    /// it. The owner sets this field once it has a stable address. A null
    /// hook loads nothing, and a TLS hop then runs on whatever
    /// `ca_bundle` already holds.
    tls_setup: ?engine.TlsSetup,
    /// Who fills `proxy_ca_bundle`, and when. `dial` calls this before a hop
    /// that puts TLS on the connection to an `https` proxy, and never
    /// before any other hop. See `engine.ProxyTlsSetup`.
    ///
    /// **A second hook, beside `tls_setup` and never instead of it.** A
    /// transfer through an `https` proxy to an `https` origin would call
    /// both, and each one loads the roots for the peer it answers for.
    proxy_tls_setup: ?engine.ProxyTlsSetup,

    /// The raw response heads of the chain that `open` is walking, or
    /// walked last, one after the other.
    ///
    /// The log belongs to the engine and not to an `Exchange`, because a
    /// chain closes each hop's exchange before it opens the next one. Only
    /// something that outlives every hop can hold what every hop said. The
    /// exchange that ends the chain reports the whole log through
    /// `engine.Head.headers`, so `open` invalidates it.
    ///
    /// `null` until the first head this engine keeps. A transfer that
    /// never gets a response head therefore pays nothing for this. Freed
    /// by `deinit`.
    ///
    /// The memory is on the heap, not in this struct, so the log survives
    /// a move of the engine. `zurl.Client` holds its engine by value and
    /// `Client.init` returns that whole value, so the address of this
    /// struct is not stable.
    head_log: ?[]u8,
    /// How much of `head_log` the chain has filled.
    head_log_used: usize,
    /// Where the last head in `head_log` starts. Reads as zero for an
    /// empty log, which is also where a first head starts, so read it only
    /// beside `head_log_used`.
    head_log_final: usize,
    /// Whether a bound dropped the log. See `engine.Head.headers_oversize`:
    /// the log then holds nothing, and never a part of a head.
    head_log_dropped: bool,

    /// The redirect target that `error.RedirectToOtherProtocol` names, in
    /// storage the engine owns.
    ///
    /// A chain that reaches a protocol this engine does not speak stops
    /// and hands the target back. The text has to outlive the chain
    /// scratch, which `followChain` frees on the way out, so it is copied
    /// here. Read it through `redirectHandoff`.
    ///
    /// `null` until the first such target, so an ordinary transfer pays
    /// nothing for this. On the heap for the same reason `head_log` is: an
    /// engine moves, and the buffer must not move with it. Freed by
    /// `deinit`.
    redirect_handoff: ?[]u8,
    /// How much of `redirect_handoff` holds the target. Zero when there is
    /// none, which every `open` resets it to.
    redirect_handoff_len: usize,

    /// Whether the request body of the `open` now running has already gone
    /// out once.
    ///
    /// One `open` may send its request more than once: a redirect hop, the
    /// resend that drops a credential, and the one retry on a pooled
    /// connection the peer had closed. Each of those needs the body from
    /// its first byte again, so each needs `engine.Body.rewind`. This flag
    /// is what tells the first send from the ones after it. `open` clears
    /// it, so it never carries an answer about an earlier request.
    ///
    /// A caller that opens the same body twice, in two separate `open`
    /// calls, owns the rewind between them. `zurl.Client` does that for
    /// the request it sends again to answer a `401`.
    body_sent: bool,

    /// Whether any peer answered any byte of the request this `open` sent.
    ///
    /// **This is what tells a caller that a request may not go out
    /// again.** It is `Exchange.peer_answered`, lifted from one exchange
    /// to the whole `open`, and it stays true once a hop has set it: a
    /// chain whose first hop answered a `302` has been answered, whatever
    /// the hop after it did. A caller with a retry of its own, such as
    /// `--retry`, reads it through `peerAnswered` and never sends a
    /// request the peer already acted on.
    ///
    /// `open` clears it, so it describes the most recent request and no
    /// earlier one. False before the first `open`, which reads as "no
    /// peer has answered anything", the safe answer.
    answered_any: bool,

    /// Whether the hop now open sits behind a redirect this engine
    /// followed, on a chain that carries no secret.
    ///
    /// **This is what stops a `WWW-Authenticate` from a redirect target
    /// being answered.** `open` withholds every secret on each redirect it
    /// follows, so a hop past the first one gets no credential. The
    /// challenge on that hop used to travel back to the caller anyway, and
    /// `zurl.Client` then built a Digest response over the `realm` and the
    /// `nonce` that hop chose and sent it to the url the caller named. A
    /// server that can point a redirect at a host it controls therefore
    /// chose the parameters a hash of the user's password was computed
    /// under, and the answer went to a third party that never issued the
    /// challenge.
    ///
    /// The two rules are now the mirror of each other: a hop that may not
    /// carry the secret may not have its challenge answered. So this is the
    /// same boundary `engine.Request.secrets` already keeps, read from the
    /// other side.
    ///
    /// **`--location-trusted` turns it off**, because that flag says the
    /// whole chain may hold the secret. A chain that carries the credential
    /// to every hop is a chain whose hops the caller named as trusted, and
    /// a challenge from one of them is then the caller's to answer.
    ///
    /// `readHead` reads it, and `followChain` sets it before each hop past
    /// the first. Every `open` and every `followChain` clears it, so it
    /// describes the chain in hand and no earlier one.
    chain_challenge_untrusted: bool,

    /// The connections this engine opened and may send another request
    /// on.
    ///
    /// `null` until the first `openOnce`, which allocates it. `Engine.init`
    /// returns an `Engine` and cannot report an allocation failure, so the
    /// pool cannot be built there. See `Pool` for why it is on the heap and
    /// not inside this struct. Freed by `deinit`.
    pool: ?*Pool,

    /// A pool this engine shares with other engines, or null when it keeps
    /// its own.
    ///
    /// **This is what lets `-Z` put eight transfers on one connection.**
    /// Every `-Z` worker owns a `zurl.Client`, and therefore an engine, and
    /// therefore a pool: eight pools meant eight connections to one host
    /// and eight TLS handshakes. A shared pool is one pool for the run, and
    /// an HTTP/2 connection in it carries a stream for each worker.
    ///
    /// `zurl_http.createSharedPool` makes one and `joinSharedPool` sets
    /// this. The engine does not own it: `deinit` gives its own hold back
    /// and the last engine out frees it.
    ///
    /// **Every engine that shares a pool must be safe to share with.**
    /// `Origin.trust` is what the pool checks and it covers the trust
    /// roots. The rest of a request's identity was already in the key.
    shared_pool: ?*Pool,

    /// A digest of the trust roots this engine verifies a peer against.
    ///
    /// It reaches `Origin.trust`, which is where it matters. The owner of
    /// the engine writes it, because the owner is what loads the roots:
    /// `zurl.Client.perform` writes it for each transfer beside the
    /// `--cacert` and `--capath` inputs it hands the hook.
    ///
    /// Zero before an owner writes one, which is one value like any other:
    /// an engine nobody told about its roots keys every connection the
    /// same way, exactly as this engine did before the field existed.
    trust_digest: [std.crypto.hash.sha2.Sha256.digest_length]u8,

    /// `allocator` owns every `Exchange` this engine opens; each is freed
    /// by its own `close`. `io` must outlive the engine.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, options: Options) Engine {
        return .{
            .allocator = allocator,
            .io = io,
            .connect_timeout = options.connect_timeout,
            .read_timeout = options.read_timeout,
            .read_bounds_dropped = 0,
            .ca_bundle = .empty,
            .ca_bundle_lock = .init,
            .proxy_ca_bundle = .empty,
            .proxy_ca_bundle_lock = .init,
            // This is the bound on a whole response head, and nothing else
            // sets it. `std.http.Reader.receiveHead` holds the head in the
            // connection's own read buffer, so a head past this size fails
            // with `error.HttpHeadersOversize`. A buffer of 8192, which is
            // what `std.http.Client` defaults to, refused response heads
            // that curl reads without trouble. See `head_len_max`.
            //
            // The cost is 300 KiB for each connection that is open, which
            // is the price of reading the heads curl reads. A buffer
            // smaller than `head_len_max` would refuse a legal head, so
            // the cost is not optional.
            //
            // An idle connection in the pool holds this buffer too, which
            // is why `pool_idle_max` is a memory budget and not a copy of
            // curl's own count. See it.
            //
            // The buffer is on the heap: `zurl_net.Connection.init`
            // allocates it. Nothing here grows a stack frame, so a small
            // thread stack is safe.
            .read_buffer_len = head_len_max,
            .open_cause = null,
            .no_delay_error = null,
            .h3_fallbacks = 0,
            .tls_setup = null,
            .proxy_tls_setup = null,
            .head_log = null,
            .head_log_used = 0,
            .head_log_final = 0,
            .head_log_dropped = false,
            .redirect_handoff = null,
            .redirect_handoff_len = 0,
            .body_sent = false,
            .answered_any = false,
            .chain_challenge_untrusted = false,
            .pool = null,
            .shared_pool = null,
            .trust_digest = @splat(0),
        };
    }

    /// Sends every connection this engine opens through `pool`, which
    /// other engines use too.
    ///
    /// Call it once, before the first `open`, and pair it with `deinit`:
    /// the engine takes a hold on the pool here and gives it back there.
    /// An engine that already opened a connection keeps that one in the
    /// pool it had, so the call is refused rather than silently half done.
    pub fn joinSharedPool(self: *Engine, pool: *Pool) error{PoolInUse}!void {
        if (self.pool != null) return error.PoolInUse;
        if (self.shared_pool != null) return error.PoolInUse;
        pool.acquire();
        pool.refs += 1;
        pool.release_lock();
        self.shared_pool = pool;
    }

    /// Frees the trust roots and the head log, and closes every connection
    /// the pool still holds.
    ///
    /// **The caller must have already closed every `Exchange` this engine
    /// opened.** An open exchange holds a connection that is not in the
    /// pool, so this cannot reach it: the socket and its buffers would
    /// leak. `Exchange.close` is what hands a connection back to the pool,
    /// and only then can this close it.
    pub fn deinit(self: *Engine) void {
        if (self.pool) |p| p.destroy();
        self.pool = null;
        // A shared pool outlives this engine unless this engine was the
        // last to hold it. `Pool.destroy` counts the holds and frees at
        // the last one.
        if (self.shared_pool) |p| p.destroy();
        self.shared_pool = null;
        if (self.head_log) |log| self.allocator.free(log);
        self.head_log = null;
        if (self.redirect_handoff) |storage| self.allocator.free(storage);
        self.redirect_handoff = null;
        self.redirect_handoff_len = 0;
        self.ca_bundle.deinit(self.allocator);
        // The proxy's own roots go with the engine, exactly as the origin's
        // do. Two bundles, and neither one frees the other.
        self.proxy_ca_bundle.deinit(self.allocator);
    }

    /// The pool, allocating it on the first call.
    ///
    /// A shared pool is already there, so an engine that joined one
    /// allocates nothing here and never owns what it gives back.
    fn ensurePool(self: *Engine) std.mem.Allocator.Error!*Pool {
        if (self.shared_pool) |p| return p;
        if (self.pool) |p| return p;
        const p = try Pool.create(self.allocator, self.io);
        self.pool = p;
        return p;
    }

    /// Why the last `open` failed, when the fault carried a cause its name
    /// alone does not say. Null when it carried none.
    ///
    /// Read this beside the error `open` returned, and never on its own:
    /// `open` clears it before every request, so it describes the most
    /// recent request and no earlier one.
    pub fn cause(self: *const Engine) ?[]const u8 {
        return self.open_cause;
    }

    /// Why the last `open` could not turn Nagle's algorithm off, when it
    /// could not. Null on every ordinary run.
    ///
    /// This says a transfer is slower and never that one failed, so read
    /// it beside a success as well as beside a fault. `open` clears it
    /// before every request, so it describes the most recent one.
    ///
    /// curl reports the same thing at info level, which a user sees only
    /// under `-v`. A caller that has no verbose mode yet may hold the
    /// sentence and print nothing.
    /// Whether any peer answered any byte of the last `open`.
    ///
    /// **Read this before sending the same request again.** A request the
    /// peer answered has been acted on, whatever the transfer failed with
    /// afterwards, so a retry of it would ask the peer to act twice. This
    /// is `Exchange.peer_answered` for the whole `open`, chain and all,
    /// and it is the one signal for the question: nothing else in this
    /// engine answers it.
    ///
    /// `open` clears it, so read it beside the result of the most recent
    /// `open` and never on its own.
    pub fn peerAnswered(self: *const Engine) bool {
        return self.answered_any;
    }

    pub fn noDelayCause(self: *const Engine) ?[]const u8 {
        return zurl_net.errors.noDelayMessage(self.no_delay_error orelse return null);
    }

    /// How many reads this engine ran with no bound because the build
    /// could not watch a clock while the read was in flight.
    ///
    /// Zero on every ordinary build. See `read_bounds_dropped`.
    pub fn readBoundsDropped(self: *const Engine) usize {
        return self.read_bounds_dropped;
    }

    /// The redirect target the last `open` handed back, or null when it
    /// handed back none.
    ///
    /// Read this only beside `error.RedirectToOtherProtocol`. Every `open`
    /// clears it first, so it describes the most recent request and no
    /// earlier one, and the text lives until the next `open` or `deinit`.
    ///
    /// The url is a **server's** text, resolved against the hop it came
    /// from. `Request.redirect_protocols` already said the protocol is one
    /// the user permits; nothing here says the caller may open it, only
    /// that this engine cannot.
    pub fn redirectHandoff(self: *const Engine) ?[]const u8 {
        if (self.redirect_handoff_len == 0) return null;
        return self.redirect_handoff.?[0..self.redirect_handoff_len];
    }

    /// Copies `target` into `redirect_handoff`, allocating it on the first
    /// call.
    ///
    /// `target` came out of the chain scratch, which is bounded by
    /// `redirect_buffer_len`, and the storage here is that same size. So a
    /// target that reached this point always fits, and the assert says so
    /// rather than truncating a url.
    fn recordHandoff(self: *Engine, target: []const u8) std.mem.Allocator.Error!void {
        std.debug.assert(target.len <= redirect_buffer_len);
        const storage = self.redirect_handoff orelse
            try self.allocator.alloc(u8, redirect_buffer_len);
        self.redirect_handoff = storage;
        @memcpy(storage[0..target.len], target);
        self.redirect_handoff_len = target.len;
    }

    /// Empties the head log, so the next chain starts with nothing in it.
    ///
    /// The buffer stays allocated. One engine serves one transfer after
    /// another, and each would otherwise pay for the same allocation
    /// again.
    fn resetHeadLog(self: *Engine) void {
        self.head_log_used = 0;
        self.head_log_final = 0;
        self.head_log_dropped = false;
    }

    /// Appends one raw response head to the log.
    ///
    /// Drops the whole log, and sets `head_log_dropped`, when `head` is
    /// larger than `head_len_max`, when it carries more than
    /// `head_fields_max` header lines, or when it does not fit the room
    /// `head_log_len` gives the chain. Recovery is never silent: the flag
    /// reaches the caller through `engine.Head.headers_oversize`, and the
    /// caller sees no headers at all rather than a piece of them.
    ///
    /// Reports `error.OutOfMemory`, and nothing else. A log that cannot be
    /// allocated is a fault of this process and not of the peer, so it is
    /// not recovered into a dropped log.
    fn logHead(self: *Engine, head: []const u8) std.mem.Allocator.Error!void {
        if (self.head_log_dropped) return;
        if (head.len > head_len_max or countFields(head) > head_fields_max) {
            self.dropHeadLog();
            return;
        }

        const need = self.head_log_used + head.len;
        if (need > head_log_len) {
            self.dropHeadLog();
            return;
        }

        const log = try self.growHeadLog(need);
        @memcpy(log[self.head_log_used..][0..head.len], head);
        self.head_log_final = self.head_log_used;
        self.head_log_used = need;
    }

    /// Makes room for `need` bytes in the head log, and returns the log.
    ///
    /// The log starts at `head_log_initial_len` and doubles from there, so
    /// a chain of ordinary heads pays one small allocation and never the
    /// `head_log_len` cap. That cap is eight full-size heads, which is
    /// worth reserving for a chain that asks for it and not for every
    /// transfer.
    ///
    /// The memory is on the heap, so a head that reaches the cap costs no
    /// stack at all.
    ///
    /// A failed grow leaves the log exactly as it was, and the caller
    /// reports `error.OutOfMemory` rather than a dropped log: the fault is
    /// this process, not the peer.
    ///
    /// Asserts `need` is inside `head_log_len`. The caller checks that
    /// against the peer's own bytes and refuses first.
    fn growHeadLog(self: *Engine, need: usize) std.mem.Allocator.Error![]u8 {
        std.debug.assert(need <= head_log_len);
        if (self.head_log) |log| {
            if (log.len >= need) return log;
        }

        var capacity: usize = head_log_initial_len;
        while (capacity < need) capacity *= 2;
        if (capacity > head_log_len) capacity = head_log_len;

        const grown = if (self.head_log) |log|
            try self.allocator.realloc(log, capacity)
        else
            try self.allocator.alloc(u8, capacity);
        self.head_log = grown;
        return grown;
    }

    /// Throws the log away and records that a bound did it.
    fn dropHeadLog(self: *Engine) void {
        self.head_log_used = 0;
        self.head_log_final = 0;
        self.head_log_dropped = true;
    }

    /// What `engine.Head` reports about the log: every head in it, and the
    /// last head alone. Both are null once a bound dropped the log.
    const LoggedHeads = struct { all: ?[]const u8, final: ?[]const u8 };

    fn loggedHeads(self: *const Engine) LoggedHeads {
        if (self.head_log_dropped or self.head_log_used == 0) return .{ .all = null, .final = null };
        const log = self.head_log.?;
        return .{
            .all = log[0..self.head_log_used],
            .final = log[self.head_log_final..self.head_log_used],
        };
    }

    /// The `engine.Engine` view of this engine, for the front package.
    pub fn interface(self: *Engine) engine.Engine {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: engine.Engine.VTable = .{ .open = open, .cause = causeImpl };

    /// Opens one transfer.
    ///
    /// **A request that carries a secret and meets a redirect reaches the
    /// origin twice, and this is deliberate.** The first request carries
    /// the secret and gets one answer. When that answer is a redirect the
    /// caller asked to follow, the whole request goes out again with no
    /// secret, and the chain is walked with that one. curl behaves the same
    /// way, and `Exchange.open` holds the reasoning and the measurement.
    ///
    /// The note is repeated here because this is the door a caller comes
    /// through, and because of what it does to a **test fixture**: a server
    /// scripted with one response per logical request runs out of script on
    /// the second request and the transfer then waits for an answer that
    /// never comes. A fixture that meets this needs two responses for one
    /// credentialed redirect. This cost a consumer a day of reading, so it
    /// is written where they looked.
    fn open(ptr: *anyopaque, req: engine.Request) engine.OpenError!*engine.Exchange {
        const self: *Engine = @ptrCast(@alignCast(ptr));
        return Exchange.open(self, req);
    }

    fn causeImpl(ptr: *anyopaque) ?[]const u8 {
        const self: *Engine = @ptrCast(@alignCast(ptr));
        return self.cause();
    }
};

/// How many header lines `head` carries.
///
/// Reads the raw bytes rather than a parsed head, because the log keeps
/// raw bytes and the count has to describe exactly what the log holds.
/// The status line is not a header line, and the empty line ends the head:
/// a block with no empty line ends at its own last byte, so a malformed
/// block cannot make this read past its end.
///
/// Stops at one past `head_fields_max`. The caller asks only whether the
/// head is over the bound, so a head built of nothing but header lines
/// costs no more to answer than the bound itself.
fn countFields(head: []const u8) usize {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.first();

    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        count += 1;
        if (count > head_fields_max) break;
    }
    return count;
}

/// Whether any line of `head` reaches `head_field_len_max`.
///
/// This is the per-line bound, which `std.http.Client` does not keep. The
/// client keeps only the whole-head bound, through `read_buffer_size`, so
/// a head of legal total size can still carry one line that curl refuses.
/// This is the check that closes that gap.
///
/// `line.len + 2` is the length the peer wrote, because the split drops the
/// CRLF that ends each line. curl measures the same length.
///
/// The status line counts. curl reads it into the same buffer as a header
/// line, so a status line at the bound is refused the same way.
///
/// Reads the raw bytes rather than a parsed head, for the same reason
/// `countFields` does: the bound describes what the peer sent. The empty
/// line ends the head, so a malformed block cannot make this read past its
/// own last byte.
fn hasOversizeField(head: []const u8) bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        if (line.len + 2 >= head_field_len_max) return true;
        if (line.len == 0) break;
    }
    return false;
}

/// Whether any `Content-Length` field of `head` holds something RFC 9112
/// does not call a length.
///
/// **`std` reads this field with `std.fmt.parseInt`, which is a wider
/// grammar than the field has.** RFC 9112 section 6.2 says `1*DIGIT`, and
/// `parseInt` also takes a leading `+` and Zig's `_` digit separators. So
/// `Content-Length: +5` framed a body of five octets and
/// `Content-Length: 1_0` framed one of ten, where curl 8.21.0 refused both
/// with exit 8. `engine.contentLengthIsDigits` holds the grammar and the
/// measurement.
///
/// **A framing this reads more generously than the proxy in front of it is
/// response splitting.** The two then disagree about where the response
/// ends, and the octets past that point reach the next request as its head.
/// The pool keys on the origin and the proxy together, so the damage is
/// bounded to that one route, and it is still a divergence that must not
/// stand.
///
/// This runs over the raw head, before `std.http.Client.Response.Head.parse`
/// reads it, for the same reason `hasOversizeField` does: the check
/// describes what the peer wrote, and the parsed head no longer holds the
/// text of a field it refused.
///
/// **Every `Content-Length` of the head is read, not the first one.** Two
/// fields that disagree are already `error.HttpHeadersInvalid` inside
/// `std`, and two that agree are one length. A head that carries one legal
/// field and one illegal one is refused here whichever order they arrived
/// in.
fn hasInvalidContentLength(head: []const u8) bool {
    var fields: engine.HeadFields = .init(head);
    while (fields.next()) |field| {
        if (!std.ascii.eqlIgnoreCase(field.name, "Content-Length")) continue;
        if (!engine.contentLengthIsDigits(field.value)) return true;
    }
    return false;
}

/// Whether a hop puts TLS on its socket.
const Protocol = enum { plain, tls };

/// Resolves `req.url.scheme` to a `Protocol`, matching case-insensitively
/// per RFC 3986. `zurl_core.url.parse` keeps the scheme's original case, so
/// an exact comparison would read an upper-case scheme from a user or a
/// redirect as unsupported.
fn resolveProtocol(scheme: []const u8) engine.OpenError!Protocol {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return .plain;
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return .tls;
    return error.UnsupportedProtocol;
}

/// Everything that must match before one request may go out on a
/// connection another request opened.
///
/// **This type is the whole safety rule of the pool.** A pooled
/// connection reaches a peer that was dialed, and for TLS verified, for
/// one origin. Handing it to a request for another origin sends that
/// request, and the `Authorization` or `Cookie` header it carries, to a
/// host the caller never named. So `Pool.take` answers only on an exact
/// match of every field here, and a field that a later option adds to a
/// connection must be added here in the same edit.
///
/// The origin is the scheme, the host, and the port together, which is
/// what RFC 6454 says an origin is and what `engine.origin_bound_headers`
/// already names as the boundary a secret may not cross. `protocol`
/// stands for the scheme, because `resolveProtocol` has already folded
/// `http` and `HTTP` onto one value and no third scheme reaches here.
///
/// The two TLS version bounds are here because they are a property of the
/// session and not only of the request. A connection opened under a floor
/// of TLS 1.2 may have settled on TLS 1.2, and a later request that asked
/// for `--tlsv1.3` must not be answered over it. Comparing the bounds the
/// caller asked for is stricter than comparing the version that was
/// reached: two requests that ask for different bounds get different
/// connections, even where one session would have satisfied both. That
/// costs a handshake in a case no command line reaches today, and it can
/// never let a request travel below the floor its caller named.
///
/// The trust roots need no field. `zurl.Client.ensureCaBundle` loads the
/// bundle once for the life of a `Client`, and a `Client` owns one
/// engine, so every connection in one pool verified against the same
/// roots.
///
/// The host is compared byte for byte, not without regard to case. DNS
/// reads `Example.com` and `example.com` as one name, so this is stricter
/// than it has to be: two spellings of one host get two connections. A
/// spare connection is a cost. A shared one that was checked against
/// another spelling is a hazard, and the exact compare is the version
/// with no argument to have.
const Origin = struct {
    protocol: Protocol,
    port: u16,
    tls_min_version: zurl_core.tls.MinVersion,
    tls_max_version: zurl_core.tls.Version,
    /// Whether the peer certificate was verified when this connection came
    /// up. This is `engine.Request.insecure`.
    ///
    /// **It is part of the identity, not a detail.** The check happens
    /// once, at the handshake, and nothing reads it back off the socket
    /// afterward. So a connection opened with `-k` carries a peer nobody
    /// authenticated for the rest of its life. Without this field, a
    /// second request that asked for verification could take that
    /// connection out of the pool and get an unverified peer while
    /// believing the opposite.
    insecure: bool,
    /// Whether Nagle's algorithm was turned off on this connection. This
    /// is `engine.Request.tcp_no_delay`.
    ///
    /// Part of the identity for the same reason `insecure` is: the option
    /// is set once, on the socket, and never read back. A pooled
    /// connection with the option on would silently ignore a later
    /// `--no-tcp-nodelay`.
    no_delay: bool,
    /// Whether the handshake that opened this connection left the ALPN
    /// extension out. This is `engine.Request.no_alpn`.
    ///
    /// Part of the identity for the same reason `insecure` is: the offer
    /// is made once, in the client hello, and it cannot be made again on
    /// an open session. A pooled connection that negotiated a protocol
    /// would otherwise answer a later request that asked for none.
    no_alpn: bool,
    /// Which HTTP versions the ALPN offer of this connection named. This is
    /// `engine.Request.http_version`.
    ///
    /// Part of the identity for the same reason `no_alpn` is: the offer is
    /// made once, in the client hello, and it cannot be made again on an
    /// open session. A pooled HTTP/2 connection would otherwise answer a
    /// later request that asked for HTTP/1.1.
    http_version: engine.HttpVersion,
    /// The host, owned. A pooled connection outlives the `engine.Request`
    /// that opened it, and `Request.url` is borrowed, so the pool cannot
    /// point at the caller's text.
    host_storage: [masked_host_max]u8,
    host_len: usize,
    /// The peer this connection was dialed at, when `--resolve` or
    /// `--connect-to` moved it away from the host above. Empty, with
    /// `dial_port` zero, when nothing moved it.
    ///
    /// **It is part of the identity, not a detail.** A socket is opened at
    /// one address and never re-dialed, so a pooled connection reaches
    /// whichever peer it was opened at. Without this field, a second
    /// request whose override list names another address could take this
    /// connection out of the pool and reach the first address instead.
    dial_storage: [masked_host_max]u8,
    dial_len: usize,
    dial_port: u16,
    /// The proxy this connection goes through, when it goes through one.
    ///
    /// **A pooled connection through one proxy must never serve a request
    /// meant for another proxy, or for no proxy.** The proxy is where the
    /// socket actually ends: a tunnelled connection reaches the origin
    /// through a peer that chose to carry it, and a direct connection
    /// reaches the origin itself. Handing one to the other sends the
    /// request, and every secret on it, to a peer the caller never named.
    ///
    /// Null for a connection that dialed the origin, so a transfer that
    /// named no proxy keys byte for byte the way it did before this field
    /// existed.
    proxy_kind: ?zurl_core.proxy.Kind,
    /// The proxy host, owned, and its port. Read only when `proxy_kind` is
    /// not null.
    proxy_storage: [masked_host_max]u8,
    proxy_len: usize,
    proxy_port: u16,
    /// Whether the proxy's own certificate was verified when this
    /// connection came up. This is `engine.Request.Proxy.insecure`.
    ///
    /// Part of the identity for the same reason `insecure` is: the check
    /// happens once, at the proxy's handshake, and nothing reads it back
    /// off the socket. A connection to a proxy nobody authenticated must
    /// never answer a request that asked for one.
    proxy_insecure: bool,
    /// A digest of the proxy credential this connection was opened with.
    ///
    /// **A digest and not the credential.** A pooled connection outlives
    /// the request that opened it, and a `Client` keeps its pool for its
    /// whole life, so the credential itself would sit in this process's
    /// memory long after the transfer that needed it finished. The digest
    /// answers the only question the pool asks, which is whether two
    /// requests named the same credential.
    ///
    /// **It is part of the identity because a tunnel is authenticated
    /// once.** The `CONNECT` that opened a tunnel carried one
    /// `Proxy-Authorization`, and nothing on the open tunnel can carry
    /// another. A second request that named a different proxy credential
    /// would run on a tunnel the first credential opened, which is one user
    /// borrowing another user's proxy authorisation.
    ///
    /// The digest of an empty credential is the digest of an empty string,
    /// so a connection with no proxy credential has one value and matches
    /// only other requests with none.
    proxy_credential: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    /// A digest of the trust roots this connection's peer was verified
    /// against. `Engine.trust_digest` is where it comes from.
    ///
    /// **It is part of the identity because a certificate is checked
    /// once.** The chain was walked at the handshake and nothing reads it
    /// back off the socket afterward, so a pooled connection carries
    /// whatever `--cacert` and `--capath` said on the day it came up. A
    /// second request that named other roots must not take it.
    ///
    /// One `Client` used to be the whole answer: one client owned one pool
    /// and one trust store, so every connection in a pool had been checked
    /// the same way. That argument ends where a pool is shared, and `-Z`
    /// shares one. This field is what replaces it, and it holds for the
    /// unshared case too: a `Client` whose next transfer names another
    /// `--cacert` reloads the store, and without this field the connection
    /// from before the reload would still match.
    ///
    /// A digest and not the paths, for the reason `proxy_credential` is a
    /// digest: a pooled connection outlives the request that opened it.
    trust: [std.crypto.hash.sha2.Sha256.digest_length]u8,

    /// The origin `req` names on `protocol`, or null when a host does not
    /// fit.
    ///
    /// A host longer than `masked_host_max` cannot be dialed as a name:
    /// `std.Io.net.HostName.init` refuses it, and an address literal is
    /// far shorter. So the null answer is not reachable through
    /// `openOnce` today. It is a branch and not an assert because an
    /// assert disappears in ReleaseFast, and the cost of the branch is
    /// one connection that is used once and closed.
    fn init(
        protocol: Protocol,
        host_text: []const u8,
        port: u16,
        target: engine.DialTarget,
        proxy: ?engine.Proxy,
        req: engine.Request,
        trust: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    ) ?Origin {
        if (host_text.len > masked_host_max) return null;
        if (target.host.len > masked_host_max) return null;
        if (proxy) |p| {
            if (p.host.len > masked_host_max) return null;
        }
        var self: Origin = .{
            .protocol = protocol,
            .port = port,
            .tls_min_version = req.tls_min_version,
            .tls_max_version = req.tls_max_version,
            .insecure = req.insecure,
            .no_delay = req.tcp_no_delay,
            .no_alpn = req.no_alpn,
            .http_version = req.http_version,
            .host_storage = undefined,
            .host_len = host_text.len,
            .dial_storage = undefined,
            // A transfer that named no override leaves both fields empty,
            // so its origin is byte for byte the one this engine built
            // before overrides existed.
            .dial_len = if (target.overridden) target.host.len else 0,
            .dial_port = if (target.overridden) target.port else 0,
            // A transfer that named no proxy leaves every field below at
            // the value it had before proxies existed, so its key is byte
            // for byte the old one.
            .proxy_kind = if (proxy) |p| p.kind else null,
            .proxy_storage = undefined,
            .proxy_len = if (proxy) |p| p.host.len else 0,
            .proxy_port = if (proxy) |p| p.port else 0,
            .proxy_insecure = if (proxy) |p| p.insecure else false,
            .proxy_credential = proxyCredentialDigest(proxy),
            .trust = trust,
        };
        @memcpy(self.host_storage[0..host_text.len], host_text);
        if (target.overridden) @memcpy(self.dial_storage[0..target.host.len], target.host);
        if (proxy) |p| @memcpy(self.proxy_storage[0..p.host.len], p.host);
        return self;
    }

    fn host(self: *const Origin) []const u8 {
        return self.host_storage[0..self.host_len];
    }

    /// The proxy this connection goes through, or an empty slice when it
    /// dialed the origin itself.
    fn proxyHost(self: *const Origin) []const u8 {
        return self.proxy_storage[0..self.proxy_len];
    }

    /// The peer this connection was dialed at, or an empty slice when the
    /// url's own host was the peer.
    fn dialHost(self: *const Origin) []const u8 {
        return self.dial_storage[0..self.dial_len];
    }

    /// Whether one connection may serve both origins. Every field, and no
    /// shortcut.
    fn eql(a: *const Origin, b: *const Origin) bool {
        if (a.protocol != b.protocol) return false;
        if (a.port != b.port) return false;
        if (a.tls_min_version != b.tls_min_version) return false;
        if (a.tls_max_version != b.tls_max_version) return false;
        // The verification answer, and not only the TLS versions. See
        // `insecure` for why a mismatch here can never share one socket.
        if (a.insecure != b.insecure) return false;
        if (a.no_delay != b.no_delay) return false;
        // The ALPN offer, which is fixed at the handshake. See `no_alpn`
        // and `http_version`: whether the extension went out at all, and
        // which names it carried, are both part of the session.
        if (a.no_alpn != b.no_alpn) return false;
        if (a.http_version != b.http_version) return false;
        // The peer the socket reaches, and not only the host the url
        // names. See `dial_storage`.
        if (a.dial_port != b.dial_port) return false;
        if (!std.mem.eql(u8, a.dialHost(), b.dialHost())) return false;
        // **The proxy, which is where the socket really ends.** A null on
        // one side and a proxy on the other are two different peers, so
        // the optional is compared and not only the fields inside it.
        if ((a.proxy_kind == null) != (b.proxy_kind == null)) return false;
        if (a.proxy_kind) |kind| {
            if (kind != b.proxy_kind.?) return false;
            if (a.proxy_port != b.proxy_port) return false;
            if (a.proxy_insecure != b.proxy_insecure) return false;
            if (!std.mem.eql(u8, a.proxyHost(), b.proxyHost())) return false;
        }
        // The proxy credential, by digest. A tunnel is authenticated once,
        // so two requests that named different proxy credentials can never
        // share one. Compared for a direct connection too, where both sides
        // hold the digest of an empty credential and always agree.
        if (!std.mem.eql(u8, &a.proxy_credential, &b.proxy_credential)) return false;
        // The trust roots, by digest. A certificate is checked once, at the
        // handshake, so a connection carries the roots of the request that
        // opened it for the rest of its life. See `trust`.
        if (!std.mem.eql(u8, &a.trust, &b.trust)) return false;
        return std.mem.eql(u8, a.host(), b.host());
    }
};

/// A digest of the proxy credential, or of nothing at all when there is no
/// proxy.
///
/// **The pool must be able to tell two proxy credentials apart and must not
/// keep either one.** So the key holds this digest and never the bytes: an
/// idle connection can sit in the pool for the whole life of a `Client`, and
/// a credential in it would sit there too.
///
/// Every field is length-prefixed before it is hashed, so a user of `ab`
/// with a password of `c` and a user of `a` with a password of `bc` give
/// two different digests. Without the lengths they would give one, and two
/// different credentials would share a tunnel.
fn proxyCredentialDigest(proxy: ?engine.Proxy) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
    if (proxy) |p| {
        for ([_][]const u8{ p.authorization, p.user, p.password }) |part| {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, part.len, .big);
            hash.update(&length);
            hash.update(part);
        }
    }
    var out: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hash.final(&out);
    return out;
}

/// One open connection and the origin it may serve again.
///
/// Heap-allocated by the pool's allocator, and never held by value. The
/// TLS session inside `connection` holds the address of the connection's
/// own buffers, so this value must not move, and it must outlive the
/// `Exchange` that borrows it: an exchange hands it back to the pool at
/// `close`.
const Pooled = struct {
    connection: zurl_net.Connection,
    /// Null when this connection can never go back to the pool. See
    /// `Origin.init` for the one reason.
    origin: ?Origin,
    /// The HTTP/2 session on this connection, when the peer chose `h2`
    /// through ALPN. Null for every HTTP/1.1 connection.
    ///
    /// **It belongs to the connection and not to one request.** The HPACK
    /// tables are built by every header block that crossed the connection,
    /// and the flow-control windows and the stream counter are connection
    /// state in the same way. A session rebuilt for a second request would
    /// send the connection preface twice and would decode nothing.
    ///
    /// Owned here, and freed by `Pool.close`, which is the one place a
    /// connection ends.
    h2_session: ?*h2.Session = null,
    /// How many exchanges hold this connection now.
    ///
    /// **One for an HTTP/1.1 connection, and one or more for a shared
    /// HTTP/2 one.** An HTTP/1.1 connection carries one request at a time,
    /// so it goes from the idle list to one exchange and back. An HTTP/2
    /// connection in a shared pool carries a stream for each exchange that
    /// joined it, and the last one to let go is the one that decides where
    /// the connection goes.
    ///
    /// Zero for a connection that is idle in the pool. Written under the
    /// pool lock and nowhere else.
    leases: usize = 0,
    /// Whether `Pool.active` holds this connection.
    ///
    /// The active list is how a second task finds a connection that is in
    /// use and has room for one more stream. A connection leaves it when
    /// the last lease ends, and at once when any holder found it unfit.
    listed: bool = false,
    /// Whether this connection must be closed when the last lease ends.
    ///
    /// A holder that found the connection unfit sets it. The connection
    /// cannot be closed there and then, because another holder may still be
    /// reading a stream on it, so it leaves the active list at once and the
    /// last holder out closes it.
    poisoned: bool = false,
};

/// How many connections a pool tracks that are in use and may carry one
/// more HTTP/2 stream.
///
/// **A bound on the list and not on the sharing.** Each entry is one
/// pointer, so the list itself costs 128 bytes. What it bounds is how many
/// origins a `-Z` run can multiplex over at once: a run that moves between
/// more origins than this dials a second connection for the ones that fell
/// off, which is what it did before sharing existed. Sixteen is twice the
/// eight workers `-Z` runs by default, so an ordinary run never reaches it.
const pool_active_max: usize = 16;

/// How many origins a pool records as being dialed right now.
///
/// **This is what makes one connection out of eight.** Eight `-Z` workers
/// start at once and find an empty pool. Without this table each of them
/// dials, and the connection the first one opens is published too late to
/// help any of them. With it, one worker marks the origin and dials, and
/// the others wait for that dial rather than start one of their own. curl's
/// own parallel path holds a transfer back the same way while a connection
/// to its host is coming up.
///
/// A table that is full costs nothing but a connection: the worker that
/// found no room dials without a marker, exactly as it did before. Eight is
/// the default worker count of `-Z`, so a run over eight different origins
/// still marks every one of them.
const pool_dialing_max: usize = 8;

/// The idle connections one engine may send another request on.
///
/// **On the heap, addressed through `Engine.pool`.** `zurl.Client` holds
/// its engine by value and `Client.init` returns that whole value, so the
/// address of an `Engine` is not stable, and an `Exchange` must be able to
/// find the pool at `close` however the engine moved. `Engine.head_log`
/// is on the heap for the same reason.
///
/// Allocated at the first `openOnce` rather than at `Engine.init`, which
/// returns an `Engine` and has no way to report an allocation failure. An
/// engine that never opens a request therefore pays nothing for this.
///
/// The list is oldest first. `take` walks it from the back, so the
/// connection that was returned most recently is the one tried first: it
/// is the one a peer is least likely to have closed while it sat idle.
/// **Two tasks may reach a shared pool, and only a shared one.** `shared`
/// is the whole switch, and `createShared` is the one way it becomes true.
/// A pool one engine owns takes an uncontended lock and behaves exactly as
/// it did before this field existed. A shared pool does three more things:
///
/// - It keys on `Origin.trust` as well, because the connections in it were
///   verified by more than one `Client`.
/// - It keeps `active`, the connections that are in use and can carry one
///   more HTTP/2 stream. That is what lets eight transfers ride one socket.
/// - It keeps `dialing`, the origins a task is opening right now, so seven
///   tasks wait for one handshake instead of starting seven.
///
/// **The lock order is this pool's lock and then a session's.** `lease`
/// reads `h2.Session.usable` and `hasRoom` while it holds this lock, so no
/// path may ask for this lock while it holds a session lock.
/// `h2.Exchange.closeImpl` is the one place that had to be written around
/// the rule, and it lets the session go before it calls `release`.
const Pool = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Guards every field below, and every `Pooled` field the pool writes.
    lock: std.Io.Mutex,
    /// Wakes the tasks waiting for a dial that another task is running.
    ready: std.Io.Condition,
    /// Whether more than one engine may reach this pool. See the note
    /// above.
    shared: bool,
    /// How many engines hold this pool. One for a pool an engine made for
    /// itself. A shared pool starts at one for its creator and counts up
    /// for each engine that joins, so the last one out frees it.
    refs: usize,
    idle: [pool_idle_max]*Pooled,
    len: usize,
    /// Connections that are in use and may carry one more stream.
    active: [pool_active_max]*Pooled,
    active_len: usize,
    /// Origins a task is dialing right now. See `pool_dialing_max`.
    dialing: [pool_dialing_max]Origin,
    dialing_len: usize,
    /// How many zstd windows the exchanges of this pool hold right now.
    ///
    /// One for each open exchange whose response named `zstd`, and each
    /// one is 8.1 MiB. `takeZstdWindow` counts up and `releaseZstdWindow`
    /// counts down, both under the pool lock. See `zstd_windows_max`.
    zstd_windows: usize,

    fn create(allocator: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!*Pool {
        const self = try allocator.create(Pool);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .lock = .init,
            .ready = .init,
            .shared = false,
            .refs = 1,
            .idle = undefined,
            .len = 0,
            .active = undefined,
            .active_len = 0,
            .dialing = undefined,
            .dialing_len = 0,
            .zstd_windows = 0,
        };
        return self;
    }

    /// Claims room for one zstd window, or refuses.
    ///
    /// Pair every true answer with one `releaseZstdWindow`. See
    /// `zstd_windows_max` for the bound and why it sits here.
    fn takeZstdWindow(self: *Pool) bool {
        self.acquire();
        defer self.release_lock();
        if (self.zstd_windows >= zstd_windows_max) return false;
        self.zstd_windows += 1;
        return true;
    }

    /// Gives back the room one `takeZstdWindow` claimed.
    fn releaseZstdWindow(self: *Pool) void {
        self.acquire();
        defer self.release_lock();
        // A release with no matching claim is a programmer error, and the
        // count would wrap without this. `closeImpl` frees the buffer and
        // releases the room together, so the two cannot come apart.
        std.debug.assert(self.zstd_windows > 0);
        self.zstd_windows -= 1;
    }

    /// Takes the pool lock.
    ///
    /// **Uncancelable.** Every caller of this leaves the pool in a state
    /// the next task can read, and a task that stopped while it held the
    /// lock would leave a connection in no list and in nobody's hands. A
    /// cancel is honoured at the dial or the transfer around it.
    fn acquire(self: *Pool) void {
        self.lock.lockUncancelable(self.io);
    }

    fn release_lock(self: *Pool) void {
        self.lock.unlock(self.io);
    }

    /// Closes every idle connection and frees the pool, once the last
    /// engine that held it has let go.
    ///
    /// The caller must have closed every `Exchange` of that engine first.
    /// An open exchange holds a `*Pooled` that is in no list this walks.
    fn destroy(self: *Pool) void {
        self.acquire();
        std.debug.assert(self.refs > 0);
        self.refs -= 1;
        if (self.refs != 0) {
            self.release_lock();
            return;
        }
        for (self.idle[0..self.len]) |c| self.close(c);
        self.len = 0;
        // A shared pool that still listed a connection would be freeing the
        // list that holds it. Every exchange has closed by here, so every
        // lease has ended and `release` already emptied this.
        std.debug.assert(self.active_len == 0);
        self.release_lock();
        self.allocator.destroy(self);
    }

    /// Closes one connection and frees it. This is what puts the socket
    /// back. The caller holds the lock and the connection has no lease.
    fn close(self: *Pool, c: *Pooled) void {
        std.debug.assert(c.leases == 0);
        std.debug.assert(!c.listed);
        // The HTTP/2 session goes with the connection it belongs to. It
        // holds the frame buffer and the HPACK tables, and neither means
        // anything once the socket is gone.
        if (c.h2_session) |session| session.destroy();
        c.connection.deinit();
        self.allocator.destroy(c);
    }

    /// The idle connection that may serve `key`, or null when the pool
    /// holds none. The caller holds the lock.
    ///
    /// The answer leaves the pool with one lease on it. A connection is
    /// either idle in this list or held by its leases, never both, so two
    /// requests can never share one HTTP/1.1 socket.
    fn take(self: *Pool, key: *const Origin) ?*Pooled {
        var i = self.len;
        while (i > 0) {
            i -= 1;
            const c = self.idle[i];
            // Every entry carries an origin: `put` closes one that does
            // not rather than store it.
            const origin: *const Origin = if (c.origin) |*o| o else continue;
            if (!origin.eql(key)) continue;
            self.remove(i);
            c.leases = 1;
            return c;
        }
        return null;
    }

    /// Takes `c` back as an idle connection, or closes it when the pool
    /// cannot keep it. The caller holds the lock.
    ///
    /// A full pool closes its oldest idle connection to make room, which
    /// is what curl does. The oldest is the one that has sat unused
    /// longest, so it is the one a peer is most likely to have closed
    /// already, and the request that finds it dead pays a retry.
    ///
    /// **The caller decides whether `c` is fit to keep.** See
    /// `Exchange.reusable`, which is the only reader of that question.
    fn put(self: *Pool, c: *Pooled) void {
        std.debug.assert(c.leases == 0);
        std.debug.assert(!c.listed);
        if (c.origin == null) return self.close(c);
        if (self.len == self.idle.len) {
            const oldest = self.idle[0];
            self.remove(0);
            self.close(oldest);
        }
        self.idle[self.len] = c;
        self.len += 1;
    }

    /// Drops entry `index` and keeps the order of the rest, because the
    /// order is the age order that `put` and `take` both read.
    fn remove(self: *Pool, index: usize) void {
        var i = index;
        while (i + 1 < self.len) : (i += 1) self.idle[i] = self.idle[i + 1];
        self.len -= 1;
    }

    /// Records that this task is dialing `key`, and says whether the
    /// record was made. The caller holds the lock.
    ///
    /// A false answer means the table is full. The dial still runs; only
    /// the chance for another task to wait for it is lost.
    fn markDialing(self: *Pool, key: *const Origin) bool {
        if (self.dialing_len == self.dialing.len) return false;
        self.dialing[self.dialing_len] = key.*;
        self.dialing_len += 1;
        return true;
    }

    /// Takes the record `markDialing` made back, and wakes whoever waited
    /// for it. The caller holds the lock.
    fn clearDialing(self: *Pool, key: *const Origin) void {
        var i: usize = 0;
        while (i < self.dialing_len) : (i += 1) {
            if (!self.dialing[i].eql(key)) continue;
            var j = i;
            while (j + 1 < self.dialing_len) : (j += 1) self.dialing[j] = self.dialing[j + 1];
            self.dialing_len -= 1;
            // Every waiter looks again. One dial can free more than one of
            // them, and a dial that failed frees them to dial themselves.
            self.ready.broadcast(self.io);
            return;
        }
    }

    /// Whether a task is dialing `key` right now. The caller holds the
    /// lock.
    fn isDialing(self: *Pool, key: *const Origin) bool {
        for (self.dialing[0..self.dialing_len]) |*each| {
            if (each.eql(key)) return true;
        }
        return false;
    }

    /// Claims a stream on a connection that is already carrying some, or
    /// null when no such connection is here. The caller holds the lock.
    ///
    /// The answer comes back with one more lease and one claimed stream
    /// slot, so the caller must reach `h2.open` or give both back. See
    /// `h2.Session.reserve`.
    fn lease(self: *Pool, key: *const Origin) ?*Pooled {
        for (self.active[0..self.active_len]) |c| {
            const origin: *const Origin = if (c.origin) |*o| o else continue;
            if (!origin.eql(key)) continue;
            const session = c.h2_session orelse continue;
            if (c.poisoned) continue;
            if (!session.reserve()) continue;
            c.leases += 1;
            return c;
        }
        return null;
    }

    /// Puts `c` where a second task can find it and join it. The caller
    /// holds the lock, and `c` already carries one lease and one HTTP/2
    /// session.
    ///
    /// A table that is full keeps the connection to its one holder, which
    /// is what an unshared pool does with every connection.
    fn publish(self: *Pool, c: *Pooled) void {
        std.debug.assert(c.h2_session != null);
        std.debug.assert(c.leases > 0);
        if (c.listed) return;
        if (c.origin == null) return;
        if (self.active_len == self.active.len) return;
        self.active[self.active_len] = c;
        self.active_len += 1;
        c.listed = true;
    }

    /// Takes `c` out of the active list. The caller holds the lock.
    fn unpublish(self: *Pool, c: *Pooled) void {
        if (!c.listed) return;
        var i: usize = 0;
        while (i < self.active_len) : (i += 1) {
            if (self.active[i] != c) continue;
            var j = i;
            while (j + 1 < self.active_len) : (j += 1) self.active[j] = self.active[j + 1];
            self.active_len -= 1;
            break;
        }
        c.listed = false;
    }

    /// Gives one holder's claim on `c` back, and decides where the
    /// connection goes when the last holder lets go.
    ///
    /// `keep` false says this holder found the connection unfit. Such a
    /// connection leaves the active list at once, so no request joins it
    /// after this, and it is closed when the last holder lets go. It cannot
    /// be closed here: another holder may still be reading a stream on it.
    fn releaseOne(self: *Pool, c: *Pooled, keep: bool) void {
        self.acquire();
        defer self.release_lock();
        if (!keep) {
            c.poisoned = true;
            self.unpublish(c);
        }
        std.debug.assert(c.leases > 0);
        c.leases -= 1;
        if (c.leases != 0) return;
        self.unpublish(c);
        if (c.poisoned) return self.close(c);
        self.put(c);
    }
};

/// Rejects a request header that would change the shape of the request
/// head on the wire.
///
/// `writeRequestHead` writes every caller header out verbatim, which is
/// what `std.http.Client.request` did before it and what curl does. That
/// call only asserted against a CR or an LF. An assert is the wrong tool
/// here: headers cross a public seam as data, so a value like
/// `a\r\nX-Injected: 1` is untrusted input, not a programmer error. The
/// assert also disappears in ReleaseFast, where the injected header then
/// goes out on the wire.
///
/// A name must be an RFC 9110 token, which rules out a colon, a space, a
/// CR, an LF, and a NUL. A value may hold any visible character and a
/// horizontal tab, but no C0 control and no DEL.
fn validateHeaders(headers: []const std.http.Header) engine.OpenError!void {
    for (headers) |header| {
        try validateHeaderName(header.name);
        try validateHeaderValue(header.value);
    }
}

/// Rejects a header name that is not an RFC 9110 token.
///
/// The set itself is `engine.headerNameIsToken`, which h2 and h3 ask as
/// well. It was written out here once and copied into those two engines,
/// and the copies then drifted: both read a response field name for its
/// case alone, so a server put a carriage return and a line feed in a name
/// and forged a whole header line. One set, asked from one place, is what
/// stops a fourth copy from being written.
///
/// `.mixed` and not `.lower`, because a request header carries the case a
/// caller wrote. Only a response field name is held to lower case, by RFC
/// 9113 section 8.2.1 and RFC 9114 section 4.2.
fn validateHeaderName(name: []const u8) engine.OpenError!void {
    if (!engine.headerNameIsToken(name, .mixed)) return error.InvalidHeader;
}

/// Rejects a header value that holds a C0 control or a DEL.
///
/// This is its own function because `user_agent` is a header value too,
/// and it does not travel in a `std.http.Header`. `writeRequestHead`
/// writes it as `prefix ++ value ++ "\r\n"` with no check of its own, so
/// an unchecked value there puts a header of the caller's choosing on the
/// wire, exactly as an unchecked caller header would.
///
/// The byte rule lives in `engine.headerValueHasControl`, which `h2` asks
/// as well, so both engines answer one question one way.
fn validateHeaderValue(value: []const u8) engine.OpenError!void {
    if (engine.headerValueHasControl(value)) return error.InvalidHeader;
}

/// Refuses every header that may not travel in the ordinary header list.
///
/// A secret has one path through this engine, which is the request's
/// `secrets` field. That path keeps the secret inside the origin the
/// caller named. An ordinary header goes out again on every hop of a
/// redirect chain, so the same value here would reach whichever host the
/// first server pointed at. Refusing it is what makes the one path the
/// only path: a caller cannot re-open the leak by putting a secret where
/// it looks like an ordinary header.
///
/// `engine.origin_bound_headers` names the secrets, and
/// `engine.refused_headers` names the headers this engine sends nowhere at
/// all. Both are matched without regard to case. Two waves closed this
/// leak for one header name and left it open for the next one, so the
/// check reads the set and never a single name.
fn refuseHeaders(headers: []const std.http.Header) engine.OpenError!void {
    for (headers) |header| {
        if (engine.isOriginBound(header.name)) return error.InvalidHeader;
        if (engine.isRefused(header.name)) return error.InvalidHeader;
    }
}

/// Refuses a `secrets` entry that the origin-bound set does not name.
///
/// The secrets channel carries exactly `engine.origin_bound_headers`. A
/// name outside that set would get the same withholding rule without ever
/// being written down as a secret, so a reader of
/// `engine.origin_bound_headers` would no longer see the whole set. A name
/// in `engine.refused_headers` has no destination at all, secrets channel
/// or not.
fn refuseUnnamedSecrets(secrets: []const std.http.Header) engine.OpenError!void {
    for (secrets) |secret| {
        if (!engine.isOriginBound(secret.name)) return error.InvalidHeader;
    }
}

/// Rejects a `Location` value that would put a header of the server's
/// choosing on the wire.
///
/// A url a person types goes through `zurl_core.url.parse`, which refuses
/// these bytes. A redirect target never goes through it: the server writes
/// the target, `std.http.Client.Response.Head.parse` splits a head on
/// CRLF, so a bare LF survives inside a header value, and `std.Uri` puts
/// no rule at all on the characters of a path. The next request line then
/// carries the target exactly as the server wrote it, and RFC 9112 section
/// 2.2 lets a recipient read a lone LF as the end of a line. So a
/// `Location: /a\nX-Injected: yes` reached the peer as a request line plus
/// a header nobody asked for.
///
/// The rule is `zurl_core.url.hasUnsafeByte`, the one `url.parse` applies,
/// so a url and a redirect target are held to one rule and not two. A
/// server is untrusted input, so this is a runtime fault and not an
/// assertion.
fn validateLocation(location: []const u8) engine.OpenError!void {
    if (zurl_core.url.hasUnsafeByte(location)) return error.InvalidUrl;
}

/// Room for a jar's `Cookie` value and one `Cookie` the caller wrote,
/// joined into the single line RFC 6265 section 5.4 sends.
///
/// Twice the jar's own bound, so a merge of a full jar line and a caller
/// header of the same size still fits. `mergeCookies` refuses anything
/// past it rather than send a cookie list cut in half.
const cookie_buffer_len = engine.cookie_header_len_max * 2;

/// The index in `secrets` of the caller's own `Cookie` header, or null
/// when the caller wrote none.
///
/// `refuseUnnamedSecrets` has already refused every name outside
/// `engine.origin_bound_headers`, so this looks for the one name that set
/// can hold beside `Authorization`.
fn findCookieSecret(secrets: []const std.http.Header) ?usize {
    for (secrets, 0..) |secret, index| {
        if (std.ascii.eqlIgnoreCase(secret.name, "Cookie")) return index;
    }
    return null;
}

/// Joins the jar's cookies and the caller's own `Cookie` value into one
/// header value, inside `buffer`.
///
/// `jar_value` must already sit at the front of `buffer`, which is what
/// `engine.CookieJar.send` wrote it into. The joined text is written
/// behind it, so one buffer serves both.
///
/// **The jar's cookies come first, then the caller's.** Measured against
/// curl 8.21.0 with `-b 'pre=set'` and a jar holding one cookie: the
/// header on the wire read `Cookie: hop=one; pre=set`, the jar's cookie
/// first and the command line's text last.
///
/// `error.InvalidHeader` when the two together pass `cookie_buffer_len`. A
/// value cut short is a different cookie list, and a server would read it
/// as a session that never existed. Refusing says so, where truncation
/// would not.
fn mergeCookies(
    buffer: *[cookie_buffer_len]u8,
    jar_value: []const u8,
    caller_value: []const u8,
) engine.OpenError![]const u8 {
    std.debug.assert(jar_value.ptr == buffer.ptr);
    const separator = "; ";
    const total = jar_value.len + separator.len + caller_value.len;
    if (total > buffer.len) return error.InvalidHeader;
    @memcpy(buffer[jar_value.len..][0..separator.len], separator);
    @memcpy(buffer[jar_value.len + separator.len ..][0..caller_value.len], caller_value);
    return buffer[0..total];
}

/// The text of `component`, whichever form it holds.
///
/// `zurl-http` never percent-encodes and never decodes a url component: it
/// writes what the url wrote. So the two forms carry the same bytes here,
/// and the tag only says who wrote them.
fn componentText(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |raw| raw,
        .percent_encoded => |encoded| encoded,
    };
}

/// `host` with a bracket pair taken off, when it carries one.
///
/// The two url parsers of this project disagree about the brackets of an
/// IPv6 host. `zurl_core.url.parse` takes them off, so `Url.host` reads
/// `::1`. `std.Uri.parseAfterScheme` keeps them, so a host component from
/// a redirect target reads `[::1]`. This engine follows `zurl_core`: every
/// host it holds is bare, and `writeHost` is the one place that puts the
/// brackets back.
fn bareHost(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return host[1 .. host.len - 1];
    }
    return host;
}

/// Writes `host` the way an authority writes it, with the brackets an
/// IPv6 address needs.
///
/// **`zurl_core.Url.host` holds no brackets.** `zurl_core.url.parse`
/// takes them off, so `http://[::1]:8080/` reaches this engine as the host
/// `::1` and the port 8080. Written plainly, that authority reads
/// `::1:8080`, which names the host `::1:8080` with no port at all, or
/// nothing a peer can read. The brackets are what tell the colons inside
/// the address apart from the colon before a port.
///
/// A colon is the whole test. `zurl_net.tcp.Host.init` accepts a name of
/// letters, digits, `-`, and `.`, and an address of hex digits, `.`, and
/// `:`, so only an IPv6 address holds one.
///
/// `bareHost` runs first, so a host that already carries brackets gets one
/// pair and never two.
///
/// **And the zone id comes off.** `zurl_core.url.hostWithoutZone` says
/// why: RFC 6874 gives a zone id meaning on the local host alone, so
/// `http://[fe80::1%25eth0]/` sends `Host: [fe80::1]`. curl 8.21.0 sends
/// the same line, measured.
///
/// The text goes out as it reads. `std.Uri.Component.formatHost` escapes
/// a `.raw` host, but every byte a host can hold by the time it gets here
/// is a byte that call leaves alone, so the two agree and this one is
/// easier to read beside `writeUri`.
fn writeHost(w: *std.Io.Writer, host: []const u8) std.Io.Writer.Error!void {
    const bare = zurl_core.url.hostWithoutZone(bareHost(host));
    const literal = std.mem.indexOfScalar(u8, bare, ':') != null;
    if (literal) try w.writeByte('[');
    try w.writeAll(bare);
    if (literal) try w.writeByte(']');
}

/// Writes the authority of `uri`: the host, and the port when `uri` names
/// one.
///
/// This is `std.Uri.writeToStream` with the `authority` flag, plus the
/// brackets of `writeHost`. `std` writes the host with no brackets, so a
/// `host:` line built from it read `host: ::1:8080`.
///
/// No userinfo. `requestUri` puts none in, and `writeRequestHead` says why
/// a credential must not reach the wire from a url.
fn writeAuthority(w: *std.Io.Writer, uri: std.Uri) std.Io.Writer.Error!void {
    // `requestUri` always names a host, and a `host:` line with an empty
    // value would name none. So this is a check on this file and not on
    // the caller, the same way `writeRequestHead` checks a header name.
    std.debug.assert(uri.host != null);
    try writeHost(w, componentText(uri.host.?));
    if (uri.port) |port| try w.print(":{d}", .{port});
}

/// The longest host this engine masks for `std.Uri.resolveInPlace`.
///
/// `resolveInPlace` runs every host through `std.Io.net.HostName.validate`,
/// which refuses anything longer than this, so a longer host cannot get
/// through that call whether it is masked or not.
const masked_host_max = std.Io.net.HostName.max_len;

/// The byte that stands in for a masked one.
///
/// A digit, so the masked text stays a host name of digits and dots
/// however the address is written. A `-` would not: it may not open or
/// close a label, and `[::1]` opens with a bracket and two colons.
const host_mask_byte: u8 = '0';

/// Whether `byte` is one an IPv6 authority adds and a host name check
/// refuses.
///
/// These three and no more. Every other byte keeps whatever verdict
/// `std.Io.net.HostName.validate` gives it, so the mask cannot make a bad
/// host read as a good one.
fn maskedByte(byte: u8) bool {
    return byte == ':' or byte == '[' or byte == ']';
}

/// Writes `host` into `out` with every byte of `maskedByte` replaced, and
/// returns the part of `out` that holds it.
///
/// **`std.Uri.resolveInPlace` refuses an IPv6 host outright.** It runs
/// every host it reads through `std.Io.net.HostName.validate`, which
/// accepts letters, digits, `-`, and `.` and nothing else. So a redirect
/// from an address, or to one, stopped at that call, and this engine
/// reported `InvalidUrl` for a chain curl 8.21.0 follows.
///
/// **The mask never reaches a socket and never reaches a user.** It is
/// read by that one call, which uses the host only to decide whether the
/// target it built is well formed. `nextTarget` keeps the true host, and
/// `writeUri` writes that one into the url text of the next hop.
///
/// The mask keeps the length, so the text it replaces stays where it was.
fn maskHost(out: []u8, host: []const u8) engine.OpenError![]const u8 {
    if (host.len > out.len) return error.InvalidUrl;
    for (host, out[0..host.len]) |byte, *masked| {
        masked.* = if (maskedByte(byte)) host_mask_byte else byte;
    }
    return out[0..host.len];
}

/// The port an authority must spell out, or null when `port` is the
/// default for `scheme` and the authority must leave it out.
///
/// `zurl_core.Url.port` is never null for a url this engine opens.
/// `zurl_core.url.parse` fills the default for the scheme when the url
/// names no port, and `resolveProtocol` has already refused every scheme
/// but `http` and `https`, both of which the built-in table names. So this
/// engine cannot tell a port a person typed from a port that `parse`
/// supplied. It must therefore write neither, which is what curl does:
/// curl 8.21.0
/// sends `host: example.com` for `http://example.com:80/` and for
/// `http://example.com/` alike, and sends `host: example.com:8080` only
/// for a port that is not the default.
///
/// **A default port that reaches the wire comes back.** A `host:` value
/// travels to the peer, and github.com and wikipedia.org copy that value
/// into the `location:` of the redirect that sends a client to `https`.
/// A `host: github.com:80` therefore earns
/// `location: https://github.com:80/`, the next hop reads port 80 out of
/// that text, and it opens a TLS session on the port that speaks cleartext
/// HTTP. The peer answers with an HTTP status line, the TLS client reads
/// `HTTP/1.1 4` as a record header, and the handshake stops at
/// `error.TlsRecordOverflow`.
///
/// RFC 3986 section 6.2.3 says the same rule from the other side: a url
/// that names the default port for its scheme and a url that names no port
/// are one url. So dropping the port loses nothing a peer can act on.
///
/// A scheme with no default keeps whatever port it holds, and a url that
/// holds no port at all writes none.
fn authorityPort(scheme: []const u8, port: ?u16) ?u16 {
    const named = port orelse return null;
    const default = zurl_core.url.defaultPort(scheme) orelse return named;
    return if (named == default) null else named;
}

/// The `std.Uri` one hop writes its request line and its `host:` line
/// from.
///
/// `scheme` is the canonical spelling of the protocol, `http` or `https`,
/// and never the spelling the url used. A url may name the scheme in any
/// case, and the wire form must not follow it.
///
/// The userinfo stays out on purpose. A `user` or a `password` here would
/// reach the wire as an `authorization: Basic base64(user:password)`
/// header, which is what `std.http.Client.Request.sendHead` built from
/// one. That put the cleartext password on the wire, in reversible base64,
/// beside every header the caller built, including a `Digest` response
/// whose whole point is that the password never travels. It also broke RFC
/// 7235, which allows one `Authorization` header per request.
/// `writeRequestHead` writes no such header at all, and the empty userinfo
/// keeps that true even for the `host:` line, which is written from this
/// same value.
///
/// The front package reads the same userinfo from `zurl_core.Url` and
/// builds whatever credential it decides to send, so nothing here needs
/// it.
///
/// The path, the query, and the fragment are `.percent_encoded` because
/// `zurl_core.url.parse` leaves them exactly as the url wrote them,
/// escapes included. `Component.formatPath` escapes a `.raw` value again,
/// so `/a%20b` used to reach the wire as `/a%2520b`: a different resource,
/// and a request line that no longer matched the target a `Digest`
/// response signs.
///
/// The port stays out when it is the default for the scheme. See
/// `authorityPort` for what a default port on the wire costs.
fn requestUri(scheme: []const u8, url: zurl_core.Url) std.Uri {
    return .{
        .scheme = scheme,
        .user = null,
        .password = null,
        .host = .{ .raw = url.host },
        .port = authorityPort(scheme, url.port),
        .path = .{ .percent_encoded = url.path },
        .query = if (url.query) |q| .{ .percent_encoded = q } else null,
        .fragment = if (url.fragment) |f| .{ .percent_encoded = f } else null,
    };
}

/// Writes `uri` into `out` as url text, with `host` as its host, and
/// returns the part of `out` that holds it.
///
/// `followChain` resolves a redirect target with `std.Uri.resolveInPlace`,
/// the same call `std.http.Client.Request.redirect` makes, and then reads
/// the result back through `zurl_core.url.parse`. Going through the text
/// is what puts every part of the target under the url rules: `parse`
/// checks the host, the path, the query, and the fragment of a redirect
/// target exactly as it checks the ones a person typed.
///
/// `host` is a parameter, and not `uri.host`, because `resolveInPlace`
/// cannot read an address. `nextTarget` masks the host it gives that call
/// and keeps the true one. See `maskHost`.
///
/// The userinfo is dropped. This engine builds no credential of its own
/// from a url, and a credential must not follow a redirect anyway.
fn writeUri(out: []u8, uri: std.Uri, host: []const u8) engine.OpenError![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    // A target with no authority names no host, and no host is no url.
    if (uri.host == null) return error.InvalidUrl;
    writer.writeAll(uri.scheme) catch return error.InvalidUrl;
    writer.writeAll("://") catch return error.InvalidUrl;
    // `writeHost` puts the brackets of an IPv6 address back. The `host:`
    // line reads the same rule through `writeAuthority`, so the url text
    // of a hop and the authority on the wire cannot drift apart.
    writeHost(&writer, host) catch return error.InvalidUrl;
    // A default port is left out, so the url text of a hop reads the way
    // curl reports it and the way a person wrote it. `std.Uri` keeps the
    // port of the base url on a relative target, and that port is the one
    // `zurl_core.url.parse` filled in, not one a peer named. See
    // `authorityPort`.
    if (uri.port) |port| {
        if (authorityPort(uri.scheme, port)) |explicit| {
            writer.print(":{d}", .{explicit}) catch return error.InvalidUrl;
        }
    }
    const path = componentText(uri.path);
    // A target with no path names the root, the same way `url.parse`
    // reads a url with no path.
    writer.writeAll(if (path.len == 0) "/" else path) catch return error.InvalidUrl;
    if (uri.query) |query| {
        writer.writeByte('?') catch return error.InvalidUrl;
        writer.writeAll(componentText(query)) catch return error.InvalidUrl;
    }
    if (uri.fragment) |fragment| {
        writer.writeByte('#') catch return error.InvalidUrl;
        writer.writeAll(componentText(fragment)) catch return error.InvalidUrl;
    }
    return writer.buffered();
}

/// Whether this engine can open a url of `scheme`.
///
/// http and https, and nothing else. This is the **build** and not a
/// policy: `zurl_core.redirect` owns which protocols a redirect may name,
/// and this says only which of them `openOnce` can dial. A scheme that
/// passes the policy and fails here is `error.RedirectToOtherProtocol`,
/// which hands the hop to the caller.
///
/// Compared without regard to case, per RFC 3986.
fn speaksScheme(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "https");
}

/// Whether `head` is a redirect that this engine follows.
///
/// Not every 3xx is one. A `304 Not Modified` answers a conditional
/// request, and it belongs to the caller. An engine that resends on any
/// 3xx threw that answer away and asked again, so a caller who sent
/// `If-None-Match` received a `200` and a body where the server had said
/// the copy was still good.
///
/// A `Location` is required too. A redirect that names no target says
/// where to go next as little as a `200` does, so the answer belongs to
/// the caller and a resend to get away from the credential would gain
/// nothing.
fn followableRedirect(head: engine.Head) bool {
    if (head.status < 300 or head.status >= 400) return false;
    if (head.status == @intFromEnum(std.http.Status.not_modified)) return false;
    return head.location != null;
}

/// The `engine.OpenError` that a `zurl_core.Error` from `zurl-net` means,
/// or null when this file has no name for it.
///
/// `zurl-net` owns the map from a dial or handshake fault onto the zurl
/// error taxonomy, and this file owns `engine.OpenError`. This is the join
/// between the two, and it is not a second table: it renames, and it never
/// decides what a fault means. A row that decided anything here could
/// disagree with `zurl-net/errors.zig`, and then a certificate that did
/// not verify would reach a user as something else again.
///
/// The comptime block below proves every fault `zurl-net` can report has
/// an arm, so the `else` cannot be reached from `mapSetupError`.
fn openErrorFor(err: zurl_core.Error) ?engine.OpenError {
    return switch (err) {
        error.CouldNotResolveHost => error.CouldNotResolveHost,
        error.CouldNotConnect => error.CouldNotConnect,
        error.OperationTimedOut => error.OperationTimedOut,
        error.SslConnectError => error.SslConnectError,
        error.PeerFailedVerification => error.PeerFailedVerification,
        error.CaCertBadFile => error.CaCertBadFile,
        error.ReadError => error.ReadError,
        error.WriteError => error.WriteError,
        error.OutOfMemory => error.OutOfMemory,
        // `zurl-net` reports a cancel as the same shape a callback that
        // answers "stop" has, and `engine.OpenError` calls that
        // `Canceled`. `zurl-http/errors.zig` maps it back to
        // `AbortedByCallback`, so the round trip keeps one meaning.
        error.AbortedByCallback => error.Canceled,
        else => null,
    };
}

comptime {
    // Every fault `zurl-net` can report must land on a name this engine
    // has. A name with no arm would fall to the branch in `mapSetupError`
    // and reach a user as a handshake failure, whatever it really was,
    // which is the exact defect this whole engine exists to close.
    //
    // The walk calls `zurl_net.errors.toCore` for each member of
    // `SetupError`, and that call scans a table of about sixty rows, so
    // the product needs far more than the default branch quota.
    @setEvalBranchQuota(200_000);
    for (@typeInfo(zurl_net.errors.SetupError).error_set.?) |field| {
        const err: zurl_net.errors.SetupError = @field(zurl_net.errors.SetupError, field.name);
        if (openErrorFor(zurl_net.errors.toCore(err)) == null) @compileError(
            "h1.zig: zurl-net can report error." ++ field.name ++
                ", and `openErrorFor` has no arm for what it means",
        );
    }
}

/// What a user reads if a setup fault ever reaches `mapSetupError` with no
/// arm. It names the function, because that is where the fix goes.
const setup_error_unmapped_message =
    "this connection fault has no arm in h1.zig, so zurl cannot name its cause";

/// Maps a dial or handshake fault onto `engine.OpenError`, and keeps the
/// cause where the caller can read it.
///
/// The cause is the deliverable. Four different certificate faults are all
/// exit 60, so the exit code alone cannot say which check refused the
/// peer. `zurl_net.errors.map` writes that sentence, and this puts it in
/// `Engine.open_cause`, which `Engine.cause` hands back.
fn mapSetupError(engine_state: *Engine, err: zurl_net.errors.SetupError) engine.OpenError {
    const mapping = zurl_net.errors.map(err);
    engine_state.open_cause = mapping.message;
    return openErrorFor(mapping.err) orelse unmapped: {
        // Not reachable: the comptime block above fails the build before a
        // fault can arrive here with no arm. It stays a branch because
        // `unreachable` is removed in ReleaseFast, which is the build a
        // user runs, and it is loud rather than quiet.
        engine_state.open_cause = setup_error_unmapped_message;
        break :unmapped error.SslConnectError;
    };
}

/// Maps a `std.http.Reader.receiveHead` failure onto `engine.OpenError`.
///
/// A server is untrusted input: a head that never ends, a head past the
/// bound, and a connection cut before the head arrives are all ordinary
/// errors here, never a panic.
///
/// An oversized head gets its own name. It used to arrive as `ReadError`,
/// which told a user that a read failed and named no cause, so the one
/// fault a user can act on read like a network fault.
///
/// `error.HttpHeadersOversize` is the whole-head bound and never the
/// per-line one, because `Reader.max_head_len` is `head_len_max`.
/// `Exchange.receiveResponseHead` checks the line bound itself, over a
/// head this function already let through. See `head_len_max` and
/// `head_field_len_max`.
fn mapHeadError(err: std.http.Reader.HeadError) engine.OpenError {
    return switch (err) {
        error.HttpHeadersOversize => error.ResponseHeadTooLarge,
        error.HttpRequestTruncated,
        error.HttpConnectionClosing,
        error.ReadFailed,
        => error.ReadError,
    };
}

/// What a read raced against a deadline answered.
///
/// `engine.RacedRead` holds the three arms, because `h2` races a frame
/// read against the same deadline and `h3` reads the same answer off a
/// QUIC wait. Named here because every caller in this file writes it.
const RacedRead = engine.RacedRead;

/// Runs a read against a deadline and answers whichever ended first.
///
/// `engine.raceRead` is the whole of it. This engine races
/// `std.http.Reader.receiveHead` and each body `stream` or `discard`
/// through it. See `engine.raceRead` for why the bound sits on one read
/// and never on the transfer.
const raceRead = engine.raceRead;

/// Everything one connection setup needs, as one value.
///
/// `zurl_net.bounded.Setup` holds the fields. This engine is one of two
/// callers of that helper, and the other is `zurl-gopher`, so the dial and
/// the handshake are bounded once for both.
const Setup = zurl_net.bounded.Setup;

/// The TLS options one `https` hop opens with.
///
/// **This is the one place in zurl that turns peer verification off, and
/// it reads `req.insecure` and nothing else.** A function and not four
/// lines inside `dial`, so a test can name both answers and prove that no
/// input other than the flag can reach the second one. There is no
/// fallback path: a handshake that fails to verify is reported with
/// `error.PeerFailedVerification`, and never tried again without the
/// check.
///
/// Both halves of the check go together, which is what curl does. A host
/// name check is worthless against a peer whose chain nobody trusts, and a
/// trusted chain for the wrong host is worthless too. Measured against
/// curl 8.21.0: `-k` answers 200 for an expired certificate, a self-signed
/// one, and one carrying the wrong host name, and each of the three exits
/// 60 with no flag.
fn tlsSetup(
    req: engine.Request,
    lock: *std.Io.RwLock,
    bundle: *std.crypto.Certificate.Bundle,
) zurl_net.Connection.Tls {
    return .{
        .host = if (req.insecure) .none else .{ .explicit = req.url.host },
        // The engine verifies against the roots its owner loaded, and
        // against nothing else.
        .trust = if (req.insecure) .none else .{ .bundle = .{
            .lock = lock,
            .bundle = bundle,
        } },
        // **The end of a socket is not the end of a stream, and this
        // engine no longer says it is.** It used to set
        // `allow_truncation_attacks`, with the reason that HTTP carries
        // its own length through `Content-Length` and chunked framing. RFC
        // 9112 section 6.3 item 8 permits a third framing, where a
        // response carries neither field and the body ends when the stream
        // does. For that one the TLS `close_notify` alert is the only
        // thing that tells a whole body from a cut one, and with the flag
        // set a network attacker's FIN read as a whole body: the transfer
        // exited 0 and the caller got a short file with nothing to say so.
        //
        // **Leaving the flag off costs nothing for the other two
        // framings, because neither one reads that far.**
        // `std.http.Reader` stops a `Content-Length` body at its announced
        // length and a chunked body at its last chunk, so a peer that
        // closes without `close_notify` after a framed body is never read
        // again and never reports anything. That is also why curl
        // tolerates such a server: not a flag, but a reader that stopped.
        //
        // Measured against curl 8.21.0 and against this engine, over a
        // loopback TLS 1.3 server that answers one response and then
        // closes, `-k` on both sides:
        //
        // ```text
        // framing                close_notify   curl   zurl before   zurl now
        // close-delimited        sent            0      0             0
        // close-delimited        absent         56      0            56
        // content-length         absent          0      0             0
        // chunked                absent          0      0             0
        // content-length short   sent           18     18            18
        // content-length short   absent         56     18            56
        // ```
        //
        // The one row the flag was hiding is the second. curl's answer
        // there is `OpenSSL SSL_read: ... unexpected eof while reading`
        // and exit 56, and this engine now answers 56 as well.
        //
        // Every other protocol package in this tree already leaves this
        // off. HTTP was the one exception, and it is no longer one.
        .allow_truncation_attacks = false,
        // The transfer owns the floor, so it travels on the request and
        // reaches every hop of a redirect chain. A chain that starts on
        // `http` and lands on `https` opens that hop through this same
        // function, so the floor still applies to it. `Origin` carries the
        // floor too, so a pooled connection can never answer a request
        // that asked for a higher one.
        .min_version = req.tls_min_version,
        // And the ceiling, which reaches every hop the same way the floor
        // does.
        .max_version = req.tls_max_version,
        // **The ALPN offer, which is the whole of the protocol choice on a
        // TLS hop.** `--no-alpn` empties the list, which leaves the
        // extension out of the hello and leaves the hop on HTTP/1.1,
        // because a peer cannot choose a protocol it was never offered.
        // `--http1.1` narrows the list to one name for the same reason,
        // and `--http2-prior-knowledge` narrows it to the other name, so a
        // peer with no HTTP/2 ends the handshake instead of answering on
        // HTTP/1.1. The default offers both, and `sendOn` reads the answer
        // back to decide which engine speaks.
        // **`--http3` and `--http3-only` offer the default pair here, and
        // never `h3`.** A hop reaches this function over TCP, and RFC 9114
        // section 3.1 puts HTTP/3 on QUIC alone: a peer that chose `h3` on
        // a stream socket would leave the connection with no protocol
        // either side can speak. A hop under `--http3` that reaches this
        // line is the fallback hop, and curl offers the pair on it too.
        // Measured: `curl -v --http3 https://example.com/` printed
        // `ALPN: curl offers h2,http/1.1`. `--http3-only` never reaches
        // this line, because `openOnce` ends that hop before it dials.
        .alpn_protocols = if (req.no_alpn) &.{} else switch (req.http_version) {
            .any, .http_2, .http_3, .http_3_only => zurl_net.Connection.alpn_default,
            .http_1_1 => zurl_net.Connection.alpn_http_1_1,
            .prior_knowledge => zurl_net.Connection.alpn_http_2,
        },
    };
}

/// The TLS options the hop to an `https` proxy opens with.
///
/// **This is the second of the two places in zurl that turn peer
/// verification off, and it reads `proxy.insecure` and nothing else.** The
/// first is `tlsSetup`, which reads `req.insecure`. Two functions, and never
/// one with a flag, because the two answer for two different peers: this
/// one for the proxy, and that one for the origin.
///
/// The name checked is the proxy's own host, and the roots are
/// `Engine.proxy_ca_bundle`, which `Engine.proxy_tls_setup` fills from
/// `--proxy-cacert` and `--proxy-capath`. Nothing here reads `req.url.host`
/// or `Engine.ca_bundle`. Crossing the two would let `--proxy-insecure`
/// turn origin verification off, or let a proxy present a certificate for
/// the origin's name and terminate the origin's TLS with nobody noticing.
///
/// The ALPN offer is `http/1.1` alone. The hop to the proxy carries a
/// request this engine frames as HTTP/1.1, and a proxy that chose `h2`
/// would be answered in a protocol this connection is not speaking. The
/// origin's own offer is untouched: a `CONNECT` tunnel runs its own
/// handshake through `tlsSetup`, which offers whatever the request asked
/// for.
///
/// **The version floor and ceiling are the request's, the same as
/// `tlsSetup`.** `--tlsv1.3` names a floor for the transfer, and a
/// transfer through an `https` proxy puts two peers on the path. A hop
/// that dropped the floor settled on whatever the proxy offered, and for a
/// cleartext origin the whole request rides that session, the
/// `Proxy-Authorization` line included. The two functions are mirror
/// images and this field is one that was missing from one of them.
fn proxyTlsSetup(
    req: engine.Request,
    proxy: engine.Proxy,
    lock: *std.Io.RwLock,
    bundle: *std.crypto.Certificate.Bundle,
) zurl_net.Connection.Tls {
    return .{
        .host = if (proxy.insecure) .none else .{ .explicit = proxy.host },
        .trust = if (proxy.insecure) .none else .{ .bundle = .{
            .lock = lock,
            .bundle = bundle,
        } },
        // The end of a socket is not the end of a stream here either. See
        // `tlsSetup`, which holds the reasoning and the measurement. A
        // `CONNECT` answer is framed by its own head and a proxy that
        // carries an origin response carries that response's framing, so
        // the reader stops where the framing says and a peer that closes
        // without `close_notify` after it is never read again.
        .allow_truncation_attacks = false,
        .min_version = req.tls_min_version,
        .max_version = req.tls_max_version,
        .alpn_protocols = zurl_net.Connection.alpn_http_1_1,
    };
}

/// The message a hop through an `https` proxy to an `https` origin gets.
const tls_in_tls_message =
    "an https proxy cannot carry an https origin in this build: that needs " ++
    "a TLS session inside a TLS session, and zurl runs one session on a socket";

/// Builds the `Route` for one hop.
///
/// **The one place that decides which peer the socket reaches and which
/// peer its TLS session authenticates.** Every case is written out, so a
/// reader can check each one against what the proxy sees:
///
/// - No proxy. The socket goes to the origin, and TLS on it is the
///   origin's. This is every transfer that named no proxy, unchanged.
/// - An HTTP or HTTPS proxy, cleartext origin. The socket goes to the
///   proxy, and the proxy reads the whole request. So the head names the
///   whole url and carries the proxy credential. TLS on this socket, when
///   the proxy is an `https` one, is the *proxy's*: the origin speaks
///   cleartext and has no session at all.
/// - An HTTP proxy, TLS origin. The socket goes to the proxy, a `CONNECT`
///   opens a tunnel, and the TLS session runs inside that tunnel against
///   the *origin*. The proxy reads the `CONNECT` and nothing after it.
/// - A SOCKS proxy, either origin. The socket goes to the proxy, the SOCKS
///   handshake opens the route, and everything after it is the origin's:
///   the request keeps the origin form, and TLS on it is the origin's.
/// - An HTTPS proxy, TLS origin. Refused. That needs a TLS session inside a
///   TLS session, and a `zurl_net.Connection` runs one session on a socket.
///   It is refused by name rather than run without the outer session,
///   because dropping the outer one would send the `CONNECT`, and the proxy
///   credential on it, in cleartext to a proxy the user asked to reach over
///   TLS.
fn routeFor(
    engine_state: *Engine,
    req: engine.Request,
    protocol: Protocol,
    target: engine.DialTarget,
    proxy: ?engine.Proxy,
) engine.OpenError!Route {
    const p = proxy orelse return .{
        .proxy = null,
        .host = target.host,
        .port = target.port,
        .proxied_head = null,
        .tls = switch (protocol) {
            .plain => .none,
            .tls => .origin,
        },
        .step = null,
    };

    // The origin the proxy must reach, which is the host the url names and
    // never a `--resolve` or `--connect-to` target. Those move a dial, and
    // this hop dials the proxy: the origin is a name the proxy resolves.
    const origin: zurl_net.proxy.Target = .{ .host = req.url.host, .port = target.port };

    if (p.kind.isSocks()) return .{
        .proxy = p,
        .host = p.host,
        .port = p.port,
        // A SOCKS proxy carries bytes and reads no HTTP, so the request
        // keeps the origin form and carries no proxy credential.
        .proxied_head = null,
        .tls = switch (protocol) {
            .plain => .none,
            .tls => .origin,
        },
        .step = .{ .socks = .{
            .kind = p.kind,
            .target = origin,
            .credential = .{ .user = p.user, .password = p.password },
        } },
    };

    if (protocol == .plain) return .{
        .proxy = p,
        .host = p.host,
        .port = p.port,
        .proxied_head = .{ .authorization = p.authorization },
        // Only the hop to the proxy can have a session here, and only an
        // `https` proxy has one. The origin speaks cleartext.
        .tls = if (p.kind.isSecure()) .proxy else .none,
        .step = null,
    };

    if (p.kind.isSecure()) {
        engine_state.open_cause = tls_in_tls_message;
        return error.ProxyError;
    }

    return .{
        .proxy = p,
        .host = p.host,
        .port = p.port,
        // **The request goes inside the tunnel, so the proxy never reads
        // it.** No absolute form, and no proxy credential on it: the tunnel
        // was authorised once, by the `CONNECT`.
        .proxied_head = null,
        // **And the session inside the tunnel is the origin's.** The name
        // checked is `req.url.host` and the roots are the origin's, through
        // `tlsSetup`. A proxy that terminated this session would have to
        // hold a certificate for the origin's name from a root the origin's
        // bundle trusts.
        .tls = .origin,
        .step = .{ .connect = .{
            .target = origin,
            .credential = .{ .authorization = p.authorization },
            .user_agent = req.user_agent,
        } },
    };
}

/// Maps a failed proxy step onto an engine fault, and records its cause.
///
/// **Two exit codes, each measured against curl 8.21.0.** A `CONNECT` that
/// did not open the tunnel is `CouldNotConnect`, exit 7: measured, a proxy
/// answering `403` and one answering `407` each gave curl exit 7, the same
/// code a refused connection gives, because no connection to the origin
/// exists either way. A SOCKS handshake that failed is `ProxyError`, exit
/// 97: measured, a listener answering `05 ff` and one answering a refused
/// request each gave curl exit 97.
///
/// The origin host failing to resolve under a `socks5` route is neither.
/// The name that did not resolve is the origin's, so it keeps the origin's
/// name.
fn mapProxyFailure(engine_state: *Engine, runner: *const zurl_net.proxy.Runner) engine.OpenError {
    engine_state.open_cause = runner.cause();
    const failed = runner.failure orelse return error.CouldNotConnect;
    if (failed == error.ProxyCouldNotResolveHost) return error.CouldNotResolveHost;
    if (failed == error.ProxyCanceled) return error.Canceled;
    return switch (runner.step) {
        .connect => error.CouldNotConnect,
        .socks => error.ProxyError,
    };
}

/// Brings `c` up against the peer, and stops waiting after
/// `engine_state.connect_timeout`.
///
/// `c` is initialized only when this returns without an error.
///
/// The race itself is `zurl_net.bounded.setup`, which `zurl-gopher` calls
/// as well. This engine adds only the map onto `engine.OpenError`, which is
/// its own vocabulary and nothing the helper can know.
fn openConnection(
    engine_state: *Engine,
    c: *zurl_net.Connection,
    setup: Setup,
) engine.OpenError!void {
    return zurl_net.bounded.setup(
        c,
        engine_state.io,
        engine_state.connect_timeout,
        setup,
    ) catch |err| switch (err) {
        // Not a fault of the peer, and not a cause a user reads about the
        // host. `zurl.Client` answers this one by retrying with no bound
        // and recording the degradation, so it must arrive by name and not
        // as `CouldNotConnect`.
        error.ConnectTimeoutUnsupported => error.ConnectTimeoutUnsupported,
        else => |rest| mapSetupError(engine_state, rest),
    };
}

/// Whether `headers` already carries an `Accept-Encoding` header of the
/// caller's own.
///
/// **One job: stop the engine writing a second `Accept-Encoding` line
/// beside the caller's.** Two offers on one request name two sets, and a
/// peer may answer either.
///
/// It does **not** raise `Request.accept_encoding`, and an earlier version
/// of this function did. Measured against curl 8.21.0 on a loopback
/// listener, `curl -H 'Accept-Encoding: gzip'` with no `--compressed`,
/// answered in gzip, wrote the 64 compressed octets out and exited 0. It
/// did not decode. So a caller header puts an offer on the wire and asks
/// for no decoding, and `engine.contentEncoding` passes that answer
/// through, which is what curl does with it.
///
/// Matched without regard to case, because HTTP field names are
/// case-insensitive and a user writes the name either way.
fn headersOfferEncoding(headers: []const std.http.Header) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "accept-encoding")) return true;
    }
    return false;
}

/// The `Content-Encoding` value the peer wrote, or null when it wrote
/// none.
///
/// **This engine reads the field itself, rather than take
/// `std.http.Client.Response.Head.content_encoding`.** `std` refuses a
/// whole head over a coding it has no enumerator for, such as `br`, so a
/// response this build has to pass through undecoded had no head at all to
/// pass through and the transfer failed with a read error. Reading the
/// field here also puts this engine on the same footing as `h2` and `h3`,
/// which always read their own. All three then ask
/// `engine.contentEncoding`, which is the one rule.
///
/// The value comes back trimmed, because `engine.HeadFields` trims it.
/// That walk reads the head itself rather than through
/// `std.http.HeaderIterator`, which unwraps a null on a head that ends on
/// two line feeds. See `engine.HeadFields`.
///
/// The first field wins: a peer that writes the header twice has
/// written a list, and `engine.contentEncoding` refuses a list under an
/// offer and ignores one without.
fn contentEncodingField(bytes: []const u8) ?[]const u8 {
    var it: engine.HeadFields = .init(bytes);
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-encoding")) return header.value;
    }
    return null;
}

/// How many line feeds in `bytes` have no carriage return before them.
///
/// Zero means the head is written the way RFC 9112 section 2.2 asks, and
/// nothing needs repair.
fn bareLineFeeds(bytes: []const u8) usize {
    var count: usize = 0;
    for (bytes, 0..) |byte, i| {
        if (byte != '\n') continue;
        if (i == 0 or bytes[i - 1] != '\r') count += 1;
    }
    return count;
}

/// Writes `bytes` into `out` with a carriage return put before every line
/// feed that has none, and gives back what it wrote.
///
/// `out` must hold `bytes.len` octets and one more for each line feed
/// `bareLineFeeds` counted.
fn withCarriageReturns(out: []u8, bytes: []const u8) []u8 {
    var len: usize = 0;
    for (bytes, 0..) |byte, i| {
        if (byte == '\n' and (i == 0 or bytes[i - 1] != '\r')) {
            out[len] = '\r';
            len += 1;
        }
        out[len] = byte;
        len += 1;
    }
    return out[0..len];
}

/// Parses a head that `std` refused, by repairing a copy of it.
///
/// `std` refuses two heads that curl reads, and both reach this function.
/// It repairs a copy, parses the copy, and then points the head back at
/// the octets the peer really sent, so `-D` and `-i` show the answer as it
/// arrived and never the repair.
///
/// **A head written with bare line feeds is one `std` cannot agree with
/// itself about.** `std.http.HeadParser` ends a head on two line feeds and
/// reports it finished, and `std.http.Client.Response.Head.parse` then
/// refuses those same octets with `error.HttpHeadersInvalid`. Measured
/// against curl 8.21.0 over a loopback fixture: curl reads such a head,
/// writes the body, and exits 0. So a carriage return goes before each
/// bare line feed in the copy, which is what `std` wanted to read, and
/// nothing else moves.
///
/// **The repaired copy is what `head.bytes` points at, so `-D` and `-i`
/// write the line endings this build put in and not the ones the peer
/// wrote.** curl dumps the peer's octets as they arrived. The difference
/// shows only for a server that writes bare line feeds, and it buys the
/// whole transfer: a head whose octets keep their bare line feeds hangs
/// the engine above, which reads `head.bytes` for the field walks and
/// holds them to the carriage returns RFC 9112 section 2.2 asks for. The
/// body and the exit code match curl, which is what a caller reads.
///
/// **A head naming `br` is a legal head too.** `Head.parse` returns
/// `error.HttpContentEncodingUnsupported` for a coding it has no
/// enumerator for and gives back no head at all, so status, framing, and
/// `location` go with it. That field is hidden rather than removed: one
/// octet of each `content-encoding` field name is overwritten, which stops
/// `std` matching the name and moves no offset after it.
///
/// The two repairs compose, because a peer can write both faults into one
/// head. The line endings are repaired first, and the coding is hidden
/// only when the parse still refuses the result.
///
/// The copy outlives this call: `Head` borrows from the octets it parsed
/// for every field but `bytes`, and `openOnce` reads `head.location`
/// afterwards. It lives on the exchange and `closeImpl` frees it. One copy
/// at a time, so a `100 Continue` loop frees the copy it is replacing.
///
/// Every ordinary response parses on the first try and copies nothing.
fn parseRefusedHead(
    exchange: *Exchange,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) engine.OpenError!std.http.Client.Response.Head {
    if (exchange.head_scratch) |old| {
        allocator.free(old);
        exchange.head_scratch = null;
    }
    // One octet for every line feed that needs a carriage return, and not
    // twice the head: the room is counted and never guessed.
    const room = try allocator.alloc(u8, bytes.len + bareLineFeeds(bytes));
    // **The copy is kept only where a head comes back.** Every head `std`
    // refuses reaches this function now, and most of them are refused
    // again below, so holding the copy on the exchange for a head that
    // never returns would leave one allocation behind for each of them.
    // Only a head that parses needs the copy to outlive this call.
    errdefer {
        allocator.free(room);
        exchange.head_scratch = null;
    }
    exchange.head_scratch = room;
    const copy = withCarriageReturns(room, bytes);

    // The line endings alone may have been the whole fault.
    if (std.http.Client.Response.Head.parse(copy)) |head| {
        return headOf(head, copy);
    } else |err| switch (err) {
        error.HttpContentEncodingUnsupported => {},
        else => return error.ReadError,
    }

    var masked: usize = 0;
    var it: engine.HeadFields = .init(copy);
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-encoding")) continue;
        // `header.name` slices `copy`, so this is where the name starts.
        const at = @intFromPtr(header.name.ptr) - @intFromPtr(copy.ptr);
        // `content-encoding` starts with `c` or `C`, and `xontent-encoding`
        // matches no field name `std` reads.
        copy[at] = 'x';
        masked += 1;
    }
    // Nothing to hide means `std` refused the head for some other reason,
    // and this function has no business inventing one.
    if (masked == 0) return error.ReadError;

    const head = std.http.Client.Response.Head.parse(copy) catch return error.ReadError;

    // The head is parsed, so the field name may read as the peer wrote it
    // again, and `-D` shows the header the server really sent.
    //
    // The two walks go together because a repair puts carriage returns in
    // and moves every offset after the first one. `bytes` is the source of
    // truth for the octet, and `copy` is where it goes. Hiding a name
    // changes no field count and no field order, so the two walks stay on
    // the same field.
    var raw_walk: engine.HeadFields = .init(bytes);
    var copy_walk: engine.HeadFields = .init(copy);
    while (raw_walk.next()) |raw_field| {
        const copy_field = copy_walk.next() orelse break;
        if (!std.ascii.eqlIgnoreCase(raw_field.name, "content-encoding")) continue;
        const to = @intFromPtr(copy_field.name.ptr) - @intFromPtr(copy.ptr);
        const from = @intFromPtr(raw_field.name.ptr) - @intFromPtr(bytes.ptr);
        copy[to] = bytes[from];
    }

    return headOf(head, copy);
}

/// `head` with its octets pointed at `copy`.
///
/// `std.http.Client.Response.Head.parse` leaves `bytes` pointing at what
/// it parsed, which is already `copy`, so this only says out loud what the
/// head must carry and gives the reason one place to live.
///
/// **The head may not keep the octets `receiveHead` gave.**
/// `std.http.Reader.receiveHead` calls `in.toss(head_len)` and then hands
/// back a slice of the buffer it tossed, so the first read of the body
/// writes over those octets. `head.bytes` is read after that. `copy` lives
/// on the exchange until `closeImpl` frees it.
fn headOf(
    head: std.http.Client.Response.Head,
    copy: []const u8,
) std.http.Client.Response.Head {
    var out = head;
    out.bytes = copy;
    return out;
}

/// Which peer the TLS session on one socket authenticates.
///
/// **The whole separation of proxy verification and origin verification is
/// this enum.** A socket carries at most one TLS session in this build, and
/// this says whose certificate it checked. `tlsSetup` answers for `.origin`
/// and `proxyTlsSetup` answers for `.proxy`, and no call site can reach the
/// wrong one, because `dial` chooses the function from this value.
const TlsPeer = enum {
    /// The socket carries no TLS at all.
    none,
    /// The session is with the origin, verified against the origin's name
    /// and the origin's roots. A direct `https` hop, and the hop inside a
    /// `CONNECT` tunnel or a SOCKS route, are all this.
    origin,
    /// The session is with the proxy, verified against the proxy's name and
    /// the proxy's roots. Only an `https` proxy is this.
    proxy,
};

/// Where one hop's socket goes, and what it must do on the way.
///
/// Built once for each hop by `routeFor`, and read by `dial` and by
/// `sendOn`. Everything that changes because a proxy is in the way is in
/// this one value, so a reader can see the whole difference in one place.
const Route = struct {
    /// The proxy this hop goes through, or null for a hop that dials the
    /// origin itself.
    proxy: ?engine.Proxy,
    /// The host the socket opens to: the proxy's host when there is a
    /// proxy, and the origin's dial target when there is none.
    host: []const u8,
    /// The port the socket opens to.
    port: u16,
    /// Whether the request head names the whole url and carries the proxy
    /// credential. Non-null only for a cleartext origin through an HTTP or
    /// an HTTPS proxy, where the proxy reads the request. See
    /// `ProxiedHead`.
    proxied_head: ?ProxiedHead,
    /// Which peer the TLS session on this socket authenticates.
    tls: TlsPeer,
    /// The step to run on the open stream, before any TLS handshake. Null
    /// for a hop that needs none.
    step: ?zurl_net.proxy.Step,
};

/// What a request head adds when the proxy itself reads the request.
///
/// **A non-null value of this type says one thing: the peer at the far end
/// of this socket is the proxy, not the origin.** That is true for a
/// cleartext origin through an HTTP or an HTTPS proxy, where the proxy
/// reads the whole request and forwards it. It is false for a request
/// inside a `CONNECT` tunnel, and false for a request through a SOCKS
/// proxy: in both of those the socket carries bytes the proxy does not
/// read as HTTP, so the request keeps the origin form and carries no proxy
/// credential at all.
///
/// **There is one field, and it is the proxy's credential.** No origin
/// header reaches this type, so no code path can write an origin secret
/// onto a request because it was proxied.
///
/// **What the proxy does read on such a request, and why that is not a
/// leak this build can close.** A cleartext origin through an HTTP proxy is
/// one ordinary request that the proxy forwards, so the proxy reads all of
/// it: the path, the headers, and any `Authorization` the caller sent to
/// the origin. That is what `http://` through a proxy is, and curl behaves
/// the same way, measured: `-x ... -u alice:originpw -U bob:proxypw
/// http://example.com/` wrote both an `Authorization` and a
/// `Proxy-Authorization` line on the one request. The way to keep an origin
/// credential from a proxy is an `https` url, and then the credential goes
/// inside the tunnel and the `CONNECT` carries none of it. `zurl_net.proxy`
/// holds that half of the rule.
const ProxiedHead = struct {
    /// The `Proxy-Authorization` value, or empty for a proxy that asked for
    /// none.
    authorization: []const u8 = "",
};

/// Writes one request head on `w`, status line through the empty line.
///
/// The bytes are the ones `std.http.Client.Request.sendHead` wrote for the
/// same request, in the same order and the same case, so the swap from
/// that call to this one changes nothing a peer can see. The engine owns
/// every framing header: `host`, `connection`, and `accept-encoding` are
/// written here, and `engine.refused_headers` stops a caller writing a
/// second copy of any of them.
///
/// No `authorization` header of the engine's own. `uri` carries no
/// userinfo, and a caller's own credential travels in `extra_headers` like
/// any other header, so exactly one such header goes out. RFC 7235 allows
/// one.
///
/// An empty `user_agent` sends no `user-agent` header at all, which is
/// what `curl -A ""` does. A bare `user-agent: ` line names no agent and
/// still costs a header.
///
/// `proxied` says the proxy itself reads this request, which is true for a
/// cleartext origin through an HTTP or HTTPS proxy and false for every
/// other hop. See `ProxiedHead`.
fn writeRequestHead(
    w: *std.Io.Writer,
    method: std.http.Method,
    uri: std.Uri,
    user_agent: []const u8,
    extra_headers: []const std.http.Header,
    body: ?engine.Body,
    proxied: ?ProxiedHead,
    /// The `HTTP2-Settings` value of an `Upgrade: h2c` offer, or null for
    /// every other request. See `upgradeOffer`.
    upgrade_settings: ?[]const u8,
    /// Whether this request offers a compressed body. See
    /// `engine.Request.accept_encoding`.
    accept_encoding: bool,
) std.Io.Writer.Error!void {
    try w.writeAll(@tagName(method));
    try w.writeByte(' ');
    if (proxied != null) {
        // **The absolute form, which only a proxied cleartext request
        // uses.** RFC 9112 section 3.2.2: a request to a proxy names the
        // whole url, because the proxy has to decide which origin to dial.
        //
        // Measured against curl 8.21.0 on a loopback listener, with `-x
        // http://127.0.0.1:PORT http://example.com/path?q=1`, the request
        // line read `GET http://example.com/path?q=1 HTTP/1.1`. The
        // authority carries no default port, exactly as `authorityPort`
        // already decides for the `host:` line.
        try w.writeAll(uri.scheme);
        try w.writeAll("://");
        try writeAuthority(w, uri);
    }
    // The path and the query, and never the fragment: RFC 9112 section
    // 3.2.1 keeps a fragment out of the request target.
    try uri.writeToStream(w, .{ .path = true, .query = true });
    try w.writeByte(' ');
    try w.writeAll("HTTP/1.1\r\n");

    // `writeAuthority` and not `uri.writeToStream`, because `std` writes an
    // IPv6 host with no brackets and the `host:` line then reads
    // `host: ::1:8080`.
    try w.writeAll("host: ");
    try writeAuthority(w, uri);
    try w.writeAll("\r\n");

    if (proxied) |head| {
        // **The proxy's credential, and the proxy's alone.** The value
        // comes from `engine.Request.Proxy.authorization` and from no
        // header the caller wrote: `engine.refused_headers` names
        // `Proxy-Authorization`, so a caller cannot put one in
        // `Request.headers` or in `Request.secrets`, which both reach the
        // origin.
        //
        // This line goes on a request the proxy reads in cleartext, which
        // is the request it has to authorise. A tunnelled request carries
        // no copy of it: the tunnel is authorised once, by the `CONNECT`.
        //
        // It sits directly after `host:`, which is where curl 8.21.0 wrote
        // it, measured on a loopback listener.
        if (head.authorization.len != 0) {
            try w.writeAll("proxy-authorization: ");
            try w.writeAll(head.authorization);
            try w.writeAll("\r\n");
        }
    }

    if (user_agent.len != 0) {
        try w.writeAll("user-agent: ");
        try w.writeAll(user_agent);
        try w.writeAll("\r\n");
    }

    if (upgrade_settings) |settings| {
        // **The `Upgrade: h2c` offer, RFC 7540 section 3.2.** Three fields
        // and they travel together: the protocol asked for, the settings
        // that would have been the first `SETTINGS` frame, and a
        // `Connection` field naming both of the others as hop-by-hop.
        //
        // Measured against curl 8.21.0 on a loopback listener, `curl
        // --http2 http://127.0.0.1:PORT/some/path`:
        //
        // ```text
        // Upgrade: h2c
        // HTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA
        // Connection: Upgrade, HTTP2-Settings
        // ```
        //
        // **`connection: keep-alive` is not written beside them.** RFC
        // 9110 section 7.6.1 makes `Connection` the list of hop-by-hop
        // field names, and this request's list is the two upgrade fields.
        // curl writes the same one line and no second one.
        //
        // The value differs from curl's because the two clients ask for
        // different windows. The encoding is the same, and each names its
        // own settings, which is what the RFC asks for.
        try w.writeAll("upgrade: h2c\r\n");
        try w.writeAll("http2-settings: ");
        try w.writeAll(settings);
        try w.writeAll("\r\n");
        try w.writeAll("connection: Upgrade, HTTP2-Settings\r\n");
    } else {
        try w.writeAll("connection: keep-alive\r\n");
    }
    // curl writes this beside `Connection` on a proxied request, measured
    // on a loopback listener. A proxy that reads it keeps the connection
    // open, which is what the pool above needs, and one that does not read
    // it ignores an unknown field.
    if (proxied != null) try w.writeAll("proxy-connection: keep-alive\r\n");

    // **No offer, no header.** Measured against curl 8.21.0 on a loopback
    // listener, a plain `curl http://127.0.0.1:PORT/path` writes the
    // request line, `Host`, `User-Agent`, and `Accept`, and no
    // `Accept-Encoding` at all. `curl --compressed` adds
    // `Accept-Encoding: deflate, gzip, br, zstd`. So the header belongs to
    // the flag, and a request that names no flag asks the peer for the
    // plain body curl would have got.
    //
    // A caller that wrote its own `Accept-Encoding` gets that one and no
    // second copy: two offers on one request name two different sets, and
    // a peer may answer either. See `headersOfferEncoding`, which also
    // raises the flag that reaches here.
    if (accept_encoding and !headersOfferEncoding(extra_headers)) {
        try w.writeAll("accept-encoding: " ++ accept_encoding_value ++ "\r\n");
    }

    // **The body framing, and the one place it is written.**
    //
    // A known length gets `content-length`, which is what curl sends for
    // `-d` and for `-T` on a regular file. An unknown length gets the
    // chunked transfer coding, which is what curl sends for `-T -` on a
    // pipe. A request with no body gets neither header: measured against
    // curl 8.21.0, `curl -X POST` with no data sends `POST / HTTP/1.1`
    // with no framing header at all, and RFC 9112 section 6 reads such a
    // request as one with no body.
    //
    // `engine.refused_headers` holds `Content-Length` and
    // `Transfer-Encoding`, so no caller header can add a second copy of
    // either line.
    //
    // These lines go before the caller's own headers, which is the order
    // curl writes them in: `Content-Length` then `Content-Type`.
    if (body) |source| {
        if (source.len) |length| {
            try w.print("content-length: {d}\r\n", .{length});
        } else {
            try w.writeAll("transfer-encoding: chunked\r\n");
        }
        // The content type describes the body, so it goes out with the
        // body and never without it. See `engine.Body.content_type`.
        if (source.content_type) |value| {
            try w.writeAll("content-type: ");
            try w.writeAll(value);
            try w.writeAll("\r\n");
        }
    }

    for (extra_headers) |header| {
        // A header with an empty name would write a bare `: value` line.
        // `validateHeaderName` already refused one, so this is a check on
        // this file and not on the caller.
        std.debug.assert(header.name.len != 0);
        try w.writeAll(header.name);
        try w.writeAll(": ");
        try w.writeAll(header.value);
        try w.writeAll("\r\n");
    }

    try w.writeAll("\r\n");
}

/// How many body bytes the engine asks `engine.Body.read` for at a time.
///
/// The engine holds one of these on the stack of the call that sends the
/// body, so a body of any size costs the engine this much memory and no
/// more. That is what lets `-T` stream a file larger than this machine's
/// memory.
///
/// 16 KiB is two pages on a 4 KiB page and one write on a TLS connection,
/// whose record is 16 KiB.
const body_chunk_len = 16 * 1024;

/// Writes `source` to `w`, framed the way `writeRequestHead` announced it.
///
/// A known `len` writes the bytes plain, and the count has to match
/// exactly: a source that ends early leaves the peer waiting for bytes
/// that never come, and one that runs long puts the tail of this request
/// at the front of the next one. Both are `error.WriteError`, and neither
/// can be an assert, because the source is caller data and a file can
/// change size between the `stat` that measured it and the read that sends
/// it.
///
/// An unknown `len` writes the chunked transfer coding: a hexadecimal size
/// line, the bytes, a CRLF, and a zero-size line with an empty trailer
/// section to end it. No `Expect: 100-continue` goes with it. curl sends
/// that header for an upload of unknown length and waits for the peer's
/// `100`. This engine sends the body straight away, which is legal HTTP/1.1
/// and needs no wait. `--help` names the difference.
///
/// A `read` that reports a fault is `error.ReadError`, which is exit 26,
/// the code curl gives a failed upload read.
fn writeRequestBody(w: *std.Io.Writer, source: engine.Body) engine.OpenError!void {
    var buffer: [body_chunk_len]u8 = undefined;
    var written: u64 = 0;

    while (true) {
        // A known length is a bound on the ask as well as on the total, so
        // a source that keeps producing bytes cannot make this loop run
        // forever.
        const want: usize = if (source.len) |length| want: {
            const left = length - written;
            if (left == 0) break :want 0;
            break :want @intCast(@min(left, buffer.len));
        } else buffer.len;
        if (want == 0) break;

        const n = source.read(source.ctx, &buffer, want);
        if (n < 0) return error.ReadError;
        const count: usize = @intCast(n);
        // A source that answers with more than it was asked for has
        // written past the end of `buffer` already. Nothing here can undo
        // that, so this is a check on the source and it fails the request.
        if (count > want) return error.WriteError;
        if (count == 0) break;

        if (source.len == null) w.print("{x}\r\n", .{count}) catch return error.WriteError;
        w.writeAll(buffer[0..count]) catch return error.WriteError;
        if (source.len == null) w.writeAll("\r\n") catch return error.WriteError;
        written += count;
    }

    if (source.len) |length| {
        // The peer was told exactly how many bytes to read. A body that
        // stopped short leaves it reading the next request as the tail of
        // this one.
        if (written != length) return error.WriteError;
    } else {
        w.writeAll("0\r\n\r\n") catch return error.WriteError;
    }
}

/// One request and its response, on a connection this exchange owns.
///
/// Heap-allocated by `Engine.allocator`, for two reasons. It must outlive
/// the stack frame that opened it, and `connection` holds pointers into
/// itself, so the whole value must not move. `close` is its only path back
/// to that allocator, and the only thing that closes the socket.
const Exchange = struct {
    interface: engine.Exchange,
    allocator: std.mem.Allocator,
    /// The `std.Io` every read of this exchange races its deadline on.
    ///
    /// Copied from the engine at `sendOn`, and not found through the
    /// engine later, for the reason `pool` gives: the address of an
    /// `Engine` is not stable, and a body outlives the `open` that built
    /// it.
    io: std.Io,
    /// How long one read of this exchange may wait with no octet arriving.
    ///
    /// **This is the bound that ends a transfer the peer stopped feeding.**
    /// See `h1.default_read_timeout_s` for why the rate watchdog above
    /// this engine cannot do it, and `raceRead` for how one read is held
    /// to it.
    ///
    /// Copied from `Engine.read_timeout` at `sendOn`, so a bound the owner
    /// changes between transfers cannot move the deadline of a body that
    /// is already being read.
    read_timeout: std.Io.Timeout,
    /// How many body reads of this exchange ran with no bound because this
    /// build could not watch a clock while the read was in flight.
    ///
    /// **A count on the exchange and not on the engine, for the same
    /// lifetime reason `io` gives.** A body outlives the `open` that built
    /// it, and the address of an `Engine` is not stable, so an exchange
    /// may not hold one. The engine's own `read_bounds_dropped` records
    /// the same build limit from the head phase, which every transfer
    /// runs, so a reader of that count already learns that this build
    /// cannot bound a read.
    read_bounds_dropped: usize,
    /// Whether a read of this exchange reached its deadline.
    ///
    /// **Latching, and it is what keeps the connection out of the pool.**
    /// A peer that stopped mid-body stopped at a place nothing here knows,
    /// so the octets it may yet write would arrive in front of the next
    /// request. `reusable` reads this first.
    ///
    /// `check` turns it into `error.OperationTimedOut`, because the body
    /// reader's own error set can say no more than `error.ReadFailed`.
    /// Recovery is never silent.
    read_timed_out: bool,
    /// The pool this exchange hands its connection back to. See
    /// `closeImpl`.
    ///
    /// Held by pointer and not found through the engine, because
    /// `zurl.Client` owns its engine by value and the address of an
    /// `Engine` is not stable. The pool is on the heap and does not move.
    pool: *Pool,
    /// The socket this exchange speaks on, plain or encrypted, and the
    /// origin it belongs to.
    ///
    /// One connection serves one exchange at a time. The connection is
    /// either here or idle in `pool`, never both, so no two requests can
    /// share one socket.
    ///
    /// `close` decides which way it goes. See `reusable` for the whole
    /// rule, and `Pool.put` for what a full pool does.
    ///
    /// Held by pointer, and initialized in place by `openConnection`,
    /// because the TLS session inside it holds the address of its own
    /// buffers, and because it outlives this exchange whenever it goes
    /// back to the pool.
    pooled: *Pooled,
    /// The response framing, over `connection.reader()`. This is what
    /// finds the end of the head, counts a content-length body, and reads
    /// the chunked framing.
    http_reader: std.http.Reader,
    /// How the peer framed the body, and how long it said the body is.
    /// Read again at `bodyReader`, long after the head bytes are gone.
    transfer_encoding: std.http.TransferEncoding,
    body_content_length: ?u64,
    content_encoding: std.http.ContentEncoding,
    decompress: std.http.Decompress,
    decompress_buffer: [decompress_buffer_len]u8,
    /// The window a zstd answer decodes through, or null for every other
    /// answer. Owned, `zstd_buffer_len` bytes, and freed by `closeImpl`.
    ///
    /// **Allocated only where the head really said zstd.** The window is
    /// 8.1 MiB, which is far too large to sit in every exchange, and an
    /// identity or a flate answer needs none of it. `decompress_buffer`
    /// serves those. See `zstd_buffer_len`.
    zstd_buffer: ?[]u8,
    /// A copy of the response head, taken only when `std` refused to parse
    /// the peer's own octets over the `Content-Encoding` field. Owned, and
    /// freed by `closeImpl`.
    ///
    /// Null for every head `std` parsed, which is every head that names a
    /// coding `std` has an enumerator for. See `parseRefusedHead`, which
    /// says why the copy has to outlive the parse.
    head_scratch: ?[]u8,
    /// An owned copy of the final response's `Location` header, taken
    /// before the first body read invalidates the head bytes. `null` when
    /// the response had no `Location`, or when one arrived too large to
    /// fit `location_storage`.
    location_storage: [redirect_buffer_len]u8,
    location_len: ?usize,
    /// An owned copy of the response's `WWW-Authenticate` header, taken
    /// before the first body read invalidates the head bytes. `null` when
    /// the response had none, or one arrived too large to fit
    /// `www_authenticate_storage`.
    www_authenticate_storage: [www_authenticate_buffer_len]u8,
    www_authenticate_len: ?usize,
    /// Whether a `WWW-Authenticate` header arrived too large to keep. The
    /// caller reads this through `engine.Head`, so a dropped challenge is
    /// reported instead of looking like a response that carried none.
    www_authenticate_oversize: bool,
    head_value: engine.Head,
    transfer_buffer: [transfer_buffer_len]u8,
    /// The reader `bodyReader` hands out. It counts the transfer to its
    /// end, so a body that stops short of its announced content length is
    /// a failure and not a short answer.
    body: std.Io.Reader,
    /// What `body` reads from: the transfer reader, with any content
    /// decoding already in front of it.
    body_source: *std.Io.Reader,
    /// The methods `std.http.Reader.bodyReader` put on the transfer
    /// reader, kept aside so the chunk size guard can call them.
    ///
    /// Valid only where `bodyReader` framed a chunked body. See
    /// `chunk_guard_vtable`, which is what stands in front of them.
    transfer_vtable: *const std.Io.Reader.VTable,
    /// Whether `bodyReader` was already called. One exchange has one body.
    body_taken: bool,
    /// Whether the transfer stopped before its announced content length.
    /// `check` reports this as `error.PartialFile`.
    body_partial: bool,
    /// Whether `finishFraming` ran. It runs once, at the end of the
    /// content stream, and a later read of the same ended reader must not
    /// start it again.
    framing_finished: bool,
    /// Whether the peer will read another request on this connection.
    ///
    /// Read from the response head by `peerKeepsAlive`, which covers
    /// `connection: close` and the HTTP/1.0 default. False until the head
    /// arrives, so a connection whose request never got an answer is never
    /// kept.
    keep_alive: bool,
    /// Whether this response carries no body byte at all.
    ///
    /// A `content-length: 0` with no transfer encoding. Such a response
    /// leaves the connection at the start of the next response even where
    /// nothing called `bodyReader`, which is the ordinary shape of a
    /// redirect hop: `followChain` closes each hop without reading it. See
    /// `reusable`.
    body_empty: bool,
    /// Whether the peer answered any byte of this request.
    ///
    /// **This is what stops a served request going out twice.** A request
    /// may be sent again on a fresh connection only when the peer answered
    /// nothing at all, because then the peer cannot have acted on it. See
    /// `openOnce` for the retry rule this feeds.
    peer_answered: bool,

    /// The scratch that `followChain` used to walk a redirect chain, when
    /// this exchange answered a hop of one.
    ///
    /// `engine.Head.effective_url` points into it, so the memory has to
    /// live as long as this exchange does. `null` when the exchange
    /// answered the url the caller named. Freed by `close`.
    chain_storage: ?[]u8,

    /// Sends `req`, and keeps every secret inside the origin the caller
    /// named.
    ///
    /// A secret must not travel to a host the caller did not ask for. An
    /// ordinary header goes out on every hop, so a secret put among them
    /// reaches whichever host the first server named.
    ///
    /// So a request that carries a secret asks for no redirect following
    /// at all. It gets one answer from the origin the caller named. When
    /// that answer is a redirect the caller wanted followed, this sends
    /// the same request again with no secret and follows the whole chain
    /// with that one. The chain then carries nothing worth stealing, and
    /// the second exchange reports `Head.credential_withheld`, so the
    /// caller can say why a transfer that had a credential arrived without
    /// one.
    ///
    /// The cost is one extra request to the origin, and a secret that does
    /// not survive even a same-origin redirect. Lifting that needs an
    /// engine that compares origins hop by hop.
    ///
    /// This engine can do that now. `followChain` walks the chain itself
    /// and holds the url of every hop, so dropping the secret at the first
    /// origin change, rather than at the first hop, is a change inside that
    /// loop.
    fn open(engine_state: *Engine, req: engine.Request) engine.OpenError!*engine.Exchange {
        // The log belongs to the chain this call is about to walk, so
        // whatever an earlier call left in it goes now. `engine.Engine.open`
        // says so: an earlier `Head.headers` is invalid from here on.
        engine_state.resetHeadLog();
        // The cause of an earlier failure goes now too. A sentence kept
        // from an earlier transfer would attach to whatever this one
        // fails with, and say the wrong thing with full confidence.
        engine_state.open_cause = null;
        // The same rule for the `TCP_NODELAY` record. A transfer that
        // reads it must read it about itself.
        engine_state.no_delay_error = null;
        // And for the redirect target of an earlier chain. A caller that
        // read a stale target would open a url this request never met.
        engine_state.redirect_handoff_len = 0;

        try validateHeaders(req.headers);
        try refuseHeaders(req.headers);
        try refuseUnnamedSecrets(req.secrets);
        // A url's userinfo is percent-decoded before it reaches here, so a
        // `%0d` in a user name decodes to a CR. Check a secret the same
        // way every other header is checked.
        try validateHeaders(req.secrets);
        // The user agent is a header value that does not travel in
        // `req.headers`, so the loop above never saw it. It is the one
        // value this engine used to put on the wire unchecked, and `-A`
        // will fill it from the command line.
        try validateHeaderValue(req.user_agent);
        // The body's content type is a header value too, and it does not
        // travel in `req.headers`, so the loop above never saw it either.
        // A `-H` cannot reach this field, but a library caller can.
        if (req.body) |source| {
            if (source.content_type) |value| try validateHeaderValue(value);
        }

        // A body-bearing method used to be refused here, because the
        // engine wrote no framing header and the peer could not find the
        // end of the request. `writeRequestHead` writes that header now,
        // from `req.body`, so any method may go out. A `POST` with a null
        // body carries no framing header and no body, which is what curl
        // 8.21.0 sends for `curl -X POST` with no data.
        //
        // The body has not been sent yet on this call, so the next
        // `openOnce` may read it without a rewind. Every send after that
        // one needs `engine.Body.rewind`.
        engine_state.body_sent = false;
        // The answer flag belongs to the request this call is about to
        // send. One kept from an earlier transfer would stop a retry that
        // is safe, or allow one that is not.
        engine_state.answered_any = false;
        // And the challenge rule. This `open` starts on the url the caller
        // named, so its first hop is the caller's own origin. Every
        // `followChain` clears it again, and the credentialed path below
        // reaches `openOnce` without one.
        engine_state.chain_challenge_untrusted = false;

        // How many hops this engine may follow, and null to hand the first
        // redirect back to the caller instead.
        //
        // `maxInt(u16)` is the value `std.http.Client` reserves for
        // "unhandled", and `RedirectBehavior.init` asserts against it. A
        // `--max-redirs` flag can carry any `u16`, so that value is
        // reachable input, not a programmer error. This engine owns the
        // chain itself now, so nothing here can assert on it, and the
        // value keeps the meaning it had: route it to the same place
        // `engine.Redirects.unfollowed` goes.
        const follow: ?u16 = switch (req.redirects) {
            .unfollowed => null,
            .follow => |count| if (count == std.math.maxInt(u16)) null else count,
        };

        if (req.secrets.len == 0) return followChain(engine_state, req, req.secrets, follow);

        // **`--location-trusted`: the caller says the whole chain may hold
        // the secret.** The chain then walks with the secret on every hop,
        // which is what curl sends under that flag, measured with two
        // loopback servers. Nothing else changes: the same `followChain`
        // walks the same hops and reads every `location:` the same way.
        //
        // This is the only branch that lets a secret leave the origin the
        // url names. `engine.Request.trusted_secrets` defaults to false,
        // so a caller reaches it only by naming the option.
        //
        // **A scheme downgrade gets no second gate here, and that was
        // decided rather than missed.** A chain that goes from `https` to
        // plain `http` puts the secret on the wire in the clear, and
        // `zurl_core.redirect.isDowngrade` can say so. Measured against
        // curl 8.21.0 with two loopback servers, one carrying TLS: curl
        // sends `Authorization`, a `-b` cookie and a `-H` header across
        // that hop under this flag, and drops all three without it.
        //
        // zurl answers the same. The flag is a choice the user wrote, and
        // a build that quietly did something narrower than what was asked
        // would be answering a question the user did not ask. The same
        // reasoning keeps `-Doptimize` as the user names it.
        //
        // A caller that wants the stricter rule has the predicate and can
        // refuse before it ever reaches this engine.
        if (req.trusted_secrets) return followChain(engine_state, req, req.secrets, follow);

        var exchange = try openOnce(engine_state, req, req.secrets);
        if (follow == null or !followableRedirect(exchange.head())) return exchange;

        exchange.close();
        const resent = try followChain(engine_state, req, &.{}, follow);
        // The caller asked for a credential and gets an answer built
        // without one. Recovery is never silent, so the exchange carries
        // that fact to whoever can report it.
        //
        // Through the seam and not through a cast of `resent` back to this
        // file's own `Exchange`. A chain that ends on an HTTP/2 hop is
        // answered by `h2.Exchange`, which has another layout, and the
        // cast would have written over whatever sat at that offset.
        resent.withheldCredential();
        return resent;
    }

    /// Sends `req` and walks the redirect chain it answers with, up to
    /// `follow` hops. A null `follow` hands the first redirect back to the
    /// caller, unfollowed.
    ///
    /// `std.http.Client.Request.receiveHead` can walk a chain by itself,
    /// and this engine used to let it. It must not.
    /// `std.http.Client.Response.Head.parse` splits a head on CRLF, so a
    /// bare LF stays inside a header value; `std.Uri` puts no rule on the
    /// characters of a path; and the resolved target then reaches the next
    /// request line exactly as the server wrote it. A `Location:
    /// /a\nX-Injected: yes` therefore put a header of the server's
    /// choosing on the wire, and no head in the middle of that chain was
    /// ever visible to this engine. So this loop makes one hop at a time
    /// and reads every `Location` before anything can send it.
    ///
    /// `std` still owns the resolution: `std.Uri.resolveInPlace` merges
    /// the target against the current url here, which is the same call
    /// `std.http.Client.Request.redirect` makes. This adds the loop and
    /// the check around it, and nothing else.
    ///
    /// Every hop after the first carries no secret, because `open` calls
    /// this with an empty `secrets` for a request that had any.
    ///
    /// The head log holds the chain this walks and nothing before it. A
    /// credentialed request that met a redirect got one answer already,
    /// from the probe `open` sent and threw away, and that answer is not a
    /// hop of this chain. curl sends no such probe, so keeping its head
    /// would put a block in `-D` output that curl never writes.
    fn followChain(
        engine_state: *Engine,
        req: engine.Request,
        secrets: []const std.http.Header,
        follow: ?u16,
    ) engine.OpenError!*engine.Exchange {
        engine_state.resetHeadLog();
        // The chain starts on the url the caller named, so the first hop
        // is the caller's own origin and its challenge is the caller's to
        // answer. See `Engine.chain_challenge_untrusted`.
        engine_state.chain_challenge_untrusted = false;

        var exchange = try openOnce(engine_state, req, secrets);
        var remaining: u16 = follow orelse return exchange;

        var hop = req;
        // `req.secrets` and the `secrets` parameter can differ: `open`
        // resends a credentialed request with none. Every `openOnce` below
        // reads the parameter, so the copy in `hop` would be a second
        // answer to "what does this hop send", and the wrong one on the
        // resend path. One field, one answer.
        hop.secrets = secrets;
        // Allocated on the first hop that needs it, so a transfer that
        // meets no redirect pays nothing. Handed to the exchange that ends
        // the chain, because that exchange still reads it.
        var chain: ?[]u8 = null;
        errdefer if (chain) |storage| engine_state.allocator.free(storage);
        // **The `Referer` list a hop sends under `--referer ';auto'`.**
        //
        // Built once, on the first hop that needs one, and rewritten in
        // place for each hop after it. The caller's own header list is
        // never touched: `base_headers` is what every rewrite starts from,
        // so a second hop cannot inherit the first hop's `Referer` twice.
        const base_headers = req.headers;
        var referer_headers: ?[]std.http.Header = null;
        defer if (referer_headers) |list| engine_state.allocator.free(list);
        // The url text of the last hop this loop opened, inside `chain`.
        // Null while the chain has made no hop, and the caller then keeps
        // the url it named. See `engine.Head.effective_url`.
        var final_url: ?[]const u8 = null;

        while (followableRedirect(exchange.head())) {
            if (remaining == 0) {
                exchange.close();
                return error.TooManyRedirects;
            }
            remaining -= 1;

            const status = exchange.head().status;
            const target = nextTarget(engine_state, &chain, hop, exchange.head().location.?) catch |err| {
                exchange.close();
                return err;
            };

            // **The url this hop was fetched from, kept before the text
            // that holds it is overwritten.** It becomes the next hop's
            // `Referer` under `--referer ';auto'`. Measured against curl
            // 8.21.0: `-L -e ';auto'` sent no `Referer` on the first
            // request and `Referer: <the first hop's url>` on the second.
            const referer: ?[]const u8 = if (!req.auto_referer) null else keep: {
                const room = chain.?[chain_referer_start..];
                const written = hopUrlText(room, hop) catch |err| {
                    exchange.close();
                    return err;
                };
                break :keep written;
            };

            // The hop that is open still points at the text this is about
            // to overwrite, so it closes first.
            exchange.close();
            const text = chain.?[0..target.len];
            @memcpy(text, target);
            hop.url = zurl_core.url.parse(text) catch return error.InvalidUrl;
            final_url = text;

            rewriteHop(&hop, status);
            if (referer) |value| try applyAutoReferer(
                engine_state,
                &hop,
                base_headers,
                &referer_headers,
                value,
            );

            // **The hop about to open is a target a server chose.** It
            // carries no secret unless `--location-trusted` says the whole
            // chain may, so it gets no challenge answered unless the same
            // flag says so. See `Engine.chain_challenge_untrusted`.
            engine_state.chain_challenge_untrusted = !req.trusted_secrets;

            exchange = try openOnce(engine_state, hop, secrets);
        }

        // `chain` is allocated by the first hop that follows a redirect,
        // and that hop writes `final_url` before it opens the next one. So
        // the two are set together, and the `if` reads both rather than
        // assert on one.
        if (chain) |storage| if (final_url) |url| {
            // The text sits in `storage`, which the exchange now owns and
            // frees at `close`. That is the life `engine.Head.effective_url`
            // names.
            //
            // Through the seam and not through a cast of `exchange` back to
            // this file's own `Exchange`. The last hop of a chain may have
            // been answered over HTTP/2, and `h2.Exchange` has another
            // layout.
            exchange.adoptChain(storage, url);
        };
        return exchange;
    }

    /// Writes the url text of `hop` into `out`, and returns the part of
    /// `out` that holds it.
    ///
    /// This is the text `Request.auto_referer` sends as the `Referer` of
    /// the hop after it. It goes through `writeUri`, the same call that
    /// builds the url text of every hop of a chain, so the `Referer` a
    /// peer reads and the url zurl reports for that hop are one text and
    /// cannot drift apart.
    ///
    /// The userinfo is dropped, because `writeUri` drops it. A password in
    /// the url must not travel to the next host in a header the next host
    /// reads. curl drops it there too.
    fn hopUrlText(out: []u8, hop: engine.Request) engine.OpenError![]const u8 {
        const protocol = try resolveProtocol(hop.url.scheme);
        const canonical_scheme = if (protocol == .plain) "http" else "https";
        return writeUri(out, requestUri(canonical_scheme, hop.url), hop.url.host);
    }

    /// Puts `value` in the `Referer` of `hop`, replacing whatever the
    /// caller's own headers named.
    ///
    /// `base` is the caller's list and never the one an earlier hop built,
    /// so each hop starts from the same place and no chain can gather two
    /// `Referer` lines. Measured against curl 8.21.0: `-L -e
    /// 'http://a/;auto'` sent `Referer: http://a/` first and the previous
    /// hop's url after it, one line each time.
    ///
    /// `storage` holds the owned list between hops, so a chain of many
    /// hops allocates once. `followChain` frees it.
    fn applyAutoReferer(
        engine_state: *Engine,
        hop: *engine.Request,
        base: []const std.http.Header,
        storage: *?[]std.http.Header,
        value: []const u8,
    ) engine.OpenError!void {
        // The text is this engine's own, built by `writeUri` out of a
        // parsed url, so it carries no CR and no LF. The check stays,
        // because a header value that reaches the wire is checked once,
        // here, and not trusted for being built nearby.
        try validateHeaderValue(value);

        if (storage.* == null)
            storage.* = try engine_state.allocator.alloc(std.http.Header, base.len + 1);
        const buffer = storage.*.?;

        var used: usize = 0;
        for (base) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "Referer")) continue;
            buffer[used] = header;
            used += 1;
        }
        buffer[used] = .{ .name = "Referer", .value = value };
        used += 1;
        hop.headers = buffer[0..used];
    }

    /// Rewrites the method and the body of the next hop for the redirect
    /// status that sent it there.
    ///
    /// **This is where a request body stops travelling.** A body belongs
    /// to the request the user wrote. A redirect that turns that request
    /// into a `GET` must not carry the body to the new target, and a
    /// redirect that keeps the request must carry it. Measured against
    /// curl 8.21.0 on a loopback listener, with `-L -d 'a=1&b=2'` and with
    /// `-L -T file`:
    ///
    /// ```
    /// 301  POST -> GET /moved, no body, no content-length
    /// 302  POST -> GET /moved, no body, no content-length
    /// 303  POST -> GET /moved, no body, no content-length
    /// 303  PUT  -> GET /moved, no body, no content-length
    /// 307  POST -> POST /moved, the same body and content-length
    /// 308  POST -> POST /moved, the same body and content-length
    /// 302  PUT  -> PUT  /moved, the same body and content-length
    /// ```
    ///
    /// So `301` and `302` rewrite a `POST` alone, and every other method
    /// keeps its body across them. `303` rewrites every method, which is
    /// RFC 9110 section 15.4.4. `307` and `308` rewrite nothing, which is
    /// the whole reason those two statuses exist.
    ///
    /// A `HEAD` stays a `HEAD` on a `303`. RFC 9110 section 15.4.4 says
    /// the target is to be asked for with `GET`, and adds that a `HEAD`
    /// request keeps its method, because a client that asked for a head
    /// alone did not ask for a body.
    ///
    /// **One divergence from curl, measured.** `curl -X POST -d a=1 -L`
    /// through a `302` sends `POST /moved` with no body and no
    /// `Content-Length`: the `-X` fixes the method text and the body is
    /// still dropped. This engine sends `GET /moved` for the same chain,
    /// because `engine.Request` carries no answer to "did the user name
    /// this method themselves". Both drop the body, which is the half that
    /// matters for a secret. `--help` names the difference.
    ///
    /// **`hop.redirect_methods` turns one status off at a time.** That is
    /// `--post301`, `--post302`, and `--post303`, and `--follow` names all
    /// three. A status the caller named keeps the method and the body, so
    /// the body reaches the redirect target as the user wrote it. See
    /// `engine.RedirectMethods`, which holds the reason a user asks for
    /// that and the reason it is not the default.
    fn rewriteHop(hop: *engine.Request, status: u16) void {
        if (hop.redirect_methods.keeps(status)) return;
        const rewrite = switch (status) {
            @intFromEnum(std.http.Status.moved_permanently),
            @intFromEnum(std.http.Status.found),
            => hop.method == .POST,
            @intFromEnum(std.http.Status.see_other) => hop.method != .HEAD,
            else => false,
        };
        if (!rewrite) return;

        hop.method = .GET;
        // The body goes with the method. A `GET` that still carried a
        // `content-length` would offer the new target bytes the user
        // addressed to the old one.
        hop.body = null;
    }

    /// Resolves `location` against `hop.url` and returns the url text of
    /// the next hop, inside the chain scratch that `chain` names.
    ///
    /// Allocates that scratch on the first call. The returned text sits in
    /// the last third of it, and the caller copies the text to the front
    /// once it has closed whatever still reads the front.
    ///
    /// A target that names a scheme outside `zurl_core.redirect` is
    /// `error.UnsupportedProtocol` and never opens. See the comment on
    /// that check for why the rule is here and not in each protocol.
    fn nextTarget(
        engine_state: *Engine,
        chain: *?[]u8,
        hop: engine.Request,
        location: []const u8,
    ) engine.OpenError![]const u8 {
        // Before anything resolves it, and long before anything sends it.
        try validateLocation(location);

        if (chain.* == null) chain.* = try engine_state.allocator.alloc(u8, chain_storage_len);
        const storage = chain.*.?;
        const scratch = storage[redirect_buffer_len .. redirect_buffer_len * 2];
        // **The end is named, and not left open.** `chain_storage_len` is
        // four parts and `chain_referer_start` is the last of them, so
        // `storage[redirect_buffer_len * 2 ..]` is two parts and not one:
        // its second half is the referer region, octet for octet.
        // `writeUri` bounds on `out.len`, so a target longer than one part
        // was written into the referer text and then partly written over
        // by `hopUrlText`, and the `Referer` a later hop sent was the
        // remains of two urls.
        const out = storage[redirect_buffer_len * 2 .. redirect_buffer_len * 3];

        // `resolveInPlace` reads the target from the front of its own
        // buffer and merges a relative path into the room behind it.
        if (location.len > scratch.len) return error.InvalidUrl;
        const copy = scratch[0..location.len];
        @memcpy(copy, location);

        // The host of the next hop, read before anything masks it.
        //
        // `resolveInPlace` reads the target with these same two calls, and
        // the host of its answer is the target's own host when the target
        // names one and the base's host when it does not. So this is that
        // host, read here where the colons of an address are still there
        // to read. See `maskHost` for why they cannot stay.
        const target = std.Uri.parse(copy) catch
            std.Uri.parseAfterScheme("", copy) catch return error.InvalidUrl;

        // **A redirect may not widen the set of protocols the transfer
        // speaks.** The user named the scheme of the first url; a
        // `location:` header is the server's text, and a server that
        // could move a transfer to `file` could read any file the user
        // can read and, under `-o`, have it written back out.
        //
        // `zurl_core.redirect` is the whole rule, and it lives in
        // `zurl-core` so the next protocol package to grow a redirect
        // chain reads this policy instead of writing a second copy of it.
        // `hop.redirect_protocols` is that policy as one set:
        // `--proto-redir` fills it, and a caller that names nothing gets
        // `zurl_core.redirect.redirect_default`, the same list this check
        // read before the flag existed.
        //
        // The check reads the target's own scheme, before anything
        // resolves it. An empty scheme is a relative target, which takes
        // the scheme of the hop it came from, and that scheme reached
        // `openOnce` already. `std.Uri.resolveInPlace` decides the same
        // way, with the same two calls, so this refuses exactly the
        // targets that would have changed the scheme.
        //
        // `UnsupportedProtocol` and not `InvalidUrl`, because the target
        // is well formed and it is the protocol that is refused. curl
        // 8.21.0 answers the same shape with exit 1 and
        // `Protocol "file" is disabled (in redirect)`.
        if (target.scheme.len > 0 and !hop.redirect_protocols.hasScheme(target.scheme)) {
            return error.UnsupportedProtocol;
        }

        // **A target the rule permitted and this engine cannot open.**
        //
        // The check above has already asked `hop.redirect_protocols`, so
        // the only way here is a `--proto-redir` that named a protocol
        // outside http and https, such as `--proto-redir +file`. The
        // default set names no such protocol, so no transfer reaches this
        // line without the user having asked for it, and the refusal above
        // is what a caller who asked for nothing still gets.
        //
        // The chain stops and the target goes back to the caller, which is
        // the one place that can dispatch a scheme. `location` and not the
        // resolved text: a target that names a scheme is already absolute,
        // and the rest of this function writes an http-shaped url, which a
        // `file:///a/b` is not. `validateLocation` has already read every
        // byte of `location`, and the bound above already refused one
        // longer than the scratch, so the text is checked and it fits.
        //
        // Nothing of the new hop is written here. The target is a
        // **server's** text, and only the caller decides to open it.
        if (target.scheme.len > 0 and !speaksScheme(target.scheme)) {
            try engine_state.recordHandoff(location);
            return error.RedirectToOtherProtocol;
        }

        var host_storage: [masked_host_max]u8 = undefined;
        var host = hop.url.host;
        if (target.host) |component| {
            const text = componentText(component);
            // `bareHost` because `std.Uri` keeps the brackets of an IPv6
            // host inside the component and `zurl_core.Url.host` does not.
            const bare = bareHost(text);
            if (bare.len > host_storage.len) return error.InvalidUrl;
            @memcpy(host_storage[0..bare.len], bare);
            host = host_storage[0..bare.len];
            // The mask goes over the very bytes just saved, brackets and
            // all. `std.Uri` borrows every component from the text it
            // read, and `resolveInPlace` writes back into that same text
            // for the same reason, so the cast says what is already true:
            // `copy` is this engine's own scratch.
            for (@constCast(text)) |*byte| {
                if (maskedByte(byte.*)) byte.* = host_mask_byte;
            }
        }

        var base_host_storage: [masked_host_max]u8 = undefined;
        const base_host = try maskHost(&base_host_storage, hop.url.host);

        var aux: []u8 = scratch;
        const base: std.Uri = .{
            .scheme = hop.url.scheme,
            .user = null,
            .password = null,
            .host = .{ .raw = base_host },
            .port = hop.url.port,
            .path = .{ .percent_encoded = hop.url.path },
            .query = if (hop.url.query) |q| .{ .percent_encoded = q } else null,
            .fragment = if (hop.url.fragment) |f| .{ .percent_encoded = f } else null,
        };
        const resolved = base.resolveInPlace(location.len, &aux) catch return error.InvalidUrl;
        return writeUri(out, resolved, host);
    }

    /// Sends one request and waits for its response head. Each header in
    /// `secrets` goes out beside `req.headers`, and an empty `secrets`
    /// sends the caller's headers alone.
    ///
    /// This makes exactly one hop. That is what keeps a secret inside one
    /// origin: the headers go out once, and a redirect comes back to the
    /// caller unfollowed. `followChain` owns the chain above it.
    ///
    /// **The connection may be one an earlier request opened.** The pool
    /// answers on an exact `Origin` match and on nothing weaker, so a
    /// reused connection reaches the host, the port, and the scheme this
    /// request names, and a TLS one was verified against this host name.
    ///
    /// **The retry rule.** A peer may close an idle connection at any
    /// time, and it owes the client no warning. So a request that went out
    /// on a pooled connection and got **no answer byte at all** goes out
    /// again, once, on a connection dialed fresh. The fresh connection is
    /// not a pooled one, so the second attempt cannot retry: one retry, and
    /// no loop.
    ///
    /// The rule reads the answer and not the method. A request the peer
    /// answered with even one byte is never sent again, whatever it
    /// failed with afterwards, because the peer has already acted on it.
    /// That is `Exchange.peer_answered`. curl decides the same way, in
    /// `Curl_retry_request`: it retries when `bytecount + headerbytecount`
    /// is zero and the connection was a reused one, for every method
    /// including `POST`. This engine decides the same way, and adds one
    /// condition: a request that carries a body may only go out again when
    /// that body can go back to its first byte. See the rewind rule at the
    /// top of this function and the one beside the retry below.
    fn openOnce(
        engine_state: *Engine,
        req: engine.Request,
        secrets: []const std.http.Header,
    ) engine.OpenError!*engine.Exchange {
        // **The body goes back to its first byte before every send.**
        //
        // A source with a rewind is put back on every call, the first one
        // included, so one rule covers the first send and each resend and
        // there is no "was this the first" question to get wrong. A source
        // with no rewind, which is what a pipe gives, may go out once and
        // no more.
        if (req.body) |source| {
            if (source.rewind) |rewind| {
                if (!rewind(source.ctx)) return error.RequestBodyNotResendable;
            } else if (engine_state.body_sent) {
                return error.RequestBodyNotResendable;
            }
        }

        const protocol = try resolveProtocol(req.url.scheme);
        const canonical_scheme = if (protocol == .plain) "http" else "https";

        // A url with no port names no peer, so there is nothing to dial.
        // `zurl_core.url.parse` fills the default of every scheme
        // `resolveProtocol` accepts, so nothing reaches this line today.
        // It is a branch and not an assert because a caller builds
        // `engine.Request` itself and can hand this engine any
        // `zurl_core.Url` at all, and because an assert would disappear
        // in the ReleaseFast build a user runs.
        const port = req.url.port orelse return error.InvalidUrl;

        // **Where this hop dials, which `--resolve` and `--connect-to`
        // may move away from the host the url names.**
        //
        // This is the one line that reads `req.connect_to`, and it feeds
        // the dial alone. Three things keep the url's own host below, and
        // each of them matters:
        //
        // - `requestUri` builds the `host:` line from `req.url`, so the
        //   peer is asked for the host the user named.
        // - `tlsSetup` verifies the certificate against `req.url.host`,
        //   so a peer at the dialed address must still hold a certificate
        //   for the name the user typed. Without that, this flag would be
        //   a way to turn verification off without `-k`.
        // - `Origin` carries both the url host and the dial target, so a
        //   pooled connection can never answer a request that would have
        //   dialed somewhere else.
        //
        // curl behaves the same way, measured: `--resolve` and
        // `--connect-to` each moved the connection to 127.0.0.1 and still
        // sent the `Host` header of the original name.
        const target = engine.dialTarget(req.connect_to, req.url.host, port);

        // **Which proxy this hop goes through, asked again for this hop.**
        // A redirect chain changes both the scheme and the host, and curl
        // reads `http_proxy` against the scheme and `no_proxy` against the
        // host, so the answer can differ from hop to hop. See
        // `engine.ProxySet.forHop`.
        const proxy = req.proxies.forHop(protocol == .tls, req.url.host);
        const route = try routeFor(engine_state, req, protocol, target, proxy);

        // An address and a name are two different dial targets, and
        // `zurl_net.tcp.Host` is what tells them apart. A host name check
        // alone refuses every colon, so an IPv6 literal used to stop here
        // and never reach a socket.
        //
        // A host that does not read reports which name it was. A user who
        // reads that the url is malformed, when the unreadable name came
        // from a `-x` flag or a shell profile, looks at the wrong thing.
        //
        // **A name over the length bound is a resolve fault and not a url
        // fault.** Every character of such a name is one a host name
        // allows, so the url is well formed and only the lookup is
        // impossible. curl answers it with exit 6 and this hop does the
        // same. See `zurl_net.tcp.Host.InitError.HostNameTooLong`.
        const host = zurl_net.tcp.Host.init(route.host) catch |err| {
            if (route.proxy == null) return switch (err) {
                error.InvalidHost => error.InvalidUrl,
                error.HostNameTooLong => resolve: {
                    engine_state.open_cause = zurl_net.errors.hostInit(err).message;
                    break :resolve error.CouldNotResolveHost;
                },
            };
            engine_state.open_cause = switch (err) {
                error.InvalidHost => "the proxy host is neither an address nor a host name",
                error.HostNameTooLong => "the proxy host name is longer than the dns encoding holds, so no resolver can look it up",
            };
            return error.CouldNotResolveProxy;
        };

        // The trust roots load here, at the hop that is about to speak
        // TLS, and at no earlier point. A transfer that stays on `http`
        // never reaches this line, so a certificate path that cannot be
        // read cannot fail it. A redirect chain that starts on `http` and
        // lands on `https` opens that hop through this same function, so
        // the roots still load for it. See `engine.TlsSetup`.
        //
        // `-k` needs no roots, so it loads none. `dial` asks for
        // `TrustCheck.none` on that hop, which reads no bundle at all, so
        // a load here would only cost the user a certificate file they
        // told zurl not to use. curl behaves the same way: `-k --cacert
        // /nope/x.pem` runs.
        //
        // **Two hooks, and each one loads the roots of the peer it answers
        // for.** `route.tls` says which peer this socket's session
        // authenticates, and `--proxy-insecure` reads the proxy's own flag
        // and never the origin's. A build that called one hook for both
        // would verify one peer against the other's roots.
        switch (route.tls) {
            .none => {},
            .origin => if (!req.insecure) {
                if (engine_state.tls_setup) |setup| try setup.call(setup.ptr);
            },
            .proxy => if (!route.proxy.?.insecure) {
                if (engine_state.proxy_tls_setup) |setup| try setup.call(setup.ptr);
            },
        }

        // The request line and the `host:` line both come from this one
        // value. `requestUri` says what it leaves out and why.
        const uri = requestUri(canonical_scheme, req.url);

        // **The jar answers for this hop, and for no other.** This
        // function opens one hop, and `followChain` calls it again for
        // each hop of a chain with that hop's own url. So the domain rule
        // inside the jar runs once for each host the transfer reaches,
        // and a cookie of the first host never travels to the second. See
        // `engine.CookieJar`.
        var cookie_buffer: [cookie_buffer_len]u8 = undefined;
        const jar_cookies: ?[]const u8 = if (req.cookies) |jar|
            jar.send(jar.ptr, req.url, cookie_buffer[0..engine.cookie_header_len_max])
        else
            null;
        // A jar builds this text out of a file and out of what a server
        // sent, so it is untrusted input and it reaches a header value. A
        // CR or an LF in it would put a header of somebody else's choosing
        // on the wire.
        if (jar_cookies) |value| try validateHeaderValue(value);

        // `writeRequestHead` takes one slice for the headers it writes
        // verbatim, so the secrets join the caller's headers in one owned
        // list. The list is read once, while the head goes on the wire,
        // and nothing keeps it after that.
        var owned_headers: ?[]std.http.Header = null;
        defer if (owned_headers) |owned| engine_state.allocator.free(owned);
        const extra_headers: []const std.http.Header = if (secrets.len == 0 and jar_cookies == null)
            req.headers
        else joined: {
            // The jar's own line, when the caller wrote no `Cookie` of its
            // own for this to join. `mergeCookies` decides which of the
            // two happens.
            const jar_line: usize = @intFromBool(jar_cookies != null and
                findCookieSecret(secrets) == null);
            const buffer = try engine_state.allocator.alloc(
                std.http.Header,
                req.headers.len + secrets.len + jar_line,
            );
            owned_headers = buffer;
            @memcpy(buffer[0..req.headers.len], req.headers);
            @memcpy(buffer[req.headers.len..][0..secrets.len], secrets);
            if (jar_cookies) |value| {
                if (findCookieSecret(secrets)) |index| {
                    // One `Cookie` line, and never two. A peer reads a
                    // second one as a second cookie list, and RFC 6265
                    // section 5.4 sends exactly one.
                    buffer[req.headers.len + index].value =
                        try mergeCookies(&cookie_buffer, value, secrets[index].value);
                } else {
                    // **`Cookie`, and not the lower case this engine
                    // writes its own framing headers in.** A field name
                    // has no case to a server, so this is about the bytes
                    // a person reads: curl writes `Cookie:`, and a caller
                    // that wrote its own through `secrets` gets whichever
                    // case it typed. A jar line in a third case would make
                    // one transfer's head read three ways.
                    buffer[buffer.len - 1] = .{ .name = "Cookie", .value = value };
                }
            }
            break :joined buffer;
        };

        // **The HTTP/3 hop, and it is taken before anything is dialed.**
        //
        // Every rule above this line has already run, and each one runs
        // once for all three protocols: the redirect chain, the credential
        // rule, the header validation, the cookie jar call for this hop,
        // and the trust roots this peer is checked against. Only the
        // octets on the wire differ, so only the octets are somewhere
        // else. `h3Choice` is the whole of the decision.
        switch (h3Choice(req, protocol, route)) {
            .tcp => {},
            .refuse_cleartext => {
                // curl 8.21.0 refuses the same hop with the same code.
                // Measured: `curl --http3-only http://example.com/` wrote
                // `HTTP/3 requested for non-HTTPS URL` and exited 3.
                engine_state.open_cause = http3_cleartext_message;
                return error.InvalidUrl;
            },
            .quic => {
                var answered = false;
                defer if (answered) {
                    engine_state.answered_any = true;
                };
                if (sendOnH3(engine_state, req, uri, extra_headers, host, route, &answered)) |exchange| {
                    return exchange;
                } else |err| {
                    // The peer answered part of this request over QUIC, so
                    // it has acted on it. Report the fault rather than send
                    // the same request again over TCP, which would ask the
                    // peer to act on it twice.
                    if (answered) return err;
                    // **`--http3-only` takes no other answer.** Measured:
                    // `curl --http3-only https://example.com/`, a host with
                    // no HTTP/3, exited 7 and fell back to nothing.
                    if (req.http_version == .http_3_only) return err;
                    // **A fault that is not about HTTP/3 is not answered
                    // with HTTP/2.** See `h3Fallback`.
                    if (!h3Fallback(err)) return err;
                    // **`--http3` falls back, and curl falls back with no
                    // word on standard error.** Measured: `curl --http3
                    // https://example.com/` exited 0 and reported
                    // `%{http_version} 2`, with an empty standard error.
                    //
                    // The recovery is counted and not silent.
                    // `Engine.h3_fallbacks` is the record of it. The
                    // QUIC hop's own sentence is cleared here on purpose:
                    // `cause` is read only when a later fault carries none
                    // of its own, and a sentence about QUIC would then
                    // describe a hop that is not the one that failed.
                    //
                    // The body may have gone out in part already, so the
                    // TCP hop needs it from the front again. A source that
                    // cannot go back reports the fault QUIC had, because
                    // the fallback would send a request the peer would act
                    // on as if it were whole.
                    if (req.body) |source| {
                        const rewind = source.rewind orelse return err;
                        if (!rewind(source.ctx)) return err;
                    }
                    engine_state.h3_fallbacks +|= 1;
                    engine_state.open_cause = null;
                }
            },
        }

        const pool = try engine_state.ensurePool();
        // A hop through a proxy dials the proxy, so the `--resolve` and
        // `--connect-to` target moved nothing: the origin is a name the
        // proxy resolves. The key records the proxy instead, which is the
        // peer this socket really reaches.
        const key_target: engine.DialTarget = if (route.proxy == null)
            target
        else
            .{ .host = req.url.host, .port = port, .overridden = false };
        const key = Origin.init(protocol, req.url.host, port, key_target, route.proxy, req, engine_state.trust_digest);

        // **Whether a connection to this origin may carry several streams
        // at once.** Three things must hold, and each one is a fact about
        // the handshake and not about this request:
        //
        // - The pool is shared. A pool one engine owns hands a connection
        //   to one exchange at a time and always did.
        // - The origin has a key. A host too long for `Origin` cannot go
        //   back in the pool at all.
        // - This hop can reach HTTP/2. That is a TLS hop whose ALPN offer
        //   names `h2`, or any hop under `--http2-prior-knowledge`.
        const may_share = pool.shared and key != null and mayMultiplex(req, protocol);

        // Whether this task told the pool it is dialing `key`, so the
        // record goes back on every path out of this function. A record
        // left behind would make every later request to this origin wait
        // for a dial that already ended.
        var dial_marked = false;
        defer if (dial_marked) {
            pool.acquire();
            pool.clearDialing(&key.?);
            pool.release_lock();
        };

        // A connection an earlier request opened to this exact origin, or
        // one another task is carrying streams on now. This is the whole
        // saving: no dial and, for `https`, no handshake.
        if (key) |origin| {
            pool.acquire();
            const found: ?Taken = found: while (true) {
                // **A connection that is in use and has room.** Only a
                // shared pool keeps such a list, and only an HTTP/2
                // connection can be in it.
                if (may_share) {
                    if (pool.lease(&origin)) |joined| {
                        break :found .{ .pooled = joined, .reserved = true };
                    }
                }
                // An idle connection, held alone.
                if (pool.take(&origin)) |reused| {
                    // An idle HTTP/2 connection goes back on the active
                    // list, so the tasks behind this one join it instead
                    // of dialing.
                    var reserved = false;
                    if (may_share) {
                        if (reused.h2_session) |session| {
                            if (session.shared and session.reserve()) {
                                pool.publish(reused);
                                reserved = true;
                            }
                        }
                    }
                    break :found .{ .pooled = reused, .reserved = reserved };
                }
                // **Another task is opening a connection to this origin.**
                // Wait for it rather than open a second one. That is the
                // difference between eight handshakes and one: eight
                // workers reach this at once, one of them dials, and the
                // other seven join the connection it publishes.
                //
                // The wait ends when the dial ends, whether it succeeded or
                // not. A dial that failed leaves nothing to join and this
                // task then dials itself.
                if (may_share and pool.isDialing(&origin)) {
                    pool.ready.wait(pool.io, &pool.lock) catch break :found null;
                    continue;
                }
                // Nothing to join. This task dials, and it says so.
                if (may_share) dial_marked = pool.markDialing(&origin);
                break :found null;
            };
            pool.release_lock();

            if (found) |taken| {
                var answered = false;
                defer if (answered) {
                    engine_state.answered_any = true;
                };
                if (sendOn(
                    engine_state,
                    pool,
                    taken.pooled,
                    req,
                    uri,
                    extra_headers,
                    route.proxied_head,
                    &answered,
                    taken.reserved,
                )) |exchange| {
                    return exchange;
                } else |err| {
                    // The peer answered part of this request, so it has
                    // acted on it. Report the fault. Sending it again
                    // would ask the peer to act on it twice.
                    if (answered) return err;
                    // **A peer that went quiet is not a peer that closed.**
                    // The retry below exists for an idle connection the
                    // peer dropped with no warning, which is a fault this
                    // side finds at once. A read that reached its deadline
                    // found the opposite: a socket that is still open and a
                    // peer that stopped writing. Sending again would wait
                    // the whole bound a second time and end the same way,
                    // so report the first one.
                    if (err == error.OperationTimedOut) return err;
                    // The peer answered nothing. It closed the connection
                    // while it sat idle, which it may do at any time and
                    // with no warning. Fall through and dial. The
                    // connection below is a fresh one, so this is the one
                    // retry and there is no loop.
                    //
                    // The body may have gone out in part already, so the
                    // retry needs it from the front again. A source that
                    // cannot go back reports the fault the first attempt
                    // had. The retry would send a request the peer would
                    // act on as if it were whole.
                    if (req.body) |source| {
                        const rewind = source.rewind orelse return err;
                        if (!rewind(source.ctx)) return err;
                    }
                }
            }
        }

        const fresh = try dial(engine_state, pool, key, host, route, req);

        // **A connection that can multiplex is published before its first
        // request goes out.** The session has to exist for another task to
        // join, and it cannot wait for the answer to this request: seven
        // waiting workers would then pay a whole round trip before they
        // could write anything. RFC 9113 section 3.4 lets the preface and
        // the first request go out together, which is what `Session.create`
        // already wrote, so nothing is sent early here either.
        const reserved = publishFresh(engine_state, pool, fresh, req, may_share);
        if (dial_marked) {
            pool.acquire();
            pool.clearDialing(&key.?);
            pool.release_lock();
            dial_marked = false;
        }

        // A fresh connection carries no retry of the engine's own, so
        // nothing here reads the flag to decide a resend. It still reaches
        // `Engine.answered_any`, because a caller with a retry of its own
        // has to know whether this peer answered.
        var answered = false;
        defer if (answered) {
            engine_state.answered_any = true;
        };
        return sendOn(engine_state, pool, fresh, req, uri, extra_headers, route.proxied_head, &answered, reserved);
    }

    /// One connection the pool handed back, and whether a stream slot on
    /// it was claimed with it. See `h2.Session.reserve`.
    const Taken = struct {
        pooled: *Pooled,
        reserved: bool,
    };

    /// Builds the HTTP/2 session on a connection that just came up and
    /// offers it to the other tasks, and says whether a stream slot on it
    /// was claimed for this request.
    ///
    /// A connection that cannot multiplex, or a session that cannot be
    /// built, is left to this one task, which is what every connection got
    /// before a pool could be shared. A session that cannot be built is not
    /// a failure here: `sendOnH2` builds one of its own and reports the
    /// fault where the request is.
    fn publishFresh(
        engine_state: *Engine,
        pool: *Pool,
        fresh: *Pooled,
        req: engine.Request,
        may_share: bool,
    ) bool {
        if (!may_share) return false;
        if (fresh.h2_session != null) return false;
        // **The same two answers `sendOn` reads, and in the same order.**
        // A peer that chose `h2` through ALPN speaks HTTP/2, and so does a
        // peer under `--http2-prior-knowledge`, which answers nothing and
        // needs to answer nothing: RFC 9113 section 3.3. A build that read
        // only the ALPN answer here published no cleartext connection at
        // all, so prior knowledge shared nothing.
        const prior_knowledge = req.http_version == .prior_knowledge;
        if (!prior_knowledge and !h2.negotiated(&fresh.connection)) return false;

        // The connection carries the owner's read bound from here on. See
        // `h2.Session.read_timeout`.
        const session = h2.Session.create(
            engine_state.allocator,
            &fresh.connection,
            engine_state.read_timeout,
        ) catch return false;
        session.markShared();
        fresh.h2_session = session;

        pool.acquire();
        defer pool.release_lock();
        pool.publish(fresh);
        // The slot for this request is claimed before any other task can
        // see the session, so this request can never be the one that finds
        // the connection full.
        const reserved = session.reserve();
        std.debug.assert(reserved);
        return reserved;
    }

    /// Whether a connection this request opens could speak HTTP/2, and so
    /// could carry a stream for another request beside this one.
    ///
    /// It reads the ALPN offer and never the answer, because the answer
    /// does not exist yet: this decides whether to wait for another task's
    /// handshake, which happens before any handshake of this task. A hop
    /// that offered `h2` and got `http/1.1` costs one wait and then dials,
    /// which is what curl's own parallel path costs for the same peer.
    ///
    /// - `--http1.1` offers `http/1.1` alone, so no connection of that hop
    ///   can multiplex.
    /// - `--no-alpn` sends no offer, so the peer cannot choose `h2`.
    /// - A cleartext hop has no ALPN. `--http2` on one sends an
    ///   `Upgrade: h2c` offer, and an upgraded stream is stream 1 of a
    ///   connection this side never publishes, so it is not counted here.
    /// - `--http2-prior-knowledge` speaks HTTP/2 with no offer at all, over
    ///   TLS and over cleartext both. RFC 9113 section 3.3.
    fn mayMultiplex(req: engine.Request, protocol: Protocol) bool {
        if (req.http_version == .prior_knowledge) return true;
        if (protocol != .tls) return false;
        if (req.no_alpn) return false;
        return switch (req.http_version) {
            .any, .http_2 => true,
            .http_1_1 => false,
            else => false,
        };
    }

    /// Opens a connection to the peer `req` names, ready for the pool.
    ///
    /// `key` is the origin the connection may serve again, and null makes
    /// it a connection that is used once and closed. See `Origin.init` for
    /// the one reason a caller has none.
    ///
    /// The connection is heap-allocated before it is opened, because
    /// `zurl_net.Connection.init` fills it in place: the TLS session holds
    /// the address of the connection's own buffers, so the value must
    /// never move.
    fn dial(
        engine_state: *Engine,
        pool: *Pool,
        key: ?Origin,
        host: zurl_net.tcp.Host,
        route: Route,
        req: engine.Request,
    ) engine.OpenError!*Pooled {
        const pooled = try pool.allocator.create(Pooled);
        errdefer pool.allocator.destroy(pooled);

        pooled.* = .{
            // `openConnection` fills this in place, and only then does
            // this value own a socket.
            .connection = undefined,
            .origin = key,
            // Built by `sendOn`, and only for a peer that chose `h2`.
            .h2_session = null,
            // The caller of `dial` is the one holder until it hands the
            // connection to an exchange or closes it.
            .leases = 1,
        };

        // **The proxy step, when this hop has one.** It runs inside the
        // raced task, on the open stream, before any handshake, so the
        // dial, the proxy dialogue, and the handshake share one
        // `--connect-timeout`. See `zurl_net.bounded.Upgrade` and
        // `zurl_net.proxy`.
        //
        // The runner lives on this frame and outlives `openConnection`,
        // which is what lets the fault it recorded be read back: a task
        // that loses the connect race returns nothing at all.
        //
        // A hop with no step still builds one, because `Runner.step` is not
        // optional. It is never run: the `upgrade` field below is null for
        // such a hop, so nothing reaches it, and `runner.failure` stays
        // null so nothing reads it either.
        var runner: zurl_net.proxy.Runner = .{
            .step = route.step orelse .{ .connect = .{ .target = .{ .host = "", .port = 0 } } },
        };

        // The dial and the TLS handshake, under one bound. See
        // `openConnection` for why they cannot be two.
        openConnection(engine_state, &pooled.connection, .{
            .allocator = engine_state.allocator,
            .io = engine_state.io,
            .host = host,
            .port = route.port,
            .read_buffer_len = engine_state.read_buffer_len,
            .no_delay_error = &engine_state.no_delay_error,
            .no_delay = req.tcp_no_delay,
            // **The one branch that picks whose certificate is checked.**
            // `route.tls` was decided by `routeFor`, and each arm reads the
            // flag and the bundle of the peer it names.
            .tls = switch (route.tls) {
                .none => null,
                .origin => tlsSetup(
                    req,
                    &engine_state.ca_bundle_lock,
                    &engine_state.ca_bundle,
                ),
                .proxy => proxyTlsSetup(
                    req,
                    route.proxy.?,
                    &engine_state.proxy_ca_bundle_lock,
                    &engine_state.proxy_ca_bundle,
                ),
            },
            .upgrade = if (route.step == null) null else runner.upgrade(),
        }) catch |err| {
            // A step that stopped reports `UpgradeFailed`, which says only
            // that a step failed. The runner knows what the proxy did, and
            // a user needs that and not the layer's name.
            if (err == error.SslConnectError and runner.failure != null) {
                return mapProxyFailure(engine_state, &runner);
            }
            // A dial that never reached the proxy names the proxy, so a
            // user does not look at the url they typed.
            if (route.proxy != null and err == error.CouldNotResolveHost) {
                return error.CouldNotResolveProxy;
            }
            return err;
        };
        return pooled;
    }

    /// Writes the request head on `pooled` and reads the response head.
    ///
    /// On success the returned exchange owns `pooled` and hands it back to
    /// `pool` at `close`. On a fault `pooled` is closed and freed here, and
    /// the caller must not touch it again: a connection that failed mid
    /// request has an unknown number of bytes still on it, so it can never
    /// serve another request.
    ///
    /// `answered` says whether the peer answered any byte of this request.
    /// It is written on every path. A caller that sent on a pooled
    /// connection reads it to decide whether the request may go out again.
    /// See `openOnce`.
    fn sendOn(
        engine_state: *Engine,
        pool: *Pool,
        pooled: *Pooled,
        req: engine.Request,
        uri: std.Uri,
        extra_headers: []const std.http.Header,
        proxied: ?ProxiedHead,
        answered: *bool,
        reserved: bool,
    ) engine.OpenError!*engine.Exchange {
        answered.* = false;
        // **Every failure below gives this holder's claim back, and says
        // the connection is unfit.** On an HTTP/1.1 connection that is the
        // last claim and the socket closes here. On a shared HTTP/2 one it
        // may not be: another task may still be reading a stream, so the
        // connection leaves the list that new requests join and the last
        // holder out closes it. Only the success path reaches the return,
        // which is where the exchange takes the claim over.
        errdefer pool.releaseOne(pooled, false);

        // **The protocol, read back off the handshake this file made.**
        //
        // Everything above this line is protocol independent: the redirect
        // chain, the credential rule, the header validation, the cookie
        // jar calls, and the pool all ran already, and they run the same
        // for either answer. Only the octets on the wire differ, so only
        // the octets are somewhere else.
        //
        // A peer that chose `http/1.1`, and a peer that answered nothing at
        // all, fall through to the HTTP/1.1 path below, which is the path
        // every transfer took before this branch existed.
        //
        // **`--http2-prior-knowledge` needs no answer to read.** RFC 9113
        // section 3.3: a client that already knows the peer speaks HTTP/2
        // sends the connection preface straight away. Over TLS the ALPN
        // offer was `h2` alone, so a peer that got this far chose it or
        // answered nothing, and either way the caller said it knows. Over
        // cleartext there is no ALPN at all and the flag is the whole of
        // the choice. Both reach the same engine.
        const prior_knowledge = req.http_version == .prior_knowledge;
        if (prior_knowledge or h2.negotiated(&pooled.connection)) {
            return sendOnH2(engine_state, pool, pooled, req, uri, extra_headers, answered, .fresh, reserved);
        }

        // A claimed stream slot belongs to an HTTP/2 session, and only a
        // connection that reached the branch above has one. A caller that
        // claimed a slot and landed here would leave the claim behind and
        // the connection would fill up with slots nobody uses. Nothing
        // reaches it: `openOnce` claims only on a connection whose session
        // already exists.
        std.debug.assert(!reserved);

        const exchange = try engine_state.allocator.create(Exchange);
        errdefer engine_state.allocator.destroy(exchange);

        // **Freed when the peer took the `Upgrade: h2c` offer.** The rest
        // of that transfer runs on `h2.Exchange`, so this one has nothing
        // left to do and must not leak.
        //
        // Declared before the `defer` that copies `peer_answered` out, so
        // it runs **after** it: a `defer` runs in reverse order of
        // declaration, and reading a field of freed memory is the one way
        // this could go wrong. The `errdefer` above covers every failing
        // path and this flag stays false on all of them.
        var upgraded_away = false;
        defer if (upgraded_away) engine_state.allocator.destroy(exchange);

        exchange.* = .{
            .interface = .{ .ptr = exchange, .vtable = &exchange_vtable },
            .allocator = engine_state.allocator,
            .io = engine_state.io,
            // Read once, here, so every read of this exchange holds to the
            // bound the transfer started with.
            .read_timeout = engine_state.read_timeout,
            .read_bounds_dropped = 0,
            .read_timed_out = false,
            .pool = pool,
            .pooled = pooled,
            .http_reader = undefined,
            .transfer_encoding = .none,
            .body_content_length = null,
            .content_encoding = .identity,
            .decompress = undefined,
            .decompress_buffer = undefined,
            .zstd_buffer = null,
            .head_scratch = null,
            .location_storage = undefined,
            .location_len = null,
            .www_authenticate_storage = undefined,
            .www_authenticate_len = null,
            .www_authenticate_oversize = false,
            .head_value = undefined,
            .transfer_buffer = undefined,
            .body = undefined,
            .body_source = undefined,
            .transfer_vtable = undefined,
            .body_taken = false,
            .body_partial = false,
            .framing_finished = false,
            // Both false until the head says otherwise, so a request that
            // never got an answer leaves a connection nothing can reuse.
            .keep_alive = false,
            .body_empty = false,
            .peer_answered = false,
            // `followChain` sets this on the exchange that ends a chain.
            .chain_storage = null,
        };
        // The flag belongs to the exchange, which lives past the reads
        // below. This copies it out on every return, the failing ones
        // included.
        defer answered.* = exchange.peer_answered;

        // **The `Upgrade: h2c` offer, on a cleartext hop under `--http2`.**
        // See `upgradeOffer` for the whole rule and for what curl sends.
        var upgrade_buffer: [engine.http2_settings_len_max]u8 = undefined;
        const upgrade_settings = upgradeOffer(req, pooled, &upgrade_buffer);

        // **`--compressed`, and nothing else, decides whether this body is
        // decoded.** A caller's own `Accept-Encoding` header does not
        // raise it: measured against curl 8.21.0, `curl -H
        // 'Accept-Encoding: gzip'` with no `--compressed`, answered in
        // gzip, wrote the 64 compressed octets out and exited 0.
        // `writeRequestHead` still writes no line of its own beside the
        // caller's, so exactly one offer goes out.
        const accept_encoding = req.accept_encoding;

        writeRequestHead(
            pooled.connection.writer(),
            req.method,
            uri,
            req.user_agent,
            extra_headers,
            req.body,
            proxied,
            upgrade_settings,
            accept_encoding,
        ) catch return error.WriteError;
        // The body goes out right behind the head, on the same writer and
        // under the same flush. `openOnce` has already put the source back
        // at its first byte, so this reads a whole body and never a tail.
        //
        // The flag goes up before the write and not after it. A write that
        // failed part way through has still read part of the source, so a
        // send that got no further than here must count as one.
        if (req.body) |source| {
            engine_state.body_sent = true;
            try writeRequestBody(pooled.connection.writer(), source);
        }
        // Both buffers, not just the writer's. An encrypted connection
        // holds the plaintext in one buffer and the ciphertext in the next
        // one, and a flush of the writer alone leaves the whole request
        // inside this process, waiting for an answer to a request that
        // never went out.
        pooled.connection.flush() catch return error.WriteError;

        exchange.http_reader = .{
            .in = pooled.connection.reader(),
            .state = .ready,
            // Filled when `bodyReaderDecompressing` is called.
            .interface = undefined,
            // The same number that sized the connection's read buffer, so
            // the bound and the room for it cannot drift apart.
            .max_head_len = engine_state.read_buffer_len,
        };

        const head = receiveResponseHead(
            exchange,
            accept_encoding,
            &engine_state.read_bounds_dropped,
        ) catch |err| {
            // The name says the peer answered something nothing can read.
            // The sentence says which octet, so a user looks at the
            // server's header and not at the url they typed. See
            // `engine.refuseNulInHead`.
            if (err == error.WeirdServerReply) engine_state.open_cause = engine.nul_in_head_message;
            return err;
        };

        // **The peer took the `Upgrade: h2c` offer.** RFC 7540 section 3.2:
        // a `101` answer means the octets behind this head are HTTP/2
        // frames and the request that carried the offer is stream 1, with
        // this side's half already closed.
        //
        // **The `101` head goes to the log, and the HTTP/2 head goes in
        // behind it.** Measured against curl 8.21.0 and a loopback server
        // that answered `101` and then wrote HTTP/2 frames, `curl --http2
        // -D file` left both blocks and then the trailer lines:
        //
        // ```text
        // HTTP/1.1 101 Switching Protocols\r\n
        // Connection: Upgrade\r\n
        // Upgrade: h2c\r\n
        // \r\n
        // HTTP/2 200 \r\n
        // content-type: text/plain\r\n
        // \r\n
        // grpc-status: 0\r\n
        // x-end: yes\r\n
        // ```
        //
        // It is not the answer to the request, so nothing else here reads
        // it: the status, the location, and the body all come from the
        // `HEADERS` frame on stream 1.
        //
        // **The handoff of the unread octets is what makes this safe.**
        // `std.http.Reader.in` is `pooled.connection.reader()` itself, and
        // `receiveHead` consumes exactly the head out of it, so any frame
        // octet that arrived in the same read is still in that reader's
        // buffer. `h2.Session` reads from the same reader and picks them
        // up. A design that gave the head reader a buffer of its own would
        // have eaten the first frames here.
        if (upgrade_settings != null and head.status == .switching_protocols) {
            // A `101` that named another protocol, or named none, switched
            // to something this build cannot read. The octets behind it
            // are whatever that protocol writes, so the connection is over
            // rather than guessed at.
            if (!h2.upgradedToH2c(upgradeField(head))) return error.ReadError;
            try engine_state.logHead(head.bytes);
            upgraded_away = true;
            // An upgraded connection is never published for sharing: the
            // stream the `101` opened is stream 1 and it belongs to this
            // request alone, so no slot was claimed for it.
            return sendOnH2(engine_state, pool, pooled, req, uri, extra_headers, answered, .upgraded, false);
        }

        // The per-line bound, which `std.http.Reader` does not keep.
        // `receiveHead` already refused a head over `head_len_max`, so
        // what arrives here is a head of legal total size. It may still
        // carry one line that curl refuses. See `head_field_len_max`.
        //
        // A head that breaks both bounds arrives here as
        // `error.HttpHeadersOversize`, so it reports the whole-head bound.
        // curl reads a head as a stream and reports whichever bound it
        // reaches first, so curl can report the line bound for the same
        // head. Such a head is over 300 KiB and carries a line over 100
        // KiB, and both answers refuse it.
        if (hasOversizeField(head.bytes)) return error.HeaderLineTooLarge;

        // The raw head goes to the log before anything else reads it, and
        // long before the first body read invalidates it. `head.bytes` is
        // the status line through the empty line that ends the head,
        // exactly as the peer wrote it, which is what `curl -D` writes to
        // a file.
        try engine_state.logHead(head.bytes);

        if (head.location) |location| {
            if (location.len <= exchange.location_storage.len) {
                @memcpy(exchange.location_storage[0..location.len], location);
                exchange.location_len = location.len;
            }
        }

        // **Every `Set-Cookie` of this hop goes to the jar, and the jar
        // owns every rule about it.** The engine keeps no cookie of its
        // own and reads no field of the header: which host may set which
        // domain is one rule, written once, in `zurl_core.cookie`.
        //
        // This runs here, before the first body read invalidates the head
        // bytes, and on every hop of a chain. A `Set-Cookie` on a redirect
        // is what lets the next hop carry the session, which is what curl
        // sends, measured on a loopback listener.
        //
        // The url is `req.url`, which is this hop's own url and not the
        // one the caller named. `followChain` rewrites that field for each
        // hop before it calls `openOnce`.
        if (req.cookies) |jar| {
            var cookie_it = head.iterateHeaders();
            while (cookie_it.next()) |header| {
                if (!std.ascii.eqlIgnoreCase(header.name, "Set-Cookie")) continue;
                jar.receive(jar.ptr, req.url, header.value);
            }
        }

        // `std.http.Client.Response.Head` keeps no dedicated field for
        // `WWW-Authenticate`, unlike `location` or `content_type`, so this
        // walks every header to find it.
        //
        // A server may send more than one. This keeps the first one that
        // offers `Digest`, and the first header of any kind when none
        // does. A server that lists `Basic` in one header and `Digest` in
        // the next used to get a `Basic` answer, which sends the password
        // in reversible base64 to a server that had offered a scheme where
        // it never travels. A `Digest` header too large to keep counts as
        // one that was offered; see the rule below the loop.
        //
        // Only one value is kept. A caller that needs to answer two
        // challenges from two headers at once needs a list here, which
        // nothing asks for today.
        //
        // **A hop the engine reached by following a redirect has no
        // challenge to offer this caller.** The chain past its first hop
        // carries no secret, and a challenge answered from there builds a
        // Digest response over a `realm` and a `nonce` a redirect target
        // chose and sends it to the url the caller named. So the challenge
        // is read only where the credential could have gone. See
        // `Engine.chain_challenge_untrusted`, which `--location-trusted`
        // turns off.
        var digest_dropped = false;
        var kept_digest = false;
        if (!engine_state.chain_challenge_untrusted) {
            var header_it = head.iterateHeaders();
            while (header_it.next()) |header| {
                if (!std.ascii.eqlIgnoreCase(header.name, "WWW-Authenticate")) continue;

                const digest = zurl_core.auth.hasDigestChallenge(header.value);
                if (header.value.len > exchange.www_authenticate_storage.len) {
                    // Recovery is never silent. The caller cannot answer a
                    // challenge it never saw, so say the challenge arrived
                    // and did not fit.
                    exchange.www_authenticate_oversize = true;
                    if (digest) digest_dropped = true;
                    continue;
                }

                if (exchange.www_authenticate_len != null and !digest) continue;
                @memcpy(exchange.www_authenticate_storage[0..header.value.len], header.value);
                exchange.www_authenticate_len = header.value.len;
                kept_digest = digest;
                if (digest) break;
            }
        }

        // A `Digest` challenge that did not fit must not leave a `Basic`
        // one behind to answer. That answer sends the password in
        // reversible base64 to a server that had offered a scheme where the
        // password never travels, and the length of a realm decides which
        // happens. Report no challenge instead. The oversize flag beside it
        // still says that a challenge arrived and was dropped.
        if (digest_dropped and !kept_digest) exchange.www_authenticate_len = null;

        // **A `HEAD` response carries no body byte, whatever its head
        // says.** RFC 9110 section 9.3.2: the answer to a `HEAD` is the
        // head the same `GET` would have, and no content. So the
        // `content-length` on it describes a body that is not coming, and
        // a reader that trusted it would wait for bytes the peer will
        // never send until the connection times out.
        //
        // The framing is forced here, before anything reads it, so
        // `bodyReader`, `body_empty`, and the length this reports to the
        // caller all describe the same thing: a body of no bytes. `-I`
        // fills this path.
        const head_request = req.method == .HEAD;

        // Kept for `bodyReader`, which runs long after the head bytes are
        // gone. The framing has to outlive the text that announced it.
        exchange.transfer_encoding = if (head_request) .none else head.transfer_encoding;
        exchange.body_content_length = if (head_request) 0 else head.content_length;
        exchange.content_encoding = if (head_request) .identity else head.content_encoding;

        // **The zstd window is taken here, where a fault still has a way
        // out.** `bodyReaderImpl` cannot fail: it answers a `*std.Io.Reader`
        // and has no error to return, so an allocation there would have to
        // panic or hand back a reader that decodes nothing. The head is
        // already parsed and `readHead` has already refused every coding
        // this engine does not read, so `.zstd` here is a coding the
        // request offered.
        if (exchange.content_encoding == .zstd) {
            // **The count is claimed before the memory, and the two are
            // released together.** A window is 8.1 MiB and one exchange
            // holds it until `closeImpl`, so the number of them alive at
            // once is what a peer would otherwise choose. See
            // `zstd_windows_max`.
            if (!exchange.pool.takeZstdWindow()) return error.OutOfMemory;
            errdefer exchange.pool.releaseZstdWindow();
            exchange.zstd_buffer = try engine_state.allocator.alloc(u8, zstd_buffer_len);
        }

        // The two answers the pool needs, read here while the head bytes
        // are still there to read. See `reusable`.
        exchange.keep_alive = peerKeepsAlive(head);
        // A response that announced a length of zero and no transfer
        // encoding carries no body byte, so the connection already sits at
        // the start of the next response. Every other shape needs the body
        // read to its end first.
        exchange.body_empty = exchange.transfer_encoding == .none and
            (exchange.body_content_length orelse 1) == 0;

        // A chunked transfer frames its own length. A `Content-Length`
        // beside it says nothing about the body, and RFC 9112 tells a
        // recipient to ignore it, so do not report it. A caller that got
        // the number would trust it, and the body would not match.
        const logged = engine_state.loggedHeads();
        exchange.head_value = .{
            .status = @intFromEnum(head.status),
            // The version the peer wrote on its own status line, read
            // back off the parsed head. A peer that answered `HTTP/1.0`
            // is reported as `1.0`, which is what curl prints for it.
            .wire_version = switch (head.version) {
                .@"HTTP/1.0" => .http_1_0,
                .@"HTTP/1.1" => .http_1_1,
            },
            // A `HEAD` reports zero, the number of body bytes that are
            // coming, and not the length the peer announced for the body
            // it is not sending. A caller that took the announced number
            // would draw a progress meter that never fills.
            .content_length = switch (exchange.transfer_encoding) {
                .chunked => null,
                .none => exchange.body_content_length,
            },
            .transfer_encoding = exchange.transfer_encoding,
            .location = if (exchange.location_len) |len| exchange.location_storage[0..len] else null,
            .www_authenticate = if (exchange.www_authenticate_len) |len| exchange.www_authenticate_storage[0..len] else null,
            .www_authenticate_oversize = exchange.www_authenticate_oversize,
            // `open` sets this on the exchange it resends without the
            // credential. One send of one request withholds nothing.
            .credential_withheld = false,
            .body_decoded = exchange.content_encoding != .identity,
            .headers = logged.all,
            .final_headers = logged.final,
            .headers_oversize = engine_state.head_log_dropped,
            // `followChain` sets this on the exchange that ends a chain.
            // One hop lands on the url the caller named.
            .effective_url = null,
        };

        return &exchange.interface;
    }

    /// Reads one response head, and stops waiting after `read_timeout`.
    ///
    /// **The head phase had no bound at all before this.**
    /// `--connect-timeout` covers the dial, the proxy step and the TLS
    /// handshake, and it ends there. A peer that accepted the connection
    /// and then wrote nothing held the transfer for as long as it liked,
    /// and on a pooled connection even the connect bound was already over.
    /// See `default_read_timeout_s`.
    ///
    /// The bound is on the whole head and not on one octet of it, because
    /// `std.http.Reader.receiveHead` reads until the head ends and gives
    /// no seam in the middle. A head is at most `head_len_max`, so a peer
    /// that cannot deliver 300 KiB inside the bound is a peer that has
    /// stopped. curl ends the same shape at the same place: measured
    /// against curl 8.21.0, a listener writing one header line every 3
    /// seconds under `--speed-limit 100 --speed-time 2` exited 28 after
    /// 2.004 seconds.
    ///
    /// Each call of the `100 Continue` loop gets the deadline again, so a
    /// peer that keeps answering `100` is bounded by `continue_heads_max`
    /// and never by this.
    fn receiveHeadBounded(
        exchange: *Exchange,
        /// `Engine.read_bounds_dropped`. The head phase runs inside
        /// `sendOn`, where the engine is still in hand, so the head's own
        /// count goes where a caller can read it.
        dropped: *usize,
    ) RacedRead(std.http.Reader.HeadError![]const u8) {
        return raceRead(
            exchange.io,
            exchange.read_timeout,
            dropped,
            std.http.Reader.HeadError![]const u8,
            receiveHeadTask,
            .{&exchange.http_reader},
        );
    }

    /// One `receiveHead`, as its own task.
    fn receiveHeadTask(reader: *std.http.Reader) std.http.Reader.HeadError![]const u8 {
        return reader.receiveHead();
    }

    /// Reads response heads until one is the answer, and returns it.
    ///
    /// A `100 Continue` is not the answer. RFC 9110 section 15.2.1 tells a
    /// client to read past it and wait for the real status, which is what
    /// `std.http.Client` does with `handle_continue`. `std` loops with no
    /// bound at all, so a peer that answers `100` forever hangs the
    /// transfer; `continue_heads_max` bounds this one.
    ///
    /// The head that comes back points into the connection's read buffer.
    /// It stays valid until the first body read, and no further.
    ///
    /// Records `Exchange.peer_answered` on every path. A head that arrived
    /// says the peer answered; a head that failed says so too whenever any
    /// byte of it reached the buffer, because `std.http.Reader.receiveHead`
    /// leaves what it read where it read it. Only a peer that answered
    /// nothing leaves the flag false, and only then may the request go out
    /// again. See `openOnce`.
    fn receiveResponseHead(
        exchange: *Exchange,
        /// Whether the request offered a compressed body. See
        /// `engine.Request.accept_encoding`.
        accept_encoding: bool,
        /// `Engine.read_bounds_dropped`. See `receiveHeadBounded`.
        dropped: *usize,
    ) engine.OpenError!std.http.Client.Response.Head {
        var seen_continue: usize = 0;
        while (true) {
            const bytes = switch (exchange.receiveHeadBounded(dropped)) {
                .done => |result| result catch |err| {
                    if (exchange.http_reader.in.buffered().len != 0) exchange.peer_answered = true;
                    return mapHeadError(err);
                },
                // **The head never finished arriving.** Whatever reached
                // the buffer is a piece of a head, so the peer did answer
                // and the request must not go out again. `sendOn`'s own
                // `errdefer` closes this connection.
                .timed_out => {
                    if (exchange.http_reader.in.buffered().len != 0) exchange.peer_answered = true;
                    exchange.read_timed_out = true;
                    return error.OperationTimedOut;
                },
                .canceled => {
                    if (exchange.http_reader.in.buffered().len != 0) exchange.peer_answered = true;
                    return error.Canceled;
                },
            };
            exchange.peer_answered = true;

            // **A NUL anywhere in the head ends the transfer, and it is
            // read here, before anything keeps the octets.**
            // `std.http.Reader.receiveHead` splits the head on CRLF and
            // says nothing about a NUL inside a value, so the octet passed
            // through this engine and reached a file name, an
            // `--etag-save` file, and from that file a later request
            // header, each of which reads a different length of the same
            // value.
            //
            // The rule used to live in `src/cli/run.zig`, over the head
            // blocks this engine kept. Two holes were open there: a
            // library caller of `zurl.Client` never runs that code, and a
            // head this engine dropped for its size left the blocks empty,
            // so the scan had nothing to read. `bytes` is the head as it
            // arrived, so neither hole is open here. See
            // `engine.refuseNulInHead`.
            try engine.refuseNulInHead(bytes);

            // **What the coding means is decided here, from the field the
            // peer wrote, and by the one rule all three engines ask.** See
            // `engine.contentEncoding`: without an offer the field is
            // ignored and the peer's own octets go to the caller, and with
            // one the coding is decoded or refused by name.
            //
            // It is read before the parse, because the parse may refuse
            // the head over this very field.
            const coding = try engine.contentEncoding(
                contentEncodingField(bytes),
                accept_encoding,
            );

            // **The response framing is read here, before `std` frames
            // anything from it.** A `Content-Length` that is not `1*DIGIT`
            // is not a length, and reading one as a length frames the body
            // where no compliant parser in the path frames it. See
            // `hasInvalidContentLength` for the grammar and the curl
            // measurement behind it.
            //
            // `ReadError` is the answer every other malformed head gets,
            // and this is a malformed head.
            if (hasInvalidContentLength(bytes)) return error.ReadError;

            // **Every way `std` can refuse a head goes to one repair.**
            // `Head.parse` reports six of them, and which one a peer gets
            // says little about what is wrong: a head written with bare
            // line feeds reports `HttpHeadersInvalid` where it has no
            // fields, and `InvalidContentLength` where it has a
            // `Content-Length`, because the value then runs to the end of
            // the head. Both are the same fault and want the same repair.
            //
            // `parseRefusedHead` answers `ReadError` for a head it cannot
            // repair, so a head that really is malformed still fails the
            // way it always did.
            var head = std.http.Client.Response.Head.parse(bytes) catch |err| switch (err) {
                // **Not a malformed head: a coding `std` has no enumerator
                // for, such as `br`.** `std` gives back no head at all for
                // it, so the status and the framing go too.
                //
                // `coding` above already answered what this build does
                // with such a head. An offer made it `BadContentEncoding`
                // and this line is never reached. With no offer the answer
                // is `identity`, the octets pass through, and the head has
                // to be read: curl writes that body out and exits 0, so
                // this parses the head with the one field hidden.
                else => try parseRefusedHead(
                    exchange,
                    exchange.allocator,
                    bytes,
                ),
            };

            if (head.status == .@"continue") {
                seen_continue += 1;
                if (seen_continue > continue_heads_max) return error.ReadError;
                continue;
            }

            // **`std`'s own answer is replaced by this build's.** `std`
            // names whichever coding it recognised, which says nothing
            // about whether this request asked to have the body decoded.
            // Everything downstream reads this field: `bodyReader` builds
            // the decoder from it, `body_decoded` reports it, and the zstd
            // window is taken for it.
            head.content_encoding = coding;

            return head;
        }
    }

    const exchange_vtable: engine.Exchange.VTable = .{
        .head = headImpl,
        .bodyReader = bodyReaderImpl,
        .check = checkImpl,
        .close = closeImpl,
        .adoptChain = adoptChainImpl,
        .withheldCredential = withheldCredentialImpl,
        .trailers = trailersImpl,
    };

    /// **This engine reports no trailer section.**
    ///
    /// A chunked HTTP/1.1 body may carry one, RFC 9112 section 7.1.2, and
    /// `std.http.Reader` reads past it to reach the end of the body rather
    /// than hand it back. There is nothing here to report, so this answers
    /// null rather than invent one.
    ///
    /// The HTTP/2 engine does report them, and a redirect chain that ends
    /// on an HTTP/2 hop reads its trailers through the same seam. See
    /// `h2.Exchange.trailersImpl` and `engine.Exchange.trailers`.
    fn trailersImpl(ptr: *anyopaque) ?[]const u8 {
        _ = ptr;
        return null;
    }

    fn adoptChainImpl(ptr: *anyopaque, storage: []u8, url: []const u8) void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        self.chain_storage = storage;
        self.head_value.effective_url = url;
    }

    fn withheldCredentialImpl(ptr: *anyopaque) void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        self.head_value.credential_withheld = true;
    }

    const body_vtable: std.Io.Reader.VTable = .{
        .stream = bodyStream,
        .discard = bodyDiscard,
    };

    fn headImpl(ptr: *anyopaque) engine.Head {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        return self.head_value;
    }

    fn bodyReaderImpl(ptr: *anyopaque, buffer: []u8) *std.Io.Reader {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        // One exchange has one body. A second reader would restart the
        // framing over a stream that already moved.
        std.debug.assert(!self.body_taken);
        self.body_taken = true;

        // The head bytes are invalid from here on: the transfer reader
        // reads over the same buffer that held them. Everything this
        // exchange still reports about the head was copied out already.
        self.body_source = self.http_reader.bodyReaderDecompressing(
            &self.transfer_buffer,
            self.transfer_encoding,
            self.body_content_length,
            self.content_encoding,
            &self.decompress,
            // The zstd window when the answer is zstd, and the flate
            // window otherwise. `openOnce` took the first one where the
            // head said so, and `std.compress.zstd.Decompress.init`
            // asserts the size, so the wrong buffer here is a panic and
            // not a quiet wrong answer.
            self.zstd_buffer orelse &self.decompress_buffer,
        );

        // **The chunk size guard goes in here, on a chunked body only.**
        // `bodyReader` has just written the transfer reader, its methods
        // included, so this is the first moment the methods exist and the
        // last moment before a caller can read through them. A body framed
        // any other way has no chunk size to bound, and keeps the methods
        // `std` gave it.
        //
        // Only the methods change. The reader itself, and its buffer, are
        // the ones `std` made, so what `decompress` holds and what
        // `finishFraming` compares stay the same objects.
        if (self.transfer_encoding == .chunked) {
            const transfer = &self.http_reader.interface;
            self.transfer_vtable = transfer.vtable;
            transfer.vtable = &chunk_guard_vtable;
        }

        self.body = .{
            .vtable = &body_vtable,
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        };
        return &self.body;
    }

    /// The methods the chunk size guard puts on the transfer reader.
    ///
    /// **Two methods cover every read.** `std.Io.Reader.VTable` has four
    /// members and the two left out here take their defaults, which is
    /// what `std.http.Reader.bodyReader` does too. `defaultReadVec` reads
    /// through `stream`, and `defaultRebase` moves octets already held and
    /// reads nothing. So a caller that streams, discards, fills, peeks or
    /// takes reaches `std`'s chunked framing through one of the two below,
    /// and the guard runs first on every one of them.
    const chunk_guard_vtable: std.Io.Reader.VTable = .{
        .stream = chunkGuardStream,
        .discard = chunkGuardDiscard,
    };

    fn chunkGuardStream(
        io_reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self = chunkGuardExchange(io_reader);
        try self.guardChunkSize();
        return self.transfer_vtable.stream(io_reader, writer, limit);
    }

    fn chunkGuardDiscard(
        io_reader: *std.Io.Reader,
        limit: std.Io.Limit,
    ) std.Io.Reader.Error!usize {
        const self = chunkGuardExchange(io_reader);
        try self.guardChunkSize();
        return self.transfer_vtable.discard(io_reader, limit);
    }

    /// The exchange that owns the transfer reader `io_reader` is.
    ///
    /// The transfer reader is `std.http.Reader.interface`, and the
    /// `std.http.Reader` is a field of the exchange, so the address of one
    /// gives the address of the next.
    fn chunkGuardExchange(io_reader: *std.Io.Reader) *Exchange {
        const reader: *std.http.Reader = @alignCast(@fieldParentPtr("interface", io_reader));
        return @alignCast(@fieldParentPtr("http_reader", reader));
    }

    /// Refuses a chunk size that `std` must not be given.
    ///
    /// **This reads the size field and consumes nothing.** `std` reads the
    /// same octets again right after, with its own parser, from the same
    /// place. That is why this runs `std.http.ChunkParser` and not a
    /// second grammar of its own: the two cannot answer differently about
    /// where the size field ends or what value it holds, because they are
    /// the same code over the same octets.
    ///
    /// **It keeps no framing state either.** `std.http.Reader.state` says
    /// where the transfer stands, and this reads it. A state of `head`,
    /// `n` or `rn` means the next call parses a size field, after zero,
    /// one or two octets of the CRLF that closed the chunk before it. Any
    /// other state means the call carries data of a chunk already open, so
    /// there is no size to bound. That is the whole of it, and it is read
    /// from `std` rather than tracked here, so it cannot drift.
    ///
    /// The guard stops at the end of the size field and never reads the
    /// chunk extensions behind it, so a long extension costs nothing and
    /// is left to `std` as before.
    ///
    /// A size field this cannot reach the end of, because the peer stopped
    /// sending or wrote something that is not a size field, is left alone.
    /// `std` reads the same octets and reports what it finds:
    /// `HttpChunkTruncated` for the first, `HttpChunkInvalid` for the
    /// second. Recovery is not silent, it is simply not this function's.
    ///
    /// **It holds the size grammar as well as the size bound, because
    /// `std.http.ChunkParser` reads a wider grammar than RFC 9112 writes.**
    /// Section 7.1 says `chunk-size` is `1*HEXDIG`, and the parser folds
    /// the whole alphabet into the value:
    ///
    /// ```zig
    /// 'A'...'Z' => |b| b - 'A' + 10,
    /// 'a'...'z' => |b| b - 'a' + 10,
    /// ```
    ///
    /// so `g` through `z` read as the values 16 through 35. Every octet
    /// that is not a hexadecimal digit and is not the end of the line then
    /// starts a chunk extension, so a size field that begins with one holds
    /// no digit at all and reads as zero, which is the last chunk.
    ///
    /// Two rules close both, and both are refusals:
    ///
    /// - An octet the parser folds into the value must be a hexadecimal
    ///   digit.
    /// - The size field must hold at least one such digit.
    ///
    /// **Measured against curl 8.21.0 on the same loopback listener**, with
    /// a chunk of `ABCDE` and a terminating chunk behind it, or 32 octets
    /// of `A` for the `1g` row:
    ///
    /// ```text
    /// size field   curl                        zurl before   zurl now
    /// 1g           exit 56, wrote 1 octet      wrote 32      refused
    /// 0x5          exit 8,  wrote nothing      wrote 12      refused
    /// (space)5     exit 56, wrote nothing      exit 0, none  refused
    /// +5           exit 56, wrote nothing      exit 0, none  refused
    /// 5;ext=1      exit 0,  wrote ABCDE        wrote ABCDE   wrote ABCDE
    /// 5(space)     exit 0,  wrote ABCDE        wrote ABCDE   wrote ABCDE
    /// 05           exit 0,  wrote ABCDE        wrote ABCDE   wrote ABCDE
    /// ```
    ///
    /// The three rows at the bottom are the legal shapes, and they are
    /// untouched: a chunk extension starts at the first octet the parser
    /// does not fold, so `;` and a space both leave the value alone.
    ///
    /// **curl accepts `5g` as five and this refuses it.** That is the one
    /// row where this is stricter than curl, and it is the safe direction:
    /// `5g` carries no `;`, so RFC 9112 does not call the `g` an extension,
    /// and curl reads the same field as 5 where `std` reads it as 96. A
    /// client that answers a third way from every parser in the path is the
    /// shape this whole guard exists to stop, and refusing is the answer
    /// that cannot frame a body where no one else frames it.
    fn guardChunkSize(self: *Exchange) std.Io.Reader.Error!void {
        const remaining = switch (self.http_reader.state) {
            .body_remaining_chunk_len => |value| value,
            else => return,
        };
        // How many octets of the CRLF that closed the chunk before stand
        // in front of the size field. `std` tosses them and then starts a
        // parser, so the guard steps over them and starts the same parser.
        const skip: usize = switch (remaining) {
            .head => 0,
            .n => 1,
            .rn => 2,
            // Data of a chunk that is open. No size field is parsed in
            // this call.
            _ => return,
        };

        const in = self.http_reader.in;
        var parser: std.http.ChunkParser = .init;
        var offset: usize = skip;
        var digits: usize = 0;
        while (parser.state == .head_size) {
            const buffered = in.buffered();
            if (offset >= buffered.len) {
                // One octet at a time is all this asks for, and `offset`
                // stops at `chunk_size_digits_max + 3`, so the buffer is
                // never near full here and `fillMore` always has room.
                in.fillMore() catch return;
                continue;
            }
            // Fed one octet at a time because the count of octets in the
            // size field is itself a bound. A longer feed would tell how
            // many octets were read and not how many of them were size.
            const byte = buffered[offset];
            _ = parser.feed(buffered[offset..][0..1]);
            offset += 1;
            if (parser.state != .head_size) break;
            // The parser stayed on the size field, so it folded this octet
            // into the value. RFC 9112 section 7.1 says a chunk size is
            // `1*HEXDIG`, so an octet that is not a hexadecimal digit must
            // never reach the value. The doc comment above holds the
            // measurement.
            if (!std.ascii.isHex(byte)) return error.ReadFailed;
            digits += 1;
            // Both bounds are tested inside the loop, so the guard answers
            // from the octets it has already read and never waits for the
            // end of a size field that is refused either way.
            if (digits > chunk_size_digits_max) return error.ReadFailed;
            if (parser.chunk_len > chunk_size_max) return error.ReadFailed;
        }
        // **A size field with no hexadecimal digit at all is not a size
        // field.** `std` reads the first octet that is not a digit as the
        // start of a chunk extension, so ` 5`, `+5` and `;x` each leave the
        // value at zero, which `std` then reads as the last chunk. The body
        // ends there, the octets behind it stay on the connection, and the
        // transfer reports success. The doc comment above holds the
        // measurement.
        if (digits == 0) return error.ReadFailed;
        // `invalid` is `std`'s answer to the same octets, so it is left to
        // `std`. Every other end of the loop has the value.
        if (parser.state == .invalid) return;
        if (parser.chunk_len > chunk_size_max) return error.ReadFailed;
    }

    /// Reads the transfer framing to its end after the content decoding
    /// ended.
    ///
    /// **A content decoder ends at the end of its own stream, and not at
    /// the end of the transfer.** `gzip` and `deflate` stop at the last
    /// octet of the compressed member and ask the transfer reader for
    /// nothing more, so a chunked answer keeps its terminating chunk and
    /// its trailers on the socket. `std.http.Reader.state` then stays away
    /// from `ready` and `reusable` closes a connection the peer is ready
    /// to serve again. `h2.Exchange.finishFraming` closes the same defect
    /// over `END_STREAM`.
    ///
    /// **This reads and never discards.** One peek is enough: the transfer
    /// reader either reaches its own end, which is what moves the state to
    /// `ready`, or it answers an octet the content decoding did not ask
    /// for. Such an octet is left where it is, so the state stays away
    /// from `ready` and the connection is closed rather than pooled.
    ///
    /// It runs only where the content stream ended, so a body a caller
    /// abandoned still closes its connection.
    fn finishFraming(self: *Exchange) void {
        if (self.framing_finished) return;
        self.framing_finished = true;
        const transfer = &self.http_reader.interface;
        // A body read with no content decoding in front of it is read
        // through the transfer reader itself, so its end is already the
        // end of the transfer. See `std.http.Decompress.init`, which hands
        // the transfer reader back for `identity`.
        if (self.body_source == transfer) return;
        switch (self.http_reader.state) {
            .body_remaining_content_length, .body_remaining_chunk_len => {},
            // `body_none` is a body the peer ends by closing the socket,
            // so there is no next response to reach. The rest are already
            // at the end of a transfer, or at a failure.
            .ready, .received_head, .body_none, .closing => return,
        }
        // Recovery is never silent, and there is nothing to recover here:
        // a fault leaves `zurl_net.Connection` holding it, and `reusable`
        // reads it back.
        _ = transfer.peekByte() catch return;
    }

    /// Reads part of the body, and stops waiting after `read_timeout` with
    /// no octet arriving.
    ///
    /// **The deadline is on one call and never on the transfer.** One call
    /// ends as soon as it has an octet for the caller, so a download over
    /// a slow link starts the clock again on every call and runs for as
    /// long as it needs. Only a call that delivers nothing at all reaches
    /// the deadline. That is the same rule `zurl_net.bounded.readToEnd`
    /// keeps for the other protocols, and it is what `--speed-time`
    /// describes.
    ///
    /// Measured against curl 8.21.0 on a loopback listener, with
    /// `--speed-limit 100 --speed-time 2`: a body of 4096 octets each
    /// second ran to its end and exited 0 after 11.09 seconds, while a
    /// body of one octet every 3 seconds exited 28 after 2.004 seconds.
    /// The bound below keeps the first of those alive.
    ///
    /// **A whole call is raced, the framing at the end of it included.**
    /// `finishFraming` reads the transfer framing that a content decoder
    /// left behind, which is another wait on the peer, so it sits inside
    /// the raced task rather than after it.
    fn bodyStream(
        io_reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *Exchange = @alignCast(@fieldParentPtr("body", io_reader));
        return switch (raceRead(
            self.io,
            self.read_timeout,
            &self.read_bounds_dropped,
            std.Io.Reader.StreamError!usize,
            streamTask,
            .{ self, writer, limit },
        )) {
            .done => |result| result,
            .timed_out => self.reportReadTimeout(),
            // **A cancel needs no flag of its own.** Something outside
            // this transfer stopped it, and a read can only be canceled
            // while it is waiting, which means the framing is part way
            // through a body. `reusable` already answers false for every
            // such state, so the connection is closed either way, and
            // naming it a timeout would be a lie about who stopped it.
            .canceled => error.ReadFailed,
        };
    }

    fn streamTask(
        self: *Exchange,
        writer: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        return self.body_source.stream(writer, limit) catch |err| switch (err) {
            error.EndOfStream => {
                self.finishFraming();
                return self.endOfBody();
            },
            else => |other| other,
        };
    }

    /// The `discard` half of `bodyStream`, under the same deadline.
    ///
    /// A caller that throws a body away still waits on the peer for every
    /// octet of it, so an unbounded discard holds the transfer exactly as
    /// an unbounded read does.
    fn bodyDiscard(io_reader: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        const self: *Exchange = @alignCast(@fieldParentPtr("body", io_reader));
        return switch (raceRead(
            self.io,
            self.read_timeout,
            &self.read_bounds_dropped,
            std.Io.Reader.Error!usize,
            discardTask,
            .{ self, limit },
        )) {
            .done => |result| result,
            .timed_out => self.reportReadTimeout(),
            .canceled => error.ReadFailed,
        };
    }

    fn discardTask(self: *Exchange, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        return self.body_source.discard(limit) catch |err| switch (err) {
            error.EndOfStream => {
                self.finishFraming();
                return self.endOfBody();
            },
            else => |other| other,
        };
    }

    /// Records a read that reached its deadline and names the one fault a
    /// `std.Io.Reader` can report.
    ///
    /// The flag is what `reusable` reads, so the connection is closed
    /// rather than handed to the next request, and what `check` turns into
    /// `error.OperationTimedOut` for the caller.
    fn reportReadTimeout(self: *Exchange) error{ReadFailed} {
        self.read_timed_out = true;
        return error.ReadFailed;
    }

    /// Answers the end of the transfer.
    ///
    /// `std.http.Reader` counts down the bytes a content-length body still
    /// owes. A count above zero here means the peer stopped early, so the
    /// stream ends with a failure and `check` names it. The count is of
    /// bytes on the wire, so this stays correct when the body arrives
    /// compressed.
    ///
    /// A chunked transfer is not checked here. It already reports a cut
    /// stream as `error.ReadFailed` through `HttpChunkTruncated`.
    fn endOfBody(self: *Exchange) std.Io.Reader.Error!usize {
        switch (self.http_reader.state) {
            .body_remaining_content_length => |remaining| if (remaining > 0) {
                self.body_partial = true;
                return error.ReadFailed;
            },
            else => {},
        }
        return error.EndOfStream;
    }

    fn checkImpl(ptr: *anyopaque) engine.BodyError!void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        // **The deadline is reported before the short body.** A transfer
        // the peer stopped feeding is also a transfer that never reached
        // its announced length, so both flags can stand together, and the
        // one that says why is this one. A caller told `PartialFile` looks
        // for a truncated file; a caller told `OperationTimedOut` looks at
        // the peer that went quiet.
        if (self.read_timed_out) return error.OperationTimedOut;
        if (self.body_partial) return error.PartialFile;
    }

    /// Whether the connection may serve another request.
    ///
    /// **Every one of these is a rule that keeps one response out of the
    /// next one.** A false answer costs a dial. A wrong true answer hands
    /// the next request the tail of this response, or a socket that is
    /// already broken.
    ///
    /// - The peer must have said it will read another request.
    ///   `peerKeepsAlive` covers `connection: close` and the HTTP/1.0
    ///   default of close. A request that got no head at all leaves
    ///   `keep_alive` false, so a connection that failed is never kept.
    /// - **The body must be at its end.** `std.http.Reader.state` is
    ///   `ready` only after a content-length body was read to its
    ///   announced length, or a chunked body reached its last chunk and
    ///   its trailers. A caller that abandoned a body early leaves the
    ///   state on `body_remaining_content_length`, and this answers false:
    ///   that is the rule that stops unread bytes reaching the next
    ///   request. `body_none`, which is a body the peer delimits by
    ///   closing the socket, answers false as well, because there is no
    ///   next request on a socket that ends the body.
    ///   A response with no body byte is the one shape that is ready
    ///   without a read. See `body_empty`, which is the ordinary shape of
    ///   a redirect hop.
    ///   A body that arrived compressed reaches `ready` through
    ///   `finishFraming`: a content decoder ends at the end of its own
    ///   stream, and the transfer has framing after it.
    /// - A short transfer is not an end. `body_partial` says the peer
    ///   stopped before its announced length, so the framing is already
    ///   wrong.
    /// - **A read that reached its deadline is not an end either.**
    ///   `read_timed_out` says the peer stopped writing at a place nothing
    ///   here knows, and the raced read was canceled part way through, so
    ///   whatever the peer writes next would arrive in front of the next
    ///   request. The state alone does not cover it: a deadline reached
    ///   while the framing already sat at `ready` would otherwise hand a
    ///   half-canceled socket to the next request.
    /// - A read or a write that failed leaves the stream at a place
    ///   nothing here knows, and a TLS session that reported a fault is
    ///   over. `zurl_net.Connection` keeps both faults, so this reads them
    ///   rather than guess.
    fn reusable(self: *const Exchange) bool {
        if (!self.keep_alive) return false;
        if (self.read_timed_out) return false;
        if (self.body_partial) return false;
        if (self.pooled.connection.readError() != null) return false;
        if (self.pooled.connection.writeError() != null) return false;
        return switch (self.http_reader.state) {
            .ready => true,
            .received_head => self.body_empty,
            .body_none, .body_remaining_content_length, .body_remaining_chunk_len, .closing => false,
        };
    }

    fn closeImpl(ptr: *anyopaque) void {
        const self: *Exchange = @ptrCast(@alignCast(ptr));
        // The connection goes first, either back to the pool or to the
        // socket close. It is the last reader of every buffer this
        // exchange owns.
        //
        // Nothing is flushed here: a caller that stops reading a body
        // mid-transfer is closing on purpose, and `reusable` answers false
        // for exactly that case, so such a connection is closed and never
        // handed on.
        self.pool.releaseOne(self.pooled, self.reusable());
        if (self.chain_storage) |storage| self.allocator.free(storage);
        // Freed after the connection, because the decoder reading through
        // it is the connection's last reader. Null for every answer that
        // was not zstd, which is nearly all of them.
        //
        // The room on the pool goes back in the same step, so the count and
        // the memory can never drift apart. See `zstd_windows_max`.
        if (self.zstd_buffer) |buffer| {
            self.allocator.free(buffer);
            self.pool.releaseZstdWindow();
        }
        // Null for every head `std` parsed on the first try, which is
        // every head naming a coding `std` knows. See `parseRefusedHead`.
        if (self.head_scratch) |scratch| self.allocator.free(scratch);
        self.allocator.destroy(self);
    }
};

/// Sends `req` over HTTP/2 on a connection whose peer chose `h2`.
///
/// **This is the whole of the HTTP/2 wiring in this file.** It builds the
/// session on the first request of a connection, renders the one value the
/// HTTP/2 request head needs and this file owns, and hands the rest over.
/// Everything `h2.open` is given has already been through the policy above:
/// `extra_headers` is the caller's headers joined with this hop's secrets
/// by `openOnce`, which is where `engine.origin_bound_headers` is honoured,
/// and `uri` is what `requestUri` built for the HTTP/1.1 request line.
///
/// On a fault the caller's `errdefer` closes the connection, which is what
/// happens on the HTTP/1.1 path too: a connection that failed part way
/// through a request has an unknown number of octets still on it.
/// Whether the stream `sendOnH2` reads was opened by writing a request or
/// by an `Upgrade: h2c` handshake.
const H2Start = enum {
    /// This side writes the request head and the body, then reads. Every
    /// ordinary HTTP/2 request.
    fresh,
    /// The request already went out whole as HTTP/1.1 and this side only
    /// reads. RFC 7540 section 3.2, and see `h2.openUpgraded`.
    upgraded,
};

fn sendOnH2(
    engine_state: *Engine,
    pool: *Pool,
    pooled: *Pooled,
    req: engine.Request,
    uri: std.Uri,
    extra_headers: []const std.http.Header,
    answered: *bool,
    start: H2Start,
    reserved: bool,
) engine.OpenError!*engine.Exchange {
    // One session for the life of the connection. A second request on a
    // pooled connection finds the one the first request built, so the
    // preface goes out once and the HPACK tables carry over.
    const session = pooled.h2_session orelse built: {
        // The connection carries the owner's read bound from here on. See
        // `h2.Session.read_timeout`.
        const fresh = h2.Session.create(
            engine_state.allocator,
            &pooled.connection,
            engine_state.read_timeout,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.WriteFailed => return error.WriteError,
        };
        pooled.h2_session = fresh;
        break :built fresh;
    };

    // **A claim that never reaches `h2.open` goes back here.** The claim
    // holds a stream slot on the session, so one that was left behind
    // would shrink the connection by one stream for the rest of its life.
    // `openInner` spends it at its first line, so a fault after that call
    // has nothing to give back.
    var claim_spent = false;
    errdefer if (reserved and !claim_spent) session.unreserve();

    // **The `:authority` value comes from the rule that writes the `host:`
    // line.** One rule, one answer: an HTTP/2 request and an HTTP/1.1
    // request to the same url name the same origin, brackets of an IPv6
    // address included, and a default port left out of both.
    var authority_buffer: [masked_host_max + "[]:65535".len]u8 = undefined;
    var authority: std.Io.Writer = .fixed(&authority_buffer);
    writeAuthority(&authority, uri) catch return error.InvalidUrl;

    const o: h2.Open = .{
        .gpa = engine_state.allocator,
        .session = session,
        .method = req.method,
        .uri = uri,
        .authority = authority.buffered(),
        .user_agent = req.user_agent,
        // `--compressed` and nothing else, the rule `openOnce` writes.
        // `h2.requestFields` writes no field beside a caller's own.
        .accept_encoding = req.accept_encoding,
        .headers = extra_headers,
        // **An upgraded stream carries no body here.** The body went out
        // behind the HTTP/1.1 request head, before the `101`, which is
        // what curl does too: measured, `curl --http2 -d k=v
        // http://host/path` wrote a `Content-Length: 3` and the three
        // octets as HTTP/1.1. Handing the source to `h2` would send it a
        // second time, as `DATA` frames, on a stream this side has already
        // closed.
        .body = switch (start) {
            .fresh => req.body,
            .upgraded => null,
        },
        .url = req.url,
        .cookies = req.cookies,
        .log = .{ .ctx = engine_state, .record = recordH2Head, .kept = keptH2Heads },
        .peer = .{ .ctx = pool, .handle = pooled, .release = releaseH2 },
        .answered = answered,
        .body_sent = &engine_state.body_sent,
        .reserved = reserved,
    };
    claim_spent = true;
    return switch (start) {
        .fresh => h2.open(o),
        .upgraded => h2.openUpgraded(o),
    };
}

/// What one hop does about HTTP/3.
///
/// Three answers and no fourth, so every reader of `openOnce` can check
/// each one against what curl 8.21.0 does for the same command line.
const H3Choice = enum {
    /// This hop goes out over TCP. Every hop that asked for no HTTP/3, and
    /// every hop that asked for it and cannot have it without a refusal.
    tcp,
    /// This hop opens a QUIC connection first.
    quic,
    /// This hop is refused, because `--http3-only` names a url with no
    /// TLS on it.
    refuse_cleartext,
};

/// Whether this hop opens QUIC, goes out over TCP, or is refused.
///
/// A function and not a few lines inside `openOnce`, so a test can name
/// every input and read the answer back. Each rule below is measured
/// against curl 8.21.0.
///
/// - **No HTTP/3 flag, no QUIC.** HTTP/3 is never the default. curl
///   requires the flag for the same reason: QUIC needs UDP 443 reachable
///   end to end, and many networks pass TCP and drop UDP. A client that
///   reached for QUIC first would turn a working transfer into a timeout
///   on those networks. Measured: `curl https://cloudflare.com/`, a host
///   that does speak HTTP/3, reported `%{http_version} 2`.
/// - **A hop through a proxy never opens QUIC.** This build speaks
///   HTTP/1.1 to a proxy, and `--proxy-http3` is refused by name. Measured:
///   `curl --http3-only -x http://127.0.0.1:1 https://example.com/` dialed
///   the proxy over TCP and exited 7 for the proxy, so curl asks the proxy
///   for no QUIC either.
/// - **A cleartext url never opens QUIC.** RFC 9114 section 3.1 puts
///   HTTP/3 on TLS, and an `http` url has none. Measured: `curl --http3
///   http://example.com/` answered on HTTP/1.1 and exited 0, and
///   `curl --http3-only http://example.com/` wrote
///   `HTTP/3 requested for non-HTTPS URL` and exited 3. So the two flags
///   part here: one falls back and one refuses.
fn h3Choice(req: engine.Request, protocol: Protocol, route: Route) H3Choice {
    switch (req.http_version) {
        .any, .http_1_1, .http_2, .prior_knowledge => return .tcp,
        .http_3, .http_3_only => {},
    }
    if (route.proxy != null) return .tcp;
    if (protocol == .tls) return .quic;
    return switch (req.http_version) {
        .http_3_only => .refuse_cleartext,
        else => .tcp,
    };
}

/// Whether a QUIC hop that met `err` may go out over TCP instead.
///
/// **`--http3` falls back when there is no HTTP/3 there, and for no other
/// reason.** A fault that would happen again over TCP, or that is not about
/// the peer at all, is the answer to the transfer and must be reported.
/// Three of them, and each one earns its place:
///
/// - **`Canceled`.** The caller stopped this transfer. `-m`/`--max-time`
///   is the one that does it, and a fallback would answer a bound that had
///   already passed with a whole transfer over TCP. Measured before this
///   rule existed: `--http3 --max-time 0.05` against a 1.3 MB page exited 0
///   with the whole body, because the cancelled QUIC hop fell back and the
///   TCP hop finished.
/// - **`PeerFailedVerification`.** The peer's certificate is the peer's
///   certificate, whichever transport carried it, so the TCP hop would
///   refuse the same chain and the user would wait twice for one answer.
///   curl reports it from the QUIC hop too: measured,
///   `curl --http3 --cacert <a root that issued nothing here>` exited 60.
/// - **`OutOfMemory`.** This process has no memory. A second attempt needs
///   more of it.
///
/// Every other fault means the peer did not speak HTTP/3 on UDP, which is
/// exactly what the fallback is for.
fn h3Fallback(err: engine.OpenError) bool {
    return switch (err) {
        error.Canceled,
        error.PeerFailedVerification,
        error.OutOfMemory,
        => false,
        else => true,
    };
}

/// The sentence a `--http3-only` hop on a cleartext url is refused with.
///
/// curl writes `HTTP/3 requested for non-HTTPS URL` for the same command
/// line, measured, and exits 3. This says the same thing and names the
/// flag, which is what every other zurl refusal does.
const http3_cleartext_message =
    "--http3-only asks for HTTP/3, which runs on TLS alone, and this url names no TLS";

/// How many resolved addresses one QUIC hop tries before it gives up.
///
/// A name can answer with many addresses, and `std.Io.net.HostName.connect`
/// tries each of them for a TCP dial. This is the same rule with a bound
/// on it, because a QUIC attempt costs a whole handshake and not one
/// `connect` call: a name with a long address list would otherwise hold
/// `--http3` for the handshake timeout once for each address before the
/// hop falls back to TCP.
const h3_addresses_max: usize = 4;

/// How many lookup results one QUIC hop reads.
///
/// `std.Io.net.HostName.lookup` promises not to block when the queue holds
/// at least 16, so this is that promise with room to spare. A name that
/// answers with more addresses than this has the rest dropped, which
/// `h3_addresses_max` would have dropped anyway.
const h3_lookup_results_max: usize = 32;

/// Sends `req` over HTTP/3, on a QUIC connection this call opens.
///
/// **This is the whole of the HTTP/3 wiring in this file**, and it is the
/// shape `sendOnH2` has. Everything `h3.open` is given has already been
/// through the policy in `openOnce`: `extra_headers` is the caller's
/// headers joined with this hop's secrets, which is where
/// `engine.origin_bound_headers` is honoured, and `uri` is what
/// `requestUri` built for the HTTP/1.1 request line. So a redirect over
/// HTTP/3 withholds the same credential an HTTP/1.1 redirect withholds,
/// and neither engine knows the rule.
///
/// **One transfer opens one QUIC connection and closes it.** There is no
/// pool here, because a pooled QUIC connection needs an idle timer and a
/// path check this build has not written. A redirect chain therefore hand
/// shakes again at each hop. `releaseH3` is what closes the connection when
/// the exchange ends.
///
/// On a fault nothing is returned and the connection is already closed.
fn sendOnH3(
    engine_state: *Engine,
    req: engine.Request,
    uri: std.Uri,
    extra_headers: []const std.http.Header,
    host: zurl_net.tcp.Host,
    route: Route,
    answered: *bool,
) engine.OpenError!*engine.Exchange {
    answered.* = false;

    // **The `:authority` value comes from the rule that writes the `host:`
    // line**, the same call `sendOnH2` makes. One rule, one answer: a
    // request to the same url names the same origin over all three
    // protocols.
    var authority_buffer: [masked_host_max + "[]:65535".len]u8 = undefined;
    var authority: std.Io.Writer = .fixed(&authority_buffer);
    writeAuthority(&authority, uri) catch return error.InvalidUrl;

    const session = try connectH3(engine_state, req, host, route);
    // Closed here on every path that does not hand it to an exchange. A
    // QUIC connection that failed part way through a request has an
    // unknown amount of state on it, so it can never serve another.
    errdefer session.deinit();

    const o: h3.Open = .{
        .gpa = engine_state.allocator,
        .session = session,
        .method = req.method,
        .uri = uri,
        .authority = authority.buffered(),
        .user_agent = req.user_agent,
        // `--compressed` and nothing else, the rule `openOnce` writes.
        .accept_encoding = req.accept_encoding,
        .headers = extra_headers,
        .body = req.body,
        .url = req.url,
        .cookies = req.cookies,
        .log = .{ .ctx = engine_state, .record = recordH3Head, .kept = keptH3Heads },
        // The session is its own handle, because there is no pool entry to
        // point at. `releaseH3` closes it.
        .peer = .{ .ctx = engine_state, .handle = session, .release = releaseH3 },
        .answered = answered,
        .body_sent = &engine_state.body_sent,
    };
    return h3.open(o);
}

/// Opens one QUIC connection to the peer this hop names.
///
/// **The certificate rule is the one `tlsSetup` writes, said again for a
/// transport that takes another type.** `quic.Trust` has the same three
/// arms `zurl_net.Connection.TrustCheck` has, and both reach the vendored
/// client's own chain walk, which is one function for TCP and QUIC alike.
/// `req.insecure` is the only input that turns either half off, and it is
/// read here exactly once, the way `tlsSetup` reads it exactly once.
///
/// **The name checked is the url's own host, and never the dial target.**
/// `--resolve` and `--connect-to` move `host` and move nothing else, so a
/// peer at the moved address must still hold a certificate for the name
/// the user typed. That is the same rule the TCP path holds, and without
/// it the flag would turn verification off without `-k`.
fn connectH3(
    engine_state: *Engine,
    req: engine.Request,
    host: zurl_net.tcp.Host,
    route: Route,
) engine.OpenError!*h3.Session {
    var buffer: [h3_lookup_results_max]std.Io.net.IpAddress = undefined;
    const addresses = try resolveForH3(engine_state, host, route.port, &buffer);

    const options: h3.Session.ConnectOptions = .{
        .io = engine_state.io,
        // Filled for each address below.
        .address = addresses[0],
        .host = req.url.host,
        .verify_host = !req.insecure,
        .trust = if (req.insecure) .none else .{ .bundle = .{
            .lock = &engine_state.ca_bundle_lock,
            .bundle = &engine_state.ca_bundle,
        } },
        .handshake_timeout_ms = h3HandshakeMs(engine_state),
        // **The bound on one wait after the handshake.** A QUIC peer that
        // completed the handshake and then went quiet met nothing at all
        // until this was wired: `--connect-timeout` covers the handshake
        // and stops there. See `h3.Session.read_timeout`.
        .read_timeout = engine_state.read_timeout,
        // **What `-m`/`--max-time` needs over QUIC.** The caller's own
        // cancel does not reach a datagram wait, so the caller hands the
        // flag down instead. See `quic.Connection.checkCancel`.
        .stop = req.stop,
    };

    var last: engine.OpenError = error.CouldNotConnect;
    for (addresses) |address| {
        var attempt = options;
        attempt.address = address;
        // **The sentence of this attempt, and of no earlier one.** Written
        // fresh for each address, so a hop that reports a fault reports the
        // reason the last attempt gave and not the reason the first did.
        // Four different certificate faults are one error name and one exit
        // code, so only the sentence says which check refused the peer.
        var cause: ?[]const u8 = null;
        attempt.cause_out = &cause;
        if (h3.Session.connect(engine_state.allocator, attempt)) |session| {
            // The hop succeeded, so no earlier attempt's sentence may stay
            // behind to attach to a later fault.
            engine_state.open_cause = null;
            return session;
        } else |fault| {
            const mapped = h3.openError(fault);
            engine_state.open_cause = cause;
            // **A peer that answered and failed verification ends the
            // attempt.** Every address of one name holds the same
            // certificate, so trying the next one asks the same question
            // again and gets the same answer. Reporting the first refusal
            // is what keeps `--http3-only` at exit 60 rather than exit 7.
            if (mapped == error.PeerFailedVerification) return mapped;
            if (mapped == error.OutOfMemory) return mapped;
            last = mapped;
        }
    }
    return last;
}

/// The bound on one QUIC handshake, in milliseconds.
///
/// `--connect-timeout` is the user's own bound on reaching a peer, and a
/// QUIC handshake is how this transport reaches one, so the flag covers it
/// the way it covers a TCP dial and a TLS handshake together. A transfer
/// that named no bound gets the `quic` default.
fn h3HandshakeMs(engine_state: *const Engine) i64 {
    return switch (engine_state.connect_timeout) {
        .none => h3_handshake_default_ms,
        .duration => |d| @max(1, d.raw.toMilliseconds()),
        // A deadline is not a length, and the length is what QUIC takes.
        // Nothing in this build sets one, so this is the safe default and
        // not a case that runs.
        .deadline => h3_handshake_default_ms,
    };
}

/// How long one QUIC handshake may take when the caller named no
/// `--connect-timeout`, in milliseconds.
///
/// Shorter than the `quic` default on purpose. `--http3` falls back to TCP
/// when QUIC does not answer, and a user waits the whole of this bound
/// before that fallback starts on a network that drops UDP with no reply.
/// curl gave up on `https://example.com/` in 119 milliseconds, because that
/// peer refuses the datagram; a peer that drops it silently costs this
/// number instead.
const h3_handshake_default_ms: i64 = 10_000;

/// The addresses one QUIC hop may try, in the order it tries them.
///
/// An address in the url is used as it stands and asks no resolver, which
/// is what `zurl_net.tcp.dial` does for the same host. A name goes to
/// `std.Io.net.HostName.lookup`, which is the resolver the TCP path uses
/// inside `std.Io.net.HostName.connect`. **So both transports reach one
/// resolver and a `/etc/hosts` entry answers for either.**
///
/// The result is bounded twice: by the caller's buffer, and by
/// `h3_addresses_max`.
fn resolveForH3(
    engine_state: *Engine,
    host: zurl_net.tcp.Host,
    port: u16,
    buffer: []std.Io.net.IpAddress,
) engine.OpenError![]const std.Io.net.IpAddress {
    std.debug.assert(buffer.len >= h3_addresses_max);

    switch (host) {
        .address => |address| {
            // The port inside a parsed address is zero. The port to reach
            // is the one this hop named.
            buffer[0] = address;
            buffer[0].setPort(port);
            return buffer[0..1];
        },
        .name => |name| {
            var results: [h3_lookup_results_max]std.Io.net.HostName.LookupResult = undefined;
            var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results);
            // `lookup` closes the queue before it returns, and it promises
            // not to block for a queue this size, so the drain below reads
            // what it left and stops at the close.
            // **A cancel is not a name that did not resolve.** Every
            // lookup fault but one means the resolver had no address, and
            // a hop under `--http3` may then go out over TCP. A cancel
            // means the caller stopped this transfer, and answering that
            // with a whole transfer over TCP would be a bound that never
            // fires. See `h3Fallback`.
            name.lookup(engine_state.io, &queue, .{ .port = port }) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return error.CouldNotResolveHost,
            };

            var found: usize = 0;
            while (found < h3_addresses_max) {
                // The queue is closed once `lookup` has put everything it
                // found, and a closed queue ends this walk. A cancel ends
                // the transfer instead, for the reason above.
                const result = queue.getOne(engine_state.io) catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    error.Closed => break,
                };
                switch (result) {
                    // The canonical name answers a question this hop does
                    // not ask: the name a certificate is checked against is
                    // the url's own, and never one a resolver returned.
                    .canonical_name => {},
                    .address => |address| {
                        buffer[found] = address;
                        buffer[found].setPort(port);
                        found += 1;
                    },
                }
            }
            if (found == 0) return error.CouldNotResolveHost;
            return buffer[0..found];
        },
    }
}

/// Records one HTTP/3 response head in this engine's head log, which is the
/// same log every HTTP/1.1 hop and every HTTP/2 hop writes into. See
/// `Engine.head_log`.
fn recordH3Head(ctx: *anyopaque, head: []const u8) std.mem.Allocator.Error!void {
    const engine_state: *Engine = @ptrCast(@alignCast(ctx));
    return engine_state.logHead(head);
}

fn keptH3Heads(ctx: *anyopaque) h3.HeadLog.Kept {
    const engine_state: *Engine = @ptrCast(@alignCast(ctx));
    const logged = engine_state.loggedHeads();
    return .{
        .all = logged.all,
        .final = logged.final,
        .dropped = engine_state.head_log_dropped,
    };
}

/// Closes the QUIC connection one HTTP/3 exchange ran on.
///
/// **`keep` is always false here and the connection is always closed.**
/// This build pools no QUIC connection, so there is nowhere to keep one.
/// The parameter stays because the seam is the one `h2` reports through,
/// and a seam with two shapes would be two seams.
fn releaseH3(ctx: *anyopaque, handle: *anyopaque, keep: bool) void {
    _ = ctx;
    std.debug.assert(!keep);
    const session: *h3.Session = @ptrCast(@alignCast(handle));
    session.deinit();
}

/// The `HTTP2-Settings` value this request offers, or null when it makes no
/// `Upgrade: h2c` offer.
///
/// **The offer goes out on a cleartext hop under `--http2`, and nowhere
/// else.** Four rules, and each of them is what curl 8.21.0 does, measured
/// on a loopback listener:
///
/// - `--http2` on an `http` url offers it. curl wrote `Upgrade: h2c`,
///   `HTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA`, and
///   `Connection: Upgrade, HTTP2-Settings`.
/// - No version flag on an `http` url does not. curl wrote a plain request
///   with none of the three fields.
/// - An `https` url does not. ALPN already carried the question and the
///   peer already answered it, so a hop that reaches this function over
///   TLS chose `http/1.1` and asking again would be asking a peer that has
///   said no.
/// - `--http2-prior-knowledge` does not reach here at all: `sendOn` sends
///   its preface without writing one HTTP/1.1 octet.
///
/// A request with a body still offers it, which is what curl does:
/// measured, `curl --http2 -d k=v http://host/path` carried the three
/// fields, a `Content-Length: 3`, and the body.
///
/// **RFC 9113 removed this handshake and curl still sends it.** Section 3.1
/// of RFC 9113 dropped the `Upgrade` mechanism RFC 7540 section 3.2
/// defined, so almost no server answers `101` any more, and the ordinary
/// outcome is an HTTP/1.1 answer that the caller reads as usual. zurl
/// sends it because curl sends it, and honours a `101` because sending an
/// offer this build could not honour would be worse than sending none.
fn upgradeOffer(req: engine.Request, pooled: *Pooled, out: []u8) ?[]const u8 {
    if (req.http_version != .http_2) return null;
    if (pooled.connection.isSecure()) return null;
    return h2.settingsUpgradeText(out);
}

/// The `Upgrade` field of a response head, or null when it carried none.
fn upgradeField(head: std.http.Client.Response.Head) ?[]const u8 {
    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Upgrade")) return header.value;
    }
    return null;
}

/// Records one HTTP/2 response head in this engine's head log, which is the
/// same log every HTTP/1.1 hop writes into. See `Engine.head_log`.
fn recordH2Head(ctx: *anyopaque, head: []const u8) std.mem.Allocator.Error!void {
    const engine_state: *Engine = @ptrCast(@alignCast(ctx));
    return engine_state.logHead(head);
}

fn keptH2Heads(ctx: *anyopaque) h2.HeadLog.Kept {
    const engine_state: *Engine = @ptrCast(@alignCast(ctx));
    const logged = engine_state.loggedHeads();
    return .{
        .all = logged.all,
        .final = logged.final,
        .dropped = engine_state.head_log_dropped,
    };
}

/// Hands an HTTP/2 connection back to the pool, or closes it.
///
/// The same two calls `Exchange.closeImpl` makes for an HTTP/1.1 exchange,
/// so one pool serves both protocols and one rule ends a connection.
fn releaseH2(ctx: *anyopaque, handle: *anyopaque, keep: bool) void {
    const pool: *Pool = @ptrCast(@alignCast(ctx));
    const pooled: *Pooled = @ptrCast(@alignCast(handle));
    pool.releaseOne(pooled, keep);
}

/// Whether the peer will read another request on this connection.
///
/// `std.http.Client.Response.Head.parse` answers most of this in
/// `keep_alive`: HTTP/1.0 defaults to close, HTTP/1.1 defaults to
/// keep-alive, and a `connection:` value of `close` turns it off either
/// way. It compares the whole value against `close`, so it reads
/// `connection: keep-alive, close` as keep-alive. That is a list of
/// tokens, and one of them is `close`.
///
/// So the tokens are read here as well. The cost of keeping a connection
/// the peer meant to drop is one retry, and `openOnce` pays it silently,
/// which is exactly why the miss must not be left to that path to cover: a
/// bound that never fires is worse than no bound.
fn peerKeepsAlive(head: std.http.Client.Response.Head) bool {
    if (!head.keep_alive) return false;
    var headers = head.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |token| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "close")) return false;
        }
    }
    return true;
}

test "an engine reports no TCP_NODELAY fault until a connection has one" {
    // The accessor must answer null on an ordinary run. `zurl.Client`
    // writes whatever this hands back into `zurl_core.Diagnostics`, so a
    // sentence here that describes nothing would attach to every transfer.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    try testing.expectEqual(@as(?[]const u8, null), http_engine.noDelayCause());

    // A dial that could not set the option writes the fault into the
    // field the setup task points at. The accessor turns it into the
    // sentence a caller reports.
    http_engine.no_delay_error = error.OperationUnsupported;
    const why = http_engine.noDelayCause().?;
    try testing.expect(std.mem.indexOf(u8, why, "TCP_NODELAY") != null);
}

test "a transfer over loopback leaves no TCP_NODELAY fault behind" {
    // The end to end check for the option, over the loopback fixture and
    // no network. A request that completes must leave the record empty,
    // because the option takes on every platform this suite runs on.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    try testing.expectEqual(@as(?[]const u8, null), http_engine.noDelayCause());
}

test "a certificate that does not verify keeps exit 60 and the check that refused it" {
    // This is what the whole engine swap is for. Through `std.http.Client`
    // every one of these arrived as `error.TlsInitializationFailed`, which
    // reached a user as exit 35 with no cause at all. Each one now keeps
    // `PeerFailedVerification`, which is exit 60, and a sentence naming
    // the check that refused the peer.
    //
    // No socket and no peer: `mapSetupError` is the join this test pins,
    // and a real certificate needs a TLS server that neither `std` nor
    // `zurl-tls` has. The badssl transcript in the report covers the rest.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const expired = mapSetupError(&http_engine, error.CertificateExpired);
    const expired_why = http_engine.cause().?;
    try testing.expectEqual(engine.OpenError.PeerFailedVerification, expired);

    const mismatch = mapSetupError(&http_engine, error.CertificateHostMismatch);
    const mismatch_why = http_engine.cause().?;
    try testing.expectEqual(engine.OpenError.PeerFailedVerification, mismatch);

    const untrusted = mapSetupError(&http_engine, error.TlsCertificateNotVerified);
    const untrusted_why = http_engine.cause().?;
    try testing.expectEqual(engine.OpenError.PeerFailedVerification, untrusted);

    // The exit code is the same for all three, so only the sentence tells
    // a user which check refused the peer. Two sentences that matched
    // would leave that user with no way to tell them apart.
    try testing.expect(!std.mem.eql(u8, expired_why, mismatch_why));
    try testing.expect(!std.mem.eql(u8, expired_why, untrusted_why));
    try testing.expect(!std.mem.eql(u8, mismatch_why, untrusted_why));
}

test "a handshake fault and a dial fault do not collapse into one name" {
    // The other half of the same defect. A peer that could not agree on a
    // handshake is exit 35, a peer that never answered is exit 7, and a
    // name that did not resolve is exit 6. curl reads those three numbers
    // differently, so this engine must not fold any of them together.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    try testing.expectEqual(
        engine.OpenError.SslConnectError,
        mapSetupError(&http_engine, error.TlsAlert),
    );
    try testing.expectEqual(
        engine.OpenError.CouldNotConnect,
        mapSetupError(&http_engine, error.CouldNotConnect),
    );
    try testing.expectEqual(
        engine.OpenError.CouldNotResolveHost,
        mapSetupError(&http_engine, error.CouldNotResolveHost),
    );
    try testing.expectEqual(
        engine.OpenError.OperationTimedOut,
        mapSetupError(&http_engine, error.OperationTimedOut),
    );
    // A cancel from outside the transfer is not a connection fault.
    try testing.expectEqual(
        engine.OpenError.Canceled,
        mapSetupError(&http_engine, error.Canceled),
    );
}

test "an open clears the cause an earlier open left behind" {
    // A sentence kept from an earlier transfer would attach to whatever
    // this one fails with, and say the wrong thing with full confidence.
    // Port 1 is closed on loopback, so this open fails at the connect,
    // which is a fault that carries no cause of its own.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const stale = mapSetupError(&http_engine, error.CertificateExpired);
    try testing.expectEqual(engine.OpenError.PeerFailedVerification, stale);
    try testing.expect(http_engine.cause() != null);

    const url = try zurl_core.url.parse("http://127.0.0.1:1/");
    try testing.expectError(
        error.CouldNotConnect,
        iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed }),
    );
    try testing.expectEqual(@as(?[]const u8, null), iface.cause());
}

test "the request head reaches the wire exactly as this engine frames it" {
    // These are the bytes `std.http.Client.Request.sendHead` wrote for the
    // same request, in the same order and the same case, with one line
    // taken out: the `accept-encoding` header now belongs to
    // `--compressed` and a request that does not ask for it sends none.
    // Measured against curl 8.21.0 on a loopback listener, a plain `curl
    // http://127.0.0.1:PORT/path` writes no such header either.
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const uri: std.Uri = .{
        .scheme = "http",
        .user = null,
        .password = null,
        .host = .{ .raw = "example.com" },
        .port = 8080,
        .path = .{ .percent_encoded = "/a%20b" },
        .query = .{ .percent_encoded = "x=1" },
        .fragment = .{ .percent_encoded = "frag" },
    };

    try writeRequestHead(&writer, .GET, uri, "zurl/0.1", &.{
        .{ .name = "X-One", .value = "1" },
    }, null, null, null, false);

    try testing.expectEqualStrings(
        "GET /a%20b?x=1 HTTP/1.1\r\n" ++
            "host: example.com:8080\r\n" ++
            "user-agent: zurl/0.1\r\n" ++
            "connection: keep-alive\r\n" ++
            "X-One: 1\r\n" ++
            "\r\n",
        writer.buffered(),
    );
}

test "an offer writes one accept-encoding line, in the place curl writes it" {
    // The same head with `--compressed`. The line sits where the engine
    // always wrote it, after `connection` and before the caller's own
    // headers, so the only difference between the two heads is the one
    // line the flag owns.
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const uri: std.Uri = .{
        .scheme = "http",
        .user = null,
        .password = null,
        .host = .{ .raw = "example.com" },
        .port = 8080,
        .path = .{ .percent_encoded = "/a%20b" },
        .query = .{ .percent_encoded = "x=1" },
        .fragment = .{ .percent_encoded = "frag" },
    };

    try writeRequestHead(&writer, .GET, uri, "zurl/0.1", &.{
        .{ .name = "X-One", .value = "1" },
    }, null, null, null, true);

    try testing.expectEqualStrings(
        "GET /a%20b?x=1 HTTP/1.1\r\n" ++
            "host: example.com:8080\r\n" ++
            "user-agent: zurl/0.1\r\n" ++
            "connection: keep-alive\r\n" ++
            "accept-encoding: deflate, gzip, zstd\r\n" ++
            "X-One: 1\r\n" ++
            "\r\n",
        writer.buffered(),
    );
}

test "a caller's own accept-encoding header is the only one that goes out" {
    // **Two offers on one request name two sets, and a peer may answer
    // either.** So the engine writes none of its own beside the caller's.
    // `openOnce` raises the flag from the same header, which is why this
    // call passes true: a request carrying `-H 'Accept-Encoding: gzip'`
    // reaches here with the offer already made.
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const uri: std.Uri = .{
        .scheme = "http",
        .user = null,
        .password = null,
        .host = .{ .raw = "example.com" },
        .port = 80,
        .path = .{ .percent_encoded = "/" },
        .query = null,
        .fragment = null,
    };

    try writeRequestHead(&writer, .GET, uri, "zurl/0.1", &.{
        .{ .name = "Accept-Encoding", .value = "gzip" },
    }, null, null, null, true);

    const written = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, written, "Accept-Encoding: gzip\r\n") != null);
    // And no second line, whatever its case.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, written, "accept-encoding: deflate"),
    );
}

test "an Upgrade: h2c offer writes three fields and replaces connection: keep-alive" {
    // **The bytes curl 8.21.0 sends for `--http2` on an http url.**
    // Measured on a loopback listener: `Upgrade: h2c`, an `HTTP2-Settings`
    // field, and `Connection: Upgrade, HTTP2-Settings`. RFC 9110 section
    // 7.6.1 makes `Connection` the list of hop-by-hop field names, so the
    // upgrade list is the whole of it and `keep-alive` is not written
    // beside it. curl writes one such line too.
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const uri: std.Uri = .{
        .scheme = "http",
        .user = null,
        .password = null,
        .host = .{ .raw = "example.com" },
        .port = 8080,
        .path = .{ .percent_encoded = "/p" },
        .query = null,
        .fragment = null,
    };

    var settings_buffer: [engine.http2_settings_len_max]u8 = undefined;
    const settings = h2.settingsUpgradeText(&settings_buffer);
    try writeRequestHead(&writer, .GET, uri, "zurl/0.1", &.{}, null, null, settings, false);

    const written = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, written, "upgrade: h2c\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, written, "http2-settings: ") != null);
    try testing.expect(std.mem.indexOf(u8, written, settings) != null);
    try testing.expect(
        std.mem.indexOf(u8, written, "connection: Upgrade, HTTP2-Settings\r\n") != null,
    );
    // **And no second `connection` line.** Two of them would name two
    // different hop-by-hop lists for one request.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, written, "connection: keep-alive"),
    );

    // The same request with no offer is the request this engine always
    // wrote, `keep-alive` and all.
    var plain_buffer: [512]u8 = undefined;
    var plain: std.Io.Writer = .fixed(&plain_buffer);
    try writeRequestHead(&plain, .GET, uri, "zurl/0.1", &.{}, null, null, null, false);
    try testing.expect(
        std.mem.indexOf(u8, plain.buffered(), "connection: keep-alive\r\n") != null,
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, plain.buffered(), "upgrade:"),
    );
}

test "an empty user agent writes no user-agent line at all" {
    // `curl -A ""` sends no such header. A bare `user-agent: ` line names
    // no agent and still costs a header.
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    const uri: std.Uri = .{
        .scheme = "http",
        .user = null,
        .password = null,
        .host = .{ .raw = "example.com" },
        .port = 80,
        .path = .{ .percent_encoded = "/" },
        .query = null,
        .fragment = null,
    };

    try writeRequestHead(&writer, .GET, uri, "", &.{}, null, null, null, false);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "user-agent") == null);
}

test "the engine decodes only under --compressed, and passes through without it" {
    // **The offer plays no part; asking for a decoded body is what
    // counts.** `engine.contentEncoding` holds the rule and the
    // measurements, and this walks it from the engine that reads the field
    // off a raw head.
    //
    // With no offer, every coding reads as `identity` and the peer's own
    // octets go to the caller. Measured against curl 8.21.0: a plain
    // `curl` answered in gzip wrote the 64 compressed octets out and
    // exited 0.
    for ([_][]const u8{ "gzip", "deflate", "zstd", "compress", "br", "exotic" }) |coding| {
        try testing.expectEqual(
            std.http.ContentEncoding.identity,
            try engine.contentEncoding(coding, false),
        );
    }

    // With the offer, the three this build decodes come back by name.
    try testing.expectEqual(
        std.http.ContentEncoding.gzip,
        try engine.contentEncoding("gzip", true),
    );
    try testing.expectEqual(
        std.http.ContentEncoding.deflate,
        try engine.contentEncoding("deflate", true),
    );
    try testing.expectEqual(
        std.http.ContentEncoding.zstd,
        try engine.contentEncoding("zstd", true),
    );
    try testing.expectEqual(
        std.http.ContentEncoding.identity,
        try engine.contentEncoding("identity", true),
    );

    // And the ones it has no decoder for are refused, which is exit 61.
    // `compress` reaches `unreachable` inside `std.http.Decompress`, and
    // `br` is not in this build at all.
    for ([_][]const u8{ "compress", "br", "exotic", "gzip, br" }) |coding| {
        try testing.expectError(
            error.BadContentEncoding,
            engine.contentEncoding(coding, true),
        );
    }

    // And what it advertises names exactly the three it decodes.
    try testing.expect(std.mem.indexOf(u8, accept_encoding_value, "gzip") != null);
    try testing.expect(std.mem.indexOf(u8, accept_encoding_value, "deflate") != null);
    try testing.expect(std.mem.indexOf(u8, accept_encoding_value, "zstd") != null);
    try testing.expect(std.mem.indexOf(u8, accept_encoding_value, "compress") == null);

    // **`br` is absent, and it must stay absent while nothing decodes
    // it.** Brotli is not in the Zig standard library, and a client that
    // advertises a coding it cannot read asks a peer for octets it must
    // then refuse with `error.BadContentEncoding`.
    try testing.expect(std.mem.indexOf(u8, accept_encoding_value, "br") == null);
}

test "the accept-encoding value is curl's list with br struck out" {
    // Measured against curl 8.21.0 on a loopback listener: `curl
    // --compressed http://127.0.0.1:PORT/path` wrote `Accept-Encoding:
    // deflate, gzip, br, zstd`. zurl decodes three of those four, so it
    // writes the same list in the same order and drops the one it cannot
    // read.
    //
    // The order is kept because a server that picks by the order the
    // client wrote then picks the same coding for both tools, whenever it
    // does not offer `br`. This walks curl's list and this one together
    // and proves zurl's is a subsequence of it.
    const curl_value = "deflate, gzip, br, zstd";

    var curl_it = std.mem.splitSequence(u8, curl_value, ", ");
    var zurl_it = std.mem.splitSequence(u8, accept_encoding_value, ", ");

    var next = zurl_it.next();
    var matched: usize = 0;
    while (curl_it.next()) |token| {
        const want = next orelse break;
        if (!std.mem.eql(u8, token, want)) continue;
        matched += 1;
        next = zurl_it.next();
    }
    // Every token zurl writes was found, in curl's own order.
    try testing.expectEqual(@as(?[]const u8, null), next);
    try testing.expectEqual(@as(usize, 3), matched);
}

test "the other two engines advertise the same codings this one does" {
    // `h2` and `h3` write the value out again rather than import it,
    // because `h1` imports both of them and the layering runs one way. A
    // peer must answer all three engines with the same body, so the three
    // values are held together here.
    try testing.expectEqualStrings(accept_encoding_value, h2.accept_encoding_value);
    try testing.expectEqualStrings(accept_encoding_value, h3.accept_encoding_value);
}

/// The reply a proxy fixture serves when a test cares about the request and
/// not the answer.
const proxy_ok_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// Reads the whole body of `exchange` and frees it, so a test that is about
/// the request head still drains the response.
fn drainBody(exchange: *engine.Exchange) !void {
    var body_buffer: [256]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    testing.allocator.free(contents);
}

/// A `Proxy` naming the fixture at `proxy_port`.
fn proxyAt(kind: zurl_core.proxy.Kind, proxy_port: u16) engine.Proxy {
    return .{ .kind = kind, .host = "127.0.0.1", .port = proxy_port };
}

test "a cleartext origin through an http proxy sends one absolute-form request" {
    // Measured against curl 8.21.0 on a loopback listener: `-x
    // http://127.0.0.1:PORT http://example.com/path?q=1` wrote
    // `GET http://example.com/path?q=1 HTTP/1.1` and `Host: example.com`.
    // The proxy reads the whole request, so the target has to name the
    // origin.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .http_proxy }, &.{proxy_ok_response});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const spec = proxyAt(.http, proxy.port());
    const exchange = try iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("http://example.com/path?q=1"),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{ .http = spec },
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try drainBody(exchange);

    const head = proxy.requestHead();
    try testing.expectEqualStrings(
        "GET http://example.com/path?q=1 HTTP/1.1",
        proxy_test_server.firstLine(head),
    );
    // The `host:` line still names the origin and not the proxy, exactly as
    // curl writes it.
    try testing.expect(std.mem.indexOf(u8, head, "host: example.com\r\n") != null);
    // And a proxied request says so on the wire, the way curl does.
    try testing.expect(std.mem.indexOf(u8, head, "proxy-connection: keep-alive") != null);
}

test "a request that named no proxy still writes the origin form" {
    // The whole of the old behaviour. A transfer with an empty proxy set
    // reaches the same bytes it reached before proxies existed, so nothing
    // about this feature can change a run that did not ask for it.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{proxy_ok_response});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{},
    });
    defer exchange.close();
    try drainBody(exchange);

    const head = server.requestHead(0).?;
    try testing.expectEqualStrings("GET /x HTTP/1.1", proxy_test_server_first_line(head));
    try testing.expect(std.mem.indexOf(u8, head, "proxy-connection") == null);
    try testing.expect(std.mem.indexOf(u8, head, "proxy-authorization") == null);
}

/// `proxy_test_server.firstLine`, named locally so the test above reads
/// without a second import.
fn proxy_test_server_first_line(head: []const u8) []const u8 {
    return @import("proxy_test_server.zig").firstLine(head);
}

test "a host the bypass list names goes straight to the origin" {
    // The proxy fixture never accepts, because nothing dials it. The origin
    // fixture answers, which is the whole proof: a `--noproxy` entry that
    // did not match would have sent this request to the proxy instead.
    const test_server = @import("test_server.zig");
    var origin: test_server.TestServer = undefined;
    try origin.start(&.{proxy_ok_response});
    defer origin.stop();

    // A port that refuses every connect. A transfer that reached the proxy
    // would fail here instead of answering.
    const dead = try test_server.closedPort("127.0.0.1");

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{origin.port()});
    defer testing.allocator.free(url_text);

    const spec = proxyAt(.http, dead);
    const exchange = try iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{ .http = spec, .https = spec, .no_proxy = "127.0.0.1" },
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try drainBody(exchange);

    // The origin form, so the request went to the origin and not through
    // anything.
    try testing.expectEqualStrings("GET /x HTTP/1.1", proxy_test_server_first_line(origin.requestHead(0).?));
}

test "a host outside the bypass list still reaches the proxy" {
    // The mirror of the test above. Both halves are needed: a `bypasses`
    // that answered true for everything would pass one of them alone.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .http_proxy }, &.{proxy_ok_response});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const spec = proxyAt(.http, proxy.port());
    const exchange = try iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("http://example.com/x"),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{ .http = spec, .no_proxy = "other.test" },
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try drainBody(exchange);
    try testing.expectEqualStrings(
        "GET http://example.com/x HTTP/1.1",
        proxy_test_server.firstLine(proxy.requestHead()),
    );
}

test "the proxy of a CONNECT tunnel sees the proxy credential and no origin credential" {
    // **This is the credential rule, read off the wire on the proxy's
    // side.** A `CONNECT` is cleartext even when the origin speaks TLS, so
    // everything in it is a secret handed to the proxy. The proxy must see
    // its own credential, because it has to authorise the tunnel, and it
    // must see nothing of the origin's.
    //
    // Measured against curl 8.21.0 on a loopback listener with `-x
    // http://127.0.0.1:PORT -u alice:originpw -U bob:proxypw
    // https://example.com/path?q=1`: the `CONNECT` carried
    // `Proxy-Authorization` and no `Authorization` at all, and it named
    // neither the path nor the query.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .connect }, &.{});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    var spec = proxyAt(.http, proxy.port());
    spec.authorization = "Basic Ym9iOnByb3h5cHc=";

    // The transfer fails at the origin's TLS handshake, because this
    // fixture is not a TLS server. That is expected, and the `CONNECT` head
    // is already on record by then.
    const opened = iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/path?q=1"),
        .headers = &.{},
        .secrets = &.{.{ .name = "authorization", .value = "Basic YWxpY2U6b3JpZ2lucHc=" }},
        .redirects = .unfollowed,
        .insecure = true,
        .proxies = .{ .https = spec },
    });
    if (opened) |exchange| {
        exchange.close();
        return error.TestUnexpectedResult;
    } else |_| {}

    const head = proxy.handshake();
    try testing.expectEqualStrings(
        "CONNECT example.com:443 HTTP/1.1",
        proxy_test_server.firstLine(head),
    );
    // The proxy's own credential is there, once.
    const test_server = @import("test_server.zig");
    try testing.expectEqual(
        @as(usize, 1),
        test_server.countHeaders(head, "Proxy-Authorization"),
    );
    try testing.expect(std.mem.indexOf(u8, head, "Ym9iOnByb3h5cHc=") != null);

    // **And the origin's credential is not.** The count is over whole
    // header names, so a `Proxy-Authorization` line does not answer for an
    // `Authorization` one.
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(head));
    try testing.expect(std.mem.indexOf(u8, head, "YWxpY2U6b3JpZ2lucHc=") == null);
    // The path and the query stayed out too. A proxy has to learn the host
    // and the port, and it has no need of the resource.
    try testing.expect(std.mem.indexOf(u8, head, "/path") == null);
    try testing.expect(std.mem.indexOf(u8, head, "q=1") == null);
    // No cookie either, which is the other name `origin_bound_headers`
    // holds.
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(head, "Cookie"));

    // The bytes after the reply are the origin's own handshake, so the
    // tunnel handed straight over. A TLS record opens with 0x16 and then
    // the legacy record version.
    const inside = proxy.request();
    try testing.expect(inside.len >= 2);
    try testing.expectEqual(@as(u8, 0x16), inside[0]);
    try testing.expectEqual(@as(u8, 0x03), inside[1]);
}

test "the origin behind a socks proxy sees the origin credential and no proxy credential" {
    // **This is the same rule, read off the wire on the origin's side.** A
    // SOCKS proxy authenticates inside its own handshake, so nothing about
    // it may appear in the HTTP request the origin reads.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{
        .kind = .socks5,
        .socks_user = "bob",
        .socks_password = "proxypw",
    }, &.{proxy_ok_response});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    var spec = proxyAt(.socks5h, proxy.port());
    spec.user = "bob";
    spec.password = "proxypw";
    // A SOCKS proxy reads no HTTP, so this value must never reach the wire
    // at all. It is set to prove exactly that.
    spec.authorization = "Basic Ym9iOnByb3h5cHc=";

    const exchange = try iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("http://example.com/x"),
        .headers = &.{},
        .secrets = &.{.{ .name = "authorization", .value = "Basic YWxpY2U6b3JpZ2lucHc=" }},
        .redirects = .unfollowed,
        .proxies = .{ .http = spec },
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try drainBody(exchange);

    // The proxy credential went into the SOCKS handshake, where it belongs.
    const handshake = proxy.handshake();
    try testing.expect(std.mem.indexOf(u8, handshake, "bob") != null);
    try testing.expect(std.mem.indexOf(u8, handshake, "proxypw") != null);
    // And the origin's credential never touched it.
    try testing.expect(std.mem.indexOf(u8, handshake, "YWxpY2U6b3JpZ2lucHc=") == null);

    // The origin sees its own credential, once, and nothing of the proxy's.
    const test_server = @import("test_server.zig");
    const head = proxy.requestHead();
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(head));
    try testing.expect(std.mem.indexOf(u8, head, "YWxpY2U6b3JpZ2lucHc=") != null);
    try testing.expectEqual(
        @as(usize, 0),
        test_server.countHeaders(head, "Proxy-Authorization"),
    );
    try testing.expect(std.mem.indexOf(u8, head, "Ym9iOnByb3h5cHc=") == null);
    try testing.expect(std.mem.indexOf(u8, head, "proxypw") == null);
    // A SOCKS route keeps the origin form: the proxy read no HTTP at all.
    try testing.expectEqualStrings("GET /x HTTP/1.1", proxy_test_server.firstLine(head));
}

test "a socks5h route sends the host name and lets the proxy resolve it" {
    // The whole difference between `socks5` and `socks5h`, read off the
    // handshake. A name here means the local resolver never saw the host.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .socks5 }, &.{proxy_ok_response});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const exchange = try iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("http://example.com:8080/x"),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{ .http = proxyAt(.socks5h, proxy.port()) },
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try drainBody(exchange);

    try testing.expectEqualStrings("example.com", proxy.target());
    try testing.expectEqual(@as(u16, 8080), proxy.targetPort());
}

test "a socks5 route sends an address, and refuses to send a name instead" {
    // `socks5` resolves on this machine. An address travels as an address,
    // and a name that would have to be resolved is refused rather than sent
    // to the proxy: sending it would turn the run into a `socks5h` one and
    // tell the proxy every host the user visits.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .socks5 }, &.{proxy_ok_response});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const exchange = try iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("http://127.0.0.9:8080/x"),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{ .http = proxyAt(.socks5, proxy.port()) },
    });
    defer exchange.close();
    try drainBody(exchange);
    try testing.expectEqualStrings("127.0.0.9", proxy.target());
}

test "a socks4a route sends the host name and socks4 needs an address" {
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .socks4a }, &.{proxy_ok_response});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const exchange = try iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("http://example.com:8080/x"),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{ .http = proxyAt(.socks4a, proxy.port()) },
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try drainBody(exchange);
    try testing.expectEqualStrings("example.com", proxy.target());
    try testing.expectEqual(@as(u16, 8080), proxy.targetPort());
}

test "a socks handshake the proxy refuses keeps the proxy's own error name" {
    // Measured against curl 8.21.0: a listener answering `05 ff`, no
    // acceptable method, gave exit 97, which is `CURLE_PROXY`. A
    // `CouldNotConnect` here would send a user to look at the network.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{ .kind = .socks5, .socks_reply = 0x02 }, &.{});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    try testing.expectError(error.ProxyError, iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("http://example.com/x"),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{ .http = proxyAt(.socks5h, proxy.port()) },
    }));
    // And the cause says what the proxy did, which the name alone cannot.
    try testing.expect(http_engine.cause() != null);
}

test "a CONNECT the proxy refuses reports a failed connect, with the reason" {
    // Measured against curl 8.21.0: a proxy answering `403` to a `CONNECT`
    // gave exit 7, the code a refused connection gives, because no
    // connection to the origin exists either way. The reason a user needs
    // is in the cause.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{
        .kind = .connect,
        .connect_reply = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
    }, &.{});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    try testing.expectError(error.CouldNotConnect, iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/x"),
        .headers = &.{},
        .redirects = .unfollowed,
        .insecure = true,
        .proxies = .{ .https = proxyAt(.http, proxy.port()) },
    }));
    try testing.expectEqualStrings(
        "the proxy refused the tunnel to the origin",
        http_engine.cause().?,
    );
}

test "a proxy that writes bytes before the tunnel exists is refused" {
    // **Nothing legitimate reaches this.** The client speaks first inside
    // any tunnel this build opens, so a byte that arrived with the
    // `CONNECT` reply came from the proxy. The step's own buffer is dropped
    // when it ends, so such a byte would be a byte of the proxy's choosing
    // taken off the front of the origin's stream.
    const proxy_test_server = @import("proxy_test_server.zig");
    var proxy: proxy_test_server.ProxyTestServer = undefined;
    try proxy.start(.{
        .kind = .connect,
        .connect_reply = "HTTP/1.1 200 Connection established\r\n\r\ninjected",
    }, &.{});
    defer proxy.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    try testing.expectError(error.CouldNotConnect, iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/x"),
        .headers = &.{},
        .redirects = .unfollowed,
        .insecure = true,
        .proxies = .{ .https = proxyAt(.http, proxy.port()) },
    }));
    try testing.expectEqualStrings(
        "the proxy wrote bytes before the tunnel could carry any",
        http_engine.cause().?,
    );
}

test "an https proxy cannot carry an https origin, and says so" {
    // A TLS session inside a TLS session, which a `zurl_net.Connection`
    // does not run. It is refused by name rather than run without the outer
    // session: dropping that session would send the `CONNECT`, and the
    // proxy credential on it, in cleartext to a proxy the user asked to
    // reach over TLS.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    try testing.expectError(error.ProxyError, iface.open(.{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/x"),
        .headers = &.{},
        .redirects = .unfollowed,
        .proxies = .{ .https = proxyAt(.https, 3129) },
    }));
    try testing.expectEqualStrings(tls_in_tls_message, http_engine.cause().?);
}

test "a route names the peer of every case, and the peer its TLS checks" {
    // **The table this whole feature rests on.** Each row says where the
    // socket goes, which peer its session authenticates, and whether the
    // proxy reads the request. A row that named the wrong TLS peer would
    // let a proxy terminate the origin's TLS, so each one is written out.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const req_plain: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("http://example.com/x"),
        .headers = &.{},
        .redirects = .unfollowed,
    };
    const req_tls: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/x"),
        .headers = &.{},
        .redirects = .unfollowed,
    };
    const dial_plain: engine.DialTarget = .{ .host = "example.com", .port = 80, .overridden = false };
    const dial_tls: engine.DialTarget = .{ .host = "example.com", .port = 443, .overridden = false };

    // No proxy: the socket goes to the origin, and TLS on it is the
    // origin's. This is every transfer that named none.
    {
        const route = try routeFor(&http_engine, req_plain, .plain, dial_plain, null);
        try testing.expectEqual(TlsPeer.none, route.tls);
        try testing.expect(route.proxied_head == null);
        try testing.expect(route.step == null);
        try testing.expectEqualStrings("example.com", route.host);
    }
    {
        const route = try routeFor(&http_engine, req_tls, .tls, dial_tls, null);
        try testing.expectEqual(TlsPeer.origin, route.tls);
        try testing.expectEqualStrings("example.com", route.host);
    }

    // An HTTP proxy, cleartext origin: the socket goes to the proxy, the
    // proxy reads the request, and nothing speaks TLS.
    {
        const spec = proxyAt(.http, 3128);
        const route = try routeFor(&http_engine, req_plain, .plain, dial_plain, spec);
        try testing.expectEqual(TlsPeer.none, route.tls);
        try testing.expect(route.proxied_head != null);
        try testing.expect(route.step == null);
        try testing.expectEqualStrings("127.0.0.1", route.host);
        try testing.expectEqual(@as(u16, 3128), route.port);
    }

    // **An HTTPS proxy, cleartext origin: the session is the proxy's.** The
    // origin speaks cleartext and has no session at all, so a route that
    // said `.origin` here would check the origin's name against the proxy's
    // certificate.
    {
        const spec = proxyAt(.https, 3128);
        const route = try routeFor(&http_engine, req_plain, .plain, dial_plain, spec);
        try testing.expectEqual(TlsPeer.proxy, route.tls);
        try testing.expect(route.proxied_head != null);
    }

    // **An HTTP proxy, TLS origin: a tunnel, and the session is the
    // origin's.** The proxy reads the `CONNECT` and nothing after it, so
    // the request keeps the origin form and carries no proxy credential.
    {
        const spec = proxyAt(.http, 3128);
        const route = try routeFor(&http_engine, req_tls, .tls, dial_tls, spec);
        try testing.expectEqual(TlsPeer.origin, route.tls);
        try testing.expect(route.proxied_head == null);
        try testing.expect(route.step.? == .connect);
        try testing.expectEqualStrings("example.com", route.step.?.connect.target.host);
        try testing.expectEqual(@as(u16, 443), route.step.?.connect.target.port);
    }

    // A SOCKS proxy: the handshake opens the route, and everything after it
    // is the origin's on either scheme.
    for ([_]zurl_core.proxy.Kind{ .socks4, .socks4a, .socks5, .socks5h }) |kind| {
        const spec = proxyAt(kind, 1080);
        const plain = try routeFor(&http_engine, req_plain, .plain, dial_plain, spec);
        try testing.expectEqual(TlsPeer.none, plain.tls);
        try testing.expect(plain.proxied_head == null);
        try testing.expect(plain.step.? == .socks);

        const secure = try routeFor(&http_engine, req_tls, .tls, dial_tls, spec);
        try testing.expectEqual(TlsPeer.origin, secure.tls);
        try testing.expect(secure.proxied_head == null);
        try testing.expect(secure.step.? == .socks);
    }
}

test "a plain GET returns the status and the body" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    const head = exchange.head();
    try testing.expectEqual(@as(u16, 200), head.status);
    try testing.expectEqual(@as(?u64, 7), head.content_length);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

/// A response whose head carries one header value of `pad` bytes, with a
/// two-byte body behind it. The caller owns the result.
///
/// The whole head is `padded_response_overhead + pad` bytes long, so a
/// test can ask for a head of an exact size.
fn buildPaddedResponse(allocator: std.mem.Allocator, pad: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, padded_response_prefix);
    try out.appendNTimes(allocator, 'x', pad);
    try out.appendSlice(allocator, padded_response_suffix);
    return out.toOwnedSlice(allocator);
}

const padded_response_prefix = "HTTP/1.1 200 OK\r\nX-Big: ";
const padded_response_suffix = "\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// How many bytes of head `buildPaddedResponse` writes beside the padding.
/// The two-byte body is not part of the head, so it does not count.
const padded_response_overhead = padded_response_prefix.len + padded_response_suffix.len - 2;

/// How many bytes the padded line writes beside the padding: the name, the
/// colon, the space, and the CRLF. A `pad` of `n` makes a line of
/// `n + padded_response_line_overhead` bytes on the wire, which is what the
/// line bound measures.
const padded_response_line_overhead = "X-Big: \r\n".len;

/// The head of a response one of the builders below made, without the
/// two-byte body.
fn responseHead(response: []const u8) []const u8 {
    return response[0 .. response.len - 2];
}

/// How long each line `buildWideResponse` repeats is, the CRLF included.
/// Far under `head_field_len_max`, so a head built of these lines only ever
/// reaches the whole-head bound.
const wide_response_line_len = 100;

/// A response whose head is exactly `head_len` bytes of many short header
/// lines, with a two-byte body behind it. The caller owns the result.
///
/// This is the shape the whole-head bound describes, and the shape
/// `buildPaddedResponse` cannot make. A head of short lines can pass
/// `head_field_len_max` many times over and still carry no line that the
/// line bound refuses, so only a head of this shape tells the two bounds
/// apart.
///
/// Asserts `head_len` leaves room for the status line, the closing lines,
/// and two full lines of padding. The loop stops with between one and two
/// lines still to write, so the last line is never shorter than a header
/// line can be.
fn buildWideResponse(allocator: std.mem.Allocator, head_len: usize) ![]u8 {
    const status = "HTTP/1.1 200 OK\r\n";
    const closing = "Content-Length: 2\r\nConnection: close\r\n\r\n";
    std.debug.assert(head_len >= status.len + closing.len + 2 * wide_response_line_len);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, status);

    var i: usize = 0;
    while (out.items.len + closing.len + 2 * wide_response_line_len <= head_len) : (i += 1) {
        var name_buffer: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "X{d:0>6}", .{i});
        try out.appendSlice(allocator, name);
        try out.appendSlice(allocator, ": ");
        try out.appendNTimes(allocator, 'b', wide_response_line_len - name.len - 4);
        try out.appendSlice(allocator, "\r\n");
    }

    // One last line brings the head to exactly `head_len`. It is between
    // one and two lines long, because the loop above stopped one line
    // short of the target.
    const last = head_len - out.items.len - closing.len;
    std.debug.assert(last >= wide_response_line_len);
    std.debug.assert(last < 2 * wide_response_line_len);
    try out.appendSlice(allocator, "X-Last: ");
    try out.appendNTimes(allocator, 'b', last - "X-Last: \r\n".len);
    try out.appendSlice(allocator, "\r\n");

    try out.appendSlice(allocator, closing);
    std.debug.assert(out.items.len == head_len);
    try out.appendSlice(allocator, "ok");
    return out.toOwnedSlice(allocator);
}

test "a response head that curl accepts arrives whole" {
    // curl 8.21.0 reads both of these and exits 0. zurl used to fail every
    // one of them with `ReadError`, on a connection read buffer of 8192
    // bytes that no engine constant sized. Real servers send heads this
    // large: many `Set-Cookie` lines, a long `Content-Security-Policy`, or
    // verbose tracing headers.
    const test_server = @import("test_server.zig");

    for ([_]usize{ 9 * 1024, 90 * 1024 }) |pad| {
        const response = try buildPaddedResponse(testing.allocator, pad);
        defer testing.allocator.free(response);
        try testing.expect(responseHead(response).len <= head_len_max);
        // These are single-line heads, so they also stay under the line
        // bound. A case that broke the line bound would prove the wrong
        // thing here.
        try testing.expect(pad + padded_response_line_overhead < head_field_len_max);

        var server: test_server.TestServer = undefined;
        try server.start(&.{response});
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();
        const iface = http_engine.interface();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
        defer testing.allocator.free(url_text);
        const url = try zurl_core.url.parse(url_text);

        const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
        defer exchange.close();

        const head = exchange.head();
        try testing.expectEqual(@as(u16, 200), head.status);
        try testing.expect(!head.headers_oversize);
        // The whole head, byte for byte, is what `-D` writes to a file. A
        // head that arrived cut short would still parse, so this compares
        // the bytes and not the status alone.
        try testing.expectEqualStrings(responseHead(response), head.headers.?);

        var body_buffer: [64]u8 = undefined;
        const body = exchange.bodyReader(&body_buffer);
        const contents = try body.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(contents);
        try testing.expectEqualStrings("ok", contents);
    }
}

/// Opens `response` from a loopback server and returns what the engine
/// said. The caller frees nothing; the exchange is closed before this
/// returns, and only the error or the head length comes back.
///
/// The head is compared inside, while the exchange is still open, because
/// `engine.Head.headers` points into memory the exchange owns.
fn expectResponseAccepted(response: []const u8) !void {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{response});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    const head = exchange.head();
    try testing.expectEqual(@as(u16, 200), head.status);
    // The whole head, byte for byte, is what `-D` writes to a file. A head
    // that arrived cut short would still parse, so this compares the bytes
    // and not the status alone.
    try testing.expectEqualStrings(responseHead(response), head.headers.?);
}

/// Opens `response` from a loopback server and asserts the engine refuses
/// it with `expected`.
fn expectResponseRefused(response: []const u8, expected: anyerror) !void {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{response});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const opened = iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    try testing.expectError(expected, opened);
}

test "a head of many short lines past the line bound still arrives whole" {
    // This is the case an earlier zurl got wrong. It kept one bound of
    // 102400 bytes and refused this head, which curl reads without
    // trouble. Measured against curl 8.21.0: a head of 112860 bytes built
    // of short lines gives exit 0.
    //
    // The head passes the line bound many times over, and no line in it
    // comes near that bound. Only a head of this shape tells the two
    // bounds apart, which is why it is built from a loop and not from one
    // long header.
    const response = try buildWideResponse(testing.allocator, 112860);
    defer testing.allocator.free(response);

    try testing.expect(responseHead(response).len > head_field_len_max);
    try testing.expect(responseHead(response).len < head_len_max);
    try testing.expect(!hasOversizeField(responseHead(response)));

    try expectResponseAccepted(response);
}

test "a whole response head at the bound arrives, and one byte past it is refused by name" {
    // The head bound counts every byte of the head together. Both heads
    // here are built of short lines, so the line bound cannot fire for
    // either one and only the head bound decides.
    //
    // Measured against curl 8.21.0: a head of 307200 bytes gives exit 0
    // and a head of 307201 bytes gives exit 56.
    const at_bound = try buildWideResponse(testing.allocator, head_len_max);
    defer testing.allocator.free(at_bound);
    try testing.expectEqual(head_len_max, responseHead(at_bound).len);
    try testing.expect(!hasOversizeField(responseHead(at_bound)));
    try expectResponseAccepted(at_bound);

    const past_bound = try buildWideResponse(testing.allocator, head_len_max + 1);
    defer testing.allocator.free(past_bound);
    try testing.expectEqual(head_len_max + 1, responseHead(past_bound).len);
    try testing.expect(!hasOversizeField(responseHead(past_bound)));
    // Its own name, and not `ReadError`. A user who reads `ReadError`
    // looks at the network, and the cause is a bound this engine keeps.
    try expectResponseRefused(past_bound, error.ResponseHeadTooLarge);
}

test "one header line at the bound is refused by name, and one byte under it arrives" {
    // The line bound counts one line, the CRLF included. Both heads here
    // stay far under the head bound, so the head bound cannot fire for
    // either one and only the line bound decides.
    //
    // Measured against curl 8.21.0: a header line of 102399 bytes gives
    // exit 0 and a line of 102400 bytes gives exit 100.
    const under = try buildPaddedResponse(
        testing.allocator,
        head_field_len_max - padded_response_line_overhead - 1,
    );
    defer testing.allocator.free(under);
    try testing.expect(responseHead(under).len < head_len_max);
    try testing.expect(!hasOversizeField(responseHead(under)));
    try expectResponseAccepted(under);

    const at_bound = try buildPaddedResponse(
        testing.allocator,
        head_field_len_max - padded_response_line_overhead,
    );
    defer testing.allocator.free(at_bound);
    try testing.expect(responseHead(at_bound).len < head_len_max);
    try testing.expect(hasOversizeField(responseHead(at_bound)));
    try expectResponseRefused(at_bound, error.HeaderLineTooLarge);
}

test "a redirect is followed to the final body" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /body\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 1 } });
    defer exchange.close();

    const head = exchange.head();
    try testing.expectEqual(@as(u16, 200), head.status);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

test "a 404 is reported as a status, not an error" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/missing", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 404), exchange.head().status);
}

// The four tests below pin the safety requirement that a server is
// untrusted input: a malformed status line, a redirect to a malformed
// URL, and a body cut off mid-stream must each surface as an
// `engine.OpenError` or an `std.Io.Reader` error, never a panic and never
// undefined behaviour. The fourth pins the same requirement against the
// engine's own caller: a `redirects` count of `maxInt(u16)` is the value
// `std.http.Client` reserves for "unhandled", and it must report the
// redirect rather than assert or follow one.

test "a malformed status line is a read error, not a panic" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"NOT AN HTTP RESPONSE\r\n\r\n"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    try testing.expectError(
        error.ReadError,
        iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed }),
    );
}

test "a body shorter than its Content-Length fails allocRemaining, and does not panic" {
    // `std.Io.Reader.allocRemaining` treats the end of the stream as
    // ordinary completion: it hands back whatever arrived, with no error.
    // `std.http.Reader.contentLengthStream` ends the stream as soon as the
    // connection closes, even though `remaining_content_length` never
    // reached zero, so the pair used to report a 2-byte body for a
    // 1000000000-byte object and call it a success. The engine's own body
    // reader closes that hole.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\nConnection: close\r\n\r\nhi",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqual(@as(?u64, 1000000000), exchange.head().content_length);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    try testing.expectError(error.ReadFailed, body.allocRemaining(testing.allocator, .unlimited));
    try testing.expectError(error.PartialFile, exchange.check());
}

test "reading exactly Content-Length bytes catches a body cut short, as a read error not a panic" {
    // A bounded read asks for a specific number of bytes, so it always
    // noticed the shortfall. It now reports the same named reason as every
    // other read shape, instead of a bare `error.EndOfStream`.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhi",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    const content_length = exchange.head().content_length.?;
    try testing.expectEqual(@as(u64, 10), content_length);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    var dest: [10]u8 = undefined;
    try testing.expectError(error.ReadFailed, body.readSliceAll(&dest));
    try testing.expectError(error.PartialFile, exchange.check());
}

test "a redirect to a malformed location is an invalid-url error, not a panic" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: http://ex ample.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    try testing.expectError(
        error.InvalidUrl,
        iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 1 } }),
    );
}

test "a follow count of the u16 maximum returns the redirect unfollowed, instead of asserting" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .{ .follow = std.math.maxInt(u16) },
    });
    defer exchange.close();

    const head = exchange.head();
    try testing.expectEqual(@as(u16, 302), head.status);
    try testing.expectEqualStrings("/elsewhere", head.location.?);
}

// The three tests below use a bare listening socket rather than
// `TestServer`, because a TLS client and a scripted HTTP responder cannot
// talk to each other. A listener is enough to prove what they pin: that
// the connect path reaches the TLS handshake, and that a connect which
// never finishes stops at its deadline.

/// Accepts one connection and closes it at once. The peer sees the
/// connection end during its TLS handshake.
fn acceptAndClose(server: *std.Io.net.Server) void {
    const stream = server.accept(testing.io) catch return;
    stream.close(testing.io);
}

/// Accepts one connection, reads until the peer or a cancel ends the read,
/// and answers nothing. A TLS handshake against this listener never
/// finishes.
fn acceptAndStall(server: *std.Io.net.Server) void {
    const stream = server.accept(testing.io) catch return;
    defer stream.close(testing.io);

    var read_buffer: [1024]u8 = undefined;
    var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
    _ = reader.interface.discardRemaining() catch {};
}

test "an https url reaches the tls handshake and reports an error, instead of panicking" {
    // The whole TLS setup runs here: a real socket, real entropy, and the
    // vendored client on the other end of it. The peer cuts the handshake,
    // so the engine must answer with a name and a cause a user can act on.
    //
    // This test pinned a different trap while `std.http.Client` was the
    // transport: `Connection.Tls.create` read `client.now.?`, and an
    // engine that did not stamp that clock aborted in Debug and checked
    // the certificate dates against an uninitialised timestamp in
    // ReleaseFast. `zurl_net.Connection.init` reads the clock itself, so
    // there is no clock left for this engine to forget. What is checked
    // instead is the cause, which is what the swap was for.
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    var future = testing.io.concurrent(acceptAndClose, .{&server}) catch |err| switch (err) {
        error.ConcurrencyUnavailable => {
            // A single-threaded build genuinely cannot run the accepting
            // task and the connecting task at once. A threaded build that
            // reaches this arm has a real concurrency regression, and
            // must fail loudly instead of skipping quietly.
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
    };
    defer future.cancel(testing.io);

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "https://127.0.0.1:{d}/",
        .{server.socket.address.ip4.port},
    );
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    // The engine carries no trust roots, and the peer answers nothing, so
    // the handshake cannot succeed. It must fail with a named error, not
    // with garbage-time validation.
    try testing.expectError(
        error.SslConnectError,
        iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed }),
    );

    // And the name is not the whole answer. The cause says the handshake
    // is where it happened, which is what tells a user apart from a peer
    // that refused the connection.
    const why = iface.cause() orelse return error.TestExpectedCause;
    try testing.expect(std.mem.indexOf(u8, why, "handshake") != null);
}

/// Counts the calls an `engine.TlsSetup` hook gets, and fails them on
/// request, for the two tests below.
const SetupCounter = struct {
    calls: usize = 0,
    fails: bool = false,

    fn call(ptr: *anyopaque) engine.TlsSetupError!void {
        const self: *SetupCounter = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        if (self.fails) return error.SslConnectError;
    }

    fn setup(self: *SetupCounter) engine.TlsSetup {
        return .{ .ptr = self, .call = call };
    }
};

test "the tls setup hook runs for an https hop and never for a plain http hop" {
    // The owner of the engine loads the trust roots from this hook, so a
    // call for a plain `http` hop is a certificate path read by a transfer
    // that uses no TLS. Port 1 is closed on loopback, so both requests
    // fail at the connect, which is after the hook either ran or did not.
    var counter: SetupCounter = .{};

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    http_engine.tls_setup = counter.setup();
    const iface = http_engine.interface();

    const plain = try zurl_core.url.parse("http://127.0.0.1:1/");
    try testing.expectError(
        error.CouldNotConnect,
        iface.open(.{ .method = .GET, .url = plain, .headers = &.{}, .redirects = .unfollowed }),
    );
    try testing.expectEqual(@as(usize, 0), counter.calls);

    const secure = try zurl_core.url.parse("https://127.0.0.1:1/");
    try testing.expectError(
        error.CouldNotConnect,
        iface.open(.{ .method = .GET, .url = secure, .headers = &.{}, .redirects = .unfollowed }),
    );
    try testing.expectEqual(@as(usize, 1), counter.calls);
}

test "a tls setup hook that fails stops the request" {
    // The hook reports that the trust roots are not ready. A handshake
    // with no roots cannot verify the peer, so the request must stop here
    // rather than run without them.
    var counter: SetupCounter = .{ .fails = true };

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    http_engine.tls_setup = counter.setup();
    const iface = http_engine.interface();

    const secure = try zurl_core.url.parse("https://127.0.0.1:1/");
    try testing.expectError(
        error.SslConnectError,
        iface.open(.{ .method = .GET, .url = secure, .headers = &.{}, .redirects = .unfollowed }),
    );
    try testing.expectEqual(@as(usize, 1), counter.calls);
}

test "a connect that never finishes stops at the connect timeout" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);

    // The top of this test already returned for a single-threaded build,
    // so `ConcurrencyUnavailable` here means a threaded build could not
    // get a concurrent task: a real regression, not an expected limit.
    var future = testing.io.concurrent(acceptAndStall, .{&server}) catch |err| return err;
    defer future.cancel(testing.io);

    var http_engine: Engine = .init(testing.allocator, testing.io, .{
        .connect_timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } },
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "https://127.0.0.1:{d}/",
        .{server.socket.address.ip4.port},
    );
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    // The listener accepts and then answers nothing, so the TLS handshake
    // inside the connect waits forever. The deadline must end it.
    try testing.expectError(
        error.OperationTimedOut,
        iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed }),
    );
}

test "a connect timeout that is not reached leaves a normal request alone" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{
        .connect_timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } },
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed }) catch |err| switch (err) {
        error.ConnectTimeoutUnsupported => {
            // A single-threaded build cannot race the connect against the
            // deadline at all, so `connect` refuses instead of dropping
            // the bound; see the test right below this one. A threaded
            // build that reaches this arm could not get a concurrent task
            // for an ordinary request, which is a real regression, not an
            // expected limit.
            if (@import("builtin").single_threaded) return error.SkipZigTest;
            return err;
        },
        else => |e| return e,
    };
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
}

/// A threaded `Io` whose `concurrent` always reports
/// `error.ConcurrencyUnavailable`, on any build.
///
/// A build compiled with no concurrency at all used to be the only way to
/// see that error out of an ordinary `Io.concurrent` call. `concurrent_limit
/// = .nothing` forces the same answer out of an ordinary threaded `Io`, so
/// a test that pins what happens when the bound cannot be raced no longer
/// needs a build that no longer exists.
///
/// The caller must `deinit` the result.
fn noConcurrencyIo() std.Io.Threaded {
    return .init(testing.allocator, .{ .concurrent_limit = .nothing });
}

test "a connect timeout is refused, not dropped, when the build has no concurrency" {
    var no_concurrency = noConcurrencyIo();
    defer no_concurrency.deinit();
    const io = no_concurrency.io();

    var http_engine: Engine = .init(testing.allocator, io, .{
        .connect_timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } },
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url = try zurl_core.url.parse("http://127.0.0.1:9/");

    try testing.expectError(
        error.ConnectTimeoutUnsupported,
        iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed }),
    );
}

/// One connection's part in a read deadline test: what to write once the
/// request head has arrived, how many single octets follow it and how far
/// apart, and whether to keep the socket open and silent at the end.
///
/// **`test_server.TestServer` cannot serve these tests.** That fixture
/// writes its scripted octets and closes the connection, and a closed
/// connection ends a body rather than stalling one. The whole subject here
/// is the difference between the two: a peer that closes is a peer this
/// engine has always handled, and a peer that holds the socket open and
/// says nothing is the one that used to hold the transfer forever.
const StallStep = struct {
    /// Written as soon as the request head has arrived.
    prelude: []const u8,
    /// How many single octets follow the prelude.
    drips: usize = 0,
    /// How long to wait before each of those octets.
    gap_ms: u32 = 0,
    /// Whether to keep the socket open and silent after the last octet.
    /// True is the stall under test; false closes, which is an ordinary
    /// end of a connection.
    hold: bool = true,
};

/// A loopback listener that serves one `StallStep` for each connection, in
/// order, and stops accepting after the last one.
const StallServer = struct {
    server: std.Io.net.Server,
    task: std.Io.Future(void),
    steps: []const StallStep,
    /// How many connections the client opened. A reuse test reads this:
    /// no header on the wire shows whether a connection was kept.
    accepts: std.atomic.Value(usize),

    /// Initializes `self` in place, so the task can hold `&self.server`
    /// for its whole life. `steps` must outlive the server.
    fn start(self: *StallServer, steps: []const StallStep) !void {
        var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        self.server = try address.listen(testing.io, .{ .reuse_address = true });
        errdefer self.server.deinit(testing.io);
        self.steps = steps;
        self.accepts = .init(0);
        self.task = testing.io.concurrent(serve, .{self}) catch |err| switch (err) {
            error.ConcurrencyUnavailable => {
                // The listener and its client cannot both make progress on
                // one task. A threaded build that lands here has a real
                // concurrency regression and must say so.
                if (@import("builtin").single_threaded) return error.SkipZigTest;
                return err;
            },
        };
    }

    /// Stops the task and releases the listening socket. The task is
    /// canceled and not joined: a step that holds a socket open waits for
    /// the client, and a test that never opened that connection would
    /// otherwise wait forever.
    fn stop(self: *StallServer) void {
        self.task.cancel(testing.io);
        self.server.deinit(testing.io);
    }

    fn port(self: *const StallServer) u16 {
        return self.server.socket.address.getPort();
    }

    fn serve(self: *StallServer) void {
        for (self.steps) |step| {
            const stream = self.server.accept(testing.io) catch return;
            defer stream.close(testing.io);
            self.accepts.store(self.accepts.load(.monotonic) + 1, .release);

            var read_buffer: [4096]u8 = undefined;
            var reader = std.Io.net.Stream.Reader.init(stream, testing.io, &read_buffer);
            // The request head, up to and including the empty line. No
            // test here sends a request body.
            while (true) {
                const line = reader.interface.takeDelimiterInclusive('\n') catch return;
                if (line.len <= 2) break;
            }

            var write_buffer: [4096]u8 = undefined;
            var writer = std.Io.net.Stream.Writer.init(stream, testing.io, &write_buffer);
            writer.interface.writeAll(step.prelude) catch return;
            writer.interface.flush() catch return;

            var sent: usize = 0;
            while (sent < step.drips) : (sent += 1) {
                if (step.gap_ms != 0) {
                    const gap: std.Io.Timeout = .{
                        .duration = .{ .raw = .fromMilliseconds(step.gap_ms), .clock = .awake },
                    };
                    gap.sleep(testing.io) catch return;
                }
                writer.interface.writeAll("x") catch return;
                writer.interface.flush() catch return;
            }

            // Hold the socket open with nothing on it. The read ends when
            // the client closes or when `stop` cancels this task, so
            // neither side waits for the other forever.
            if (step.hold) _ = reader.interface.discardRemaining() catch {};
        }
    }
};

/// A `read_timeout` of `ms` milliseconds, for the tests below.
fn readTimeoutMs(ms: u32) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

/// How many nanoseconds have passed since `started`.
///
/// **Every timing assertion here is a floor and never a ceiling.** A
/// loaded machine makes a ceiling fail for a reason that has nothing to do
/// with this engine. A floor says only that the deadline did not fire
/// early, which is the property under test.
fn elapsedNs(started: std.Io.Timestamp) i128 {
    return started.durationTo(std.Io.Timestamp.now(testing.io, .awake)).nanoseconds;
}

test "a peer that answers a head and then stops sending ends the transfer" {
    // **The defect this closes.** The connect succeeded, the head arrived
    // whole, and then the peer wrote nothing and kept the socket open.
    // `zurl_stream.Stall` cannot see it: that decorator measures a read
    // after the read comes back, and this read never comes back. Without
    // the deadline below, the transfer waits for as long as the peer
    // likes.
    var server: StallServer = undefined;
    try server.start(&.{.{ .prelude = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n" }});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{
        .read_timeout = readTimeoutMs(200),
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const started = std.Io.Timestamp.now(testing.io, .awake);
    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    try testing.expectError(
        error.ReadFailed,
        body.allocRemaining(testing.allocator, .unlimited),
    );
    // `std.Io.Reader` has a closed error set, so the read can say no more
    // than that it failed. `check` is where the reason is, and recovery is
    // never silent.
    try testing.expectError(error.OperationTimedOut, exchange.check());

    try testing.expect(elapsedNs(started) >= 200 * std.time.ns_per_ms);
}

test "a peer that answers nothing at all ends the head phase" {
    // The same stall, one step earlier. `--connect-timeout` is already
    // over by the time this starts, and on a pooled connection there was
    // never a dial to bound at all.
    var server: StallServer = undefined;
    try server.start(&.{.{ .prelude = "" }});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{
        .read_timeout = readTimeoutMs(200),
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const started = std.Io.Timestamp.now(testing.io, .awake);
    try testing.expectError(
        error.OperationTimedOut,
        iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed }),
    );
    try testing.expect(elapsedNs(started) >= 200 * std.time.ns_per_ms);
}

test "a body that drips slower than the bound ends the transfer" {
    // The peer is alive and writing, and still too slow to count as
    // writing at all. curl answers the same shape the same way: measured
    // against curl 8.21.0, one octet every 3 seconds under
    // `--speed-limit 100 --speed-time 2` exited 28 after 2.004 seconds.
    var server: StallServer = undefined;
    try server.start(&.{.{
        .prelude = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n",
        .drips = 10,
        .gap_ms = 600,
    }});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{
        .read_timeout = readTimeoutMs(150),
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const started = std.Io.Timestamp.now(testing.io, .awake);
    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    try testing.expectError(
        error.ReadFailed,
        body.allocRemaining(testing.allocator, .unlimited),
    );
    try testing.expectError(error.OperationTimedOut, exchange.check());

    try testing.expect(elapsedNs(started) >= 150 * std.time.ns_per_ms);
}

test "a body that is slow but keeps arriving runs past the bound and completes" {
    // **The bound is on one read and never on the transfer.** This body
    // takes about 400 milliseconds to arrive over a 150 millisecond bound,
    // and it must arrive whole: a deadline on the total would kill a
    // download over a slow link, which is exactly what `--speed-limit` and
    // `--speed-time` come as a pair to avoid. Measured against curl
    // 8.21.0, 4096 octets each second under `--speed-limit 100
    // --speed-time 2` ran 11.09 seconds and exited 0.
    var server: StallServer = undefined;
    try server.start(&.{.{
        .prelude = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n",
        .drips = 10,
        .gap_ms = 40,
        .hold = false,
    }});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{
        .read_timeout = readTimeoutMs(150),
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const started = std.Io.Timestamp.now(testing.io, .awake);
    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("xxxxxxxxxx", contents);
    try exchange.check();

    // A floor, and it is over the bound: ten gaps of 40 milliseconds
    // cannot pass in less than 400. That is what says the deadline counts
    // one read and not the whole transfer.
    try testing.expect(elapsedNs(started) >= 400 * std.time.ns_per_ms);
}

test "a connection whose read timed out never serves the next request" {
    // A peer that went quiet stopped at a place nothing here knows, and
    // the raced read was canceled part way through. Whatever that peer
    // writes next would land in front of the next request, so the
    // connection has to be closed and not pooled.
    //
    // **Two rules in `reusable` stand behind this, and the test pins what
    // a caller can see rather than which of the two fired.** The framing
    // state is away from `ready` for a body that stopped mid-count, and
    // `read_timed_out` covers the shapes where it is not. A test that
    // named one of them would go quiet if the other were removed.
    var server: StallServer = undefined;
    try server.start(&.{
        // Keep-alive by default: an HTTP/1.1 response with no
        // `connection: close` is exactly the shape the pool keeps.
        .{ .prelude = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n" },
        .{ .prelude = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", .hold = false },
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{
        .read_timeout = readTimeoutMs(200),
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);
    const request: engine.Request = .{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    };

    {
        const stalled = try iface.open(request);
        defer stalled.close();
        var body_buffer: [64]u8 = undefined;
        const body = stalled.bodyReader(&body_buffer);
        try testing.expectError(
            error.ReadFailed,
            body.allocRemaining(testing.allocator, .unlimited),
        );
        try testing.expectError(error.OperationTimedOut, stalled.check());
    }

    // The second request must reach the peer, which it can only do on a
    // connection of its own.
    const second = try iface.open(request);
    defer second.close();
    var second_buffer: [64]u8 = undefined;
    const second_body = second.bodyReader(&second_buffer);
    const contents = try second_body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("ok", contents);

    try testing.expectEqual(@as(usize, 2), server.accepts.load(.acquire));
}

test "a read runs with no bound, and is counted, when the build has no clock to watch" {
    // **A refusal here would leave such a build with no HTTP at all.** The
    // connect path refuses and the front package retries with no bound;
    // a body read has no such second chance, so the read runs unbounded
    // and the engine counts it. The same build enforces no
    // `--connect-timeout` and no `--max-time` either, so the clock is
    // missing from the whole transfer and not from this engine alone.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var no_concurrency = noConcurrencyIo();
    defer no_concurrency.deinit();

    var http_engine: Engine = .init(testing.allocator, no_concurrency.io(), .{
        .read_timeout = readTimeoutMs(200),
    });
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);

    // The dropped bound reaches a caller instead of going quiet.
    try testing.expect(http_engine.readBoundsDropped() >= 1);
}

test "the read timeout default is curl's own speed-time default" {
    // The number is not chosen here twice. `zurl_net.bounded.stallTimeout`
    // narrows it with `--speed-time` and never widens it, which is how
    // every other protocol package in this tree reads the pair.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    try testing.expectEqual(@as(u32, 300), default_read_timeout_s);
    try testing.expectEqual(
        @as(i64, 300_000),
        http_engine.read_timeout.duration.raw.toMilliseconds(),
    );
    try testing.expectEqual(std.Io.Clock.awake, http_engine.read_timeout.duration.clock);

    // `--speed-time 2` narrows it, and `--speed-limit 0` leaves the
    // package ceiling standing. Both answers come from one function, which
    // the front package reaches through `readTimeoutFor`.
    const narrowed = readTimeoutFor(100, 2);
    try testing.expectEqual(@as(i64, 2_000), narrowed.duration.raw.toMilliseconds());
    const off = readTimeoutFor(0, 0);
    try testing.expectEqual(@as(i64, 300_000), off.duration.raw.toMilliseconds());
    // A `--speed-time` past the ceiling does not widen it.
    const wide = readTimeoutFor(100, 3600);
    try testing.expectEqual(@as(i64, 300_000), wide.duration.raw.toMilliseconds());
}

test "a short body fails streamRemaining, the shape a hashing download uses" {
    // A download that hashes while it writes streams the body. It never
    // asks for a byte count, so nothing in the read shape itself can find
    // a truncated transfer. Without the engine's check, that download
    // would report a confident digest over 2 bytes of a 100-byte object.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nhi",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);

    var sink_storage: [256]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_storage);
    try testing.expectError(error.ReadFailed, body.streamRemaining(&sink));
    try testing.expectError(error.PartialFile, exchange.check());
}

test "a Content-Length of the u64 maximum is a short body, not a trusted length" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\nConnection: close\r\n\r\nhi",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), exchange.head().content_length);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    try testing.expectError(error.ReadFailed, body.allocRemaining(testing.allocator, .unlimited));
    try testing.expectError(error.PartialFile, exchange.check());
}

test "a complete body reports no fault" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);
    try exchange.check();
}

test "a chunked body reports no content length, whatever Content-Length said" {
    // RFC 9112 tells a recipient to ignore a `Content-Length` that arrives
    // beside `Transfer-Encoding: chunked`. Reporting the number would let
    // a caller size a file, or a progress bar, from something the body
    // does not match.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n" ++
            "Connection: close\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    const head = exchange.head();
    try testing.expectEqual(@as(?u64, null), head.content_length);
    try testing.expectEqual(std.http.TransferEncoding.chunked, head.transfer_encoding);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("body", contents);
    try exchange.check();
}

test "a chunked body cut mid-stream is still a read error" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n64\r\nshort\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    try testing.expectError(error.ReadFailed, body.allocRemaining(testing.allocator, .unlimited));
}

/// Reads the first octet of a chunked body whose first chunk size field is
/// `size_line`, written on the wire exactly as given.
///
/// **The first octet is what tells the two answers apart.** A size the
/// engine accepts is handed to `std`, which streams the chunk, so the
/// octet arrives. A size the engine refuses is refused before any octet of
/// the chunk is read, so the read fails. An error code alone would say
/// nothing, because a peer that names a size larger than it sends is a
/// truncated transfer, and that fails too.
fn firstChunkOctet(size_line: []const u8) !u8 {
    const gpa = testing.allocator;
    const reply = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{s}\r\nabc",
        .{size_line},
    );
    defer gpa.free(reply);

    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{reply});
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    return body.takeByte();
}

test "a chunk size of ffffffffffffffff is refused and never overflows" {
    // **The finding this guard was written for.** `std.http.Reader` holds
    // the size in a `u64` and computes `chunk_len + 2 - n`. Zig adds
    // before it subtracts, so a size of `2^64-1` overflows the addition:
    // a panic in a checked build, and in a build without the check a
    // wrapped length that reads the rest of the connection as body.
    //
    // Sixteen octets from a peer chose between the two. The guard refuses
    // the size, so the transfer ends with an error and the process lives.
    try testing.expectError(error.ReadFailed, firstChunkOctet("ffffffffffffffff"));
    // The size one below it overflows the same addition, and is refused
    // the same way.
    try testing.expectError(error.ReadFailed, firstChunkOctet("fffffffffffffffe"));
}

test "a chunk size of ffffffffffffffff is refused when the body is discarded" {
    // **The same expression stands in the discarding half of `std`.**
    // `chunkedDiscardEndless` computes `chunk_len + 2 - n` as
    // `chunkedReadEndless` does, so a caller that throws the body away
    // reaches the same overflow. The guard is on both methods of the
    // transfer reader, and this is the second one.
    const gpa = testing.allocator;
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" ++
            "ffffffffffffffff\r\nabc",
    });
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    try testing.expectError(error.ReadFailed, body.discard(.unlimited));
}

test "a chunk size at chunk_size_max is read, and one above it is refused" {
    // The bound is curl's. Measured against curl 8.21.0: a first chunk of
    // `7fffffffffffffff` gives exit 18, a truncated transfer, so the size
    // was accepted, and `8000000000000000` gives exit 56 with
    // `* invalid chunk size: '8000000000000000'`.
    try testing.expectEqual(@as(u8, 'a'), try firstChunkOctet("7fffffffffffffff"));
    try testing.expectError(error.ReadFailed, firstChunkOctet("8000000000000000"));

    // The two lines above are the bound, and this one pins that they are
    // the bound the constant names.
    try testing.expectEqual(@as(u64, std.math.maxInt(i64)), chunk_size_max);
}

test "a chunk size field of more than chunk_size_digits_max octets is refused" {
    // **Leading zeroes are octets of the size field.** Without this bound
    // a peer would write the size that matters behind a long run of them
    // and push it past every window the guard can read, so the value
    // bound would never be tested. curl 8.21.0 answers a size field of 17
    // octets with exit 56 and `* chunk hex-length longer than 16`.
    //
    // Sixteen octets hold every value a `u64` can take, so a size field
    // this long is refused and a legal one never is.
    try testing.expectEqual(@as(u8, 'a'), try firstChunkOctet("0000000000000003"));
    try testing.expectError(error.ReadFailed, firstChunkOctet("00000000000000003"));

    // The refused size is a legal value, so it is the length of the field
    // that refused it and not the number it holds. Written short, the same
    // value is read.
    try testing.expectEqual(@as(u8, 'a'), try firstChunkOctet("3"));

    // And the padding does not let the value bound be walked past either.
    try testing.expectError(error.ReadFailed, firstChunkOctet("000000000000000000000000ffffffffffffffff"));
}

test "a chunk extension behind a size within the bound is left alone" {
    // The guard stops at the end of the size field, so the extensions
    // behind it are read by `std` as before. A long extension is not a
    // long size field.
    try testing.expectEqual(@as(u8, 'a'), try firstChunkOctet("3;name=value;other=\"quoted text\""));
}

test "an ordinary chunked transfer of several chunks with trailers still arrives" {
    // **The regression this whole change risks.** The guard runs in front
    // of every chunk size field of every chunked body, so a body of many
    // chunks crosses it many times. A guard that consumed an octet, or
    // that read the state wrongly at one of the three places a size field
    // can start, would break this.
    const gpa = testing.allocator;
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" ++
            "5\r\nfirst\r\n" ++
            "6\r\nsecond\r\n" ++
            "1\r\n.\r\n" ++
            "5;ext=1\r\nthird\r\n" ++
            "0\r\n" ++
            "X-Checksum: 1234\r\nX-Note: done\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    const contents = try getWholeBody(iface, url_text);
    defer gpa.free(contents);
    try testing.expectEqualStrings("firstsecond.third", contents);
}

test "a chunked gzip body of several chunks still decodes" {
    // **The composition the guard has to keep.** A content decoder pulls
    // from the transfer reader until its own buffer is full, so one read
    // by the caller crosses as many chunk size fields as the decoder
    // needs. The guard therefore sits on the transfer reader, where every
    // one of those reads passes it, and not on the reader the caller
    // holds, where only the first would.
    //
    // The member is cut into small chunks so the decoder has to cross
    // several size fields inside one read.
    const gpa = testing.allocator;
    const text = "compressed payload, long enough to be worth cutting up into many chunks";
    const member = try gzipAlloc(gpa, text);
    defer gpa.free(member);
    try testing.expect(member.len > 16);

    var framed: std.Io.Writer.Allocating = .init(gpa);
    defer framed.deinit();
    try framed.writer.writeAll(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n" ++
            "Connection: close\r\n\r\n",
    );
    var offset: usize = 0;
    while (offset < member.len) {
        const take = @min(@as(usize, 8), member.len - offset);
        try framed.writer.print("{x}\r\n", .{take});
        try framed.writer.writeAll(member[offset..][0..take]);
        try framed.writer.writeAll("\r\n");
        offset += take;
    }
    try framed.writer.writeAll("0\r\n\r\n");

    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{framed.written()});
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    const contents = try getWholeBodyCompressed(iface, url_text);
    defer gpa.free(contents);
    try testing.expectEqualStrings(text, contents);
}

// The two tests below pin that `Head.www_authenticate` reaches the front
// package. A digest retry cannot build a response without it, and nothing
// proved this engine could carry it at all before Task 9.

test "a 401 response's WWW-Authenticate header reaches the head" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqualStrings(
        "Digest realm=\"test\", nonce=\"abc\"",
        exchange.head().www_authenticate.?,
    );
}

test "the head reports the digest challenge, whatever order the server listed" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"first\"\r\n" ++
            "WWW-Authenticate: Digest realm=\"test\", nonce=\"abc\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqualStrings(
        "Digest realm=\"test\", nonce=\"abc\"",
        exchange.head().www_authenticate.?,
    );
    try testing.expectEqual(false, exchange.head().www_authenticate_oversize);
}

test "a WWW-Authenticate header too long to keep is reported, not silently dropped" {
    const test_server = @import("test_server.zig");
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

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqual(@as(?[]const u8, null), exchange.head().www_authenticate);
    try testing.expectEqual(true, exchange.head().www_authenticate_oversize);
}

test "a response with no WWW-Authenticate header reports null, not an empty string" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqual(@as(?[]const u8, null), exchange.head().www_authenticate);
}

test "a url with userinfo sends only the caller's authorization header" {
    // A `std.Uri` that carries userinfo used to become an
    // `authorization: Basic base64(user:password)` header of the engine's
    // own, beside the caller's: the cleartext password in reversible
    // base64, on every request, and two `Authorization` headers where RFC
    // 7235 allows one. `writeRequestHead` builds no such header, and
    // `openOnce` leaves the userinfo out of the `std.Uri` as well, so
    // neither half of that can come back on its own.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);
    try testing.expectEqualStrings("hunter2", url.password.?);

    // The credential the caller wants sent, whoever built it, rides the
    // one field that carries a credential. The url beside it still holds a
    // password, and none of it may reach the wire.
    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .secrets = &.{.{ .name = "Authorization", .value = "Digest username=\"bob\"" }},
        .redirects = .unfollowed,
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(head));
    try testing.expect(std.mem.indexOf(u8, head, "Digest username=\"bob\"") != null);
    // "Ym9iOmh1bnRlcjI=" is base64("bob:hunter2"), which is what the
    // leaked header carried.
    try testing.expect(std.mem.indexOf(u8, head, "Ym9iOmh1bnRlcjI=") == null);
    try testing.expect(std.mem.indexOf(u8, head, "hunter2") == null);
}

test "an authorization header among the ordinary headers is refused" {
    // A credential has one path through this engine. A second path is how
    // a credential ends up on a host the caller never named: `std` writes
    // `extra_headers` again on every hop of a redirect chain.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url = try zurl_core.url.parse("http://127.0.0.1:9/");

    const headers = [_]std.http.Header{.{ .name = "Authorization", .value = "Bearer caller-token" }};
    try testing.expectError(
        error.InvalidHeader,
        iface.open(.{ .method = .GET, .url = url, .headers = &headers, .redirects = .unfollowed }),
    );

    // The name is a field name, so case does not change what it means.
    const lower = [_]std.http.Header{.{ .name = "authorization", .value = "Bearer caller-token" }};
    try testing.expectError(
        error.InvalidHeader,
        iface.open(.{ .method = .GET, .url = url, .headers = &lower, .redirects = .unfollowed }),
    );

    // `Proxy-Authorization` is a different header, and it has its own
    // rule: this engine sends it nowhere. It used to reach the connect
    // attempt, and from there the origin server and every host a redirect
    // named.
    const proxy = [_]std.http.Header{.{ .name = "Proxy-Authorization", .value = "Basic x" }};
    try testing.expectError(
        error.InvalidHeader,
        iface.open(.{ .method = .GET, .url = url, .headers = &proxy, .redirects = .unfollowed }),
    );
}

test "every origin-bound and refused name is refused among the ordinary headers" {
    // Two waves closed this leak for one header name and left the next one
    // open. So this test reads `engine.origin_bound_headers` and
    // `engine.refused_headers` instead of naming a header: a name added to
    // either set is covered here the moment it is added.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    // Nothing listens on this port, so a request that gets past the header
    // check reports a connect failure. The two answers cannot be confused.
    const url = try zurl_core.url.parse("http://127.0.0.1:9/");

    inline for (engine.origin_bound_headers ++ engine.refused_headers) |name| {
        const headers = [_]std.http.Header{.{ .name = name, .value = "super-secret" }};
        try testing.expectError(
            error.InvalidHeader,
            iface.open(.{ .method = .GET, .url = url, .headers = &headers, .redirects = .unfollowed }),
        );

        // A field name has no case, so neither has the rule.
        var lower_buf: [name.len]u8 = undefined;
        const lower = [_]std.http.Header{.{
            .name = std.ascii.lowerString(&lower_buf, name),
            .value = "super-secret",
        }};
        try testing.expectError(
            error.InvalidHeader,
            iface.open(.{ .method = .GET, .url = url, .headers = &lower, .redirects = .unfollowed }),
        );

        // A longer name that starts with a refused one is a different
        // header, and it still travels. A rule written with
        // `startsWith` would swallow it.
        const note = [_]std.http.Header{.{ .name = name ++ "-Note", .value = "not a secret" }};
        try testing.expectError(
            error.CouldNotConnect,
            iface.open(.{ .method = .GET, .url = url, .headers = &note, .redirects = .unfollowed }),
        );
    }
}

test "a secret the origin-bound set does not name is refused" {
    // The secrets channel carries exactly `engine.origin_bound_headers`.
    // A name outside the set would get the withholding rule without ever
    // being written down as a secret, so the set would stop being the
    // whole truth about what zurl protects.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url = try zurl_core.url.parse("http://127.0.0.1:9/");

    const stowaway = [_]std.http.Header{.{ .name = "X-Session", .value = "super-secret" }};
    try testing.expectError(error.InvalidHeader, iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .secrets = &stowaway,
        .redirects = .unfollowed,
    }));

    // A refused name is refused in this channel too. It is not
    // origin-bound, so one rule covers both.
    const proxy = [_]std.http.Header{.{ .name = "Proxy-Authorization", .value = "Basic x" }};
    try testing.expectError(error.InvalidHeader, iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .secrets = &proxy,
        .redirects = .unfollowed,
    }));
}

test "a url with userinfo and no caller header sends no authorization at all" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://bob:hunter2@127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(head));
    try testing.expect(std.mem.indexOf(u8, head, "Ym9iOmh1bnRlcjI=") == null);
    // The host header still names the peer, with no userinfo in it.
    const expected_host = try std.fmt.allocPrint(testing.allocator, "127.0.0.1:{d}", .{server.port()});
    defer testing.allocator.free(expected_host);
    try testing.expect(std.mem.indexOf(u8, head, expected_host) != null);
}

test "a 304 answer is not treated as a redirect to resend without the credential" {
    // A `304` answers a conditional request, so it belongs to the caller
    // and no client follows one. `followableRedirect` holds that line. An
    // engine that resends on any 3xx threw the answer away and asked
    // again.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/cached", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .secrets = &.{.{ .name = "Authorization", .value = "Basic Ym9iOmh1bnRlcjI=" }},
        .redirects = .{ .follow = 3 },
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 304), exchange.head().status);
    try testing.expect(!exchange.head().credential_withheld);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "a 3xx with no location is not resent either" {
    // A resend exists to take the credential off a chain the engine is
    // about to follow. `std` cannot follow a redirect that names no
    // target, so there is no chain, and the answer belongs to the caller.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .secrets = &.{.{ .name = "Authorization", .value = "Basic Ym9iOmh1bnRlcjI=" }},
        .redirects = .{ .follow = 3 },
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 302), exchange.head().status);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "a followed redirect reports that the credential was withheld" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .secrets = &.{.{ .name = "Authorization", .value = "Basic Ym9iOmh1bnRlcjI=" }},
        .redirects = .{ .follow = 3 },
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    // The caller asked for a credential and got an answer built without
    // one. Nothing else in the response says so.
    try testing.expect(exchange.head().credential_withheld);
    try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(server.requestHead(1).?));
}

test "every secret reaches the first origin, and the resend carries none" {
    // The withholding rule is one rule over the whole set, not one rule
    // per header name. A wave that fixed `Authorization` alone left a
    // `Cookie` riding `extra_headers` to every host in the chain.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const ordinary = [_]std.http.Header{.{ .name = "X-Trace", .value = "1" }};
    const secrets = [_]std.http.Header{
        .{ .name = "Authorization", .value = "Basic Ym9iOmh1bnRlcjI=" },
        .{ .name = "Cookie", .value = "session=super-secret-session" },
    };
    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &ordinary,
        .secrets = &secrets,
        .redirects = .{ .follow = 3 },
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try testing.expect(exchange.head().credential_withheld);

    // One request carried both secrets, each exactly once, beside the
    // ordinary header.
    const first = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(first, "Authorization"));
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(first, "Cookie"));
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(first, "X-Trace"));

    // The resend that follows the chain carries the ordinary header and
    // neither secret.
    const resend = server.requestHead(1).?;
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(resend, "Authorization"));
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(resend, "Cookie"));
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(resend, "X-Trace"));
    try testing.expect(std.mem.indexOf(u8, resend, "super-secret-session") == null);

    // And so does every hop after it.
    const landed = server.requestHead(2).?;
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(landed, "Cookie"));
    try testing.expect(std.mem.indexOf(u8, landed, "super-secret-session") == null);
}

test "an oversize digest challenge takes a fitting basic challenge with it" {
    // The engine kept the `Basic` value and set the oversize flag for the
    // `Digest` value, and a caller that reads the flag only when there is
    // no challenge answered `Basic`. That sends the password in reversible
    // base64 to a server that had offered a scheme where it never travels.
    const test_server = @import("test_server.zig");
    const long_realm = "r" ** 1100;
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"small\"\r\n" ++
            "WWW-Authenticate: Digest realm=\"" ++ long_realm ++ "\", nonce=\"n\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 401), exchange.head().status);
    try testing.expectEqual(@as(?[]const u8, null), exchange.head().www_authenticate);
    try testing.expect(exchange.head().www_authenticate_oversize);
}

test "an escaped path and query reach the request line escaped once" {
    // `zurl_core.url.parse` leaves both percent-encoded, and
    // `std.Uri.Component.formatPath` escapes a `.raw` value again, so
    // "/a%20b" used to go out as "/a%2520b": another resource entirely.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/a%20b/c?x=%26y",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.startsWith(u8, head, "GET /a%20b/c?x=%26y HTTP/1.1\r\n"));
}

// The three tests below pin that a request header is data, not a
// programmer's promise. `writeRequestHead` writes every value verbatim,
// and the only check that ever stood in front of it was an assert against
// a CR or an LF, so in ReleaseFast a value of `a\r\nX-Injected: 1` used to
// put a second header of the peer's choosing on the wire.

test "a CRLF in a header value is an error, not an injected header" {
    // No server: the check runs before the engine opens a socket, so a
    // bad header never reaches the wire at all.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url = try zurl_core.url.parse("http://127.0.0.1:9/");

    const headers = [_]std.http.Header{.{ .name = "X-Evil", .value = "a\r\nX-Injected: 1" }};
    try testing.expectError(
        error.InvalidHeader,
        iface.open(.{ .method = .GET, .url = url, .headers = &headers, .redirects = .unfollowed }),
    );
}

test "a NUL in a header value, and a colon or a space in a name, are errors" {
    const url = try zurl_core.url.parse("http://127.0.0.1:9/");

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const rejected = [_]std.http.Header{
        .{ .name = "X-Nul", .value = "a\x00b" },
        .{ .name = "X-Bare-Lf", .value = "a\nb" },
        .{ .name = "X-Bare-Cr", .value = "a\rb" },
        .{ .name = "X-Colon:", .value = "ok" },
        .{ .name = "X Space", .value = "ok" },
        .{ .name = "X-Nul\x00", .value = "ok" },
        .{ .name = "", .value = "ok" },
    };
    for (rejected) |header| {
        const one = [_]std.http.Header{header};
        try testing.expectError(
            error.InvalidHeader,
            iface.open(.{ .method = .GET, .url = url, .headers = &one, .redirects = .unfollowed }),
        );
    }
}

test "a CRLF, an LF, or a NUL in the user agent is an error, not an injected header" {
    // `req.user_agent` reaches `std`'s `.override`, which writes
    // `prefix ++ value ++ "\r\n"` and checks nothing. It was the one
    // header value in this engine that went out unchecked, so
    // `evil/1\r\nX-Injected: yes` put a second header on the wire. No
    // server here: the check runs before the engine opens a socket.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url = try zurl_core.url.parse("http://127.0.0.1:9/");

    const rejected = [_][]const u8{
        "evil/1\r\nX-Injected: yes",
        "evil/1\rX-Injected: yes",
        "evil/1\nX-Injected: yes",
        "evil/1\x00",
    };
    for (rejected) |user_agent| {
        try testing.expectError(error.InvalidHeader, iface.open(.{
            .method = .GET,
            .url = url,
            .headers = &.{},
            .redirects = .unfollowed,
            .user_agent = user_agent,
        }));
    }
}

test "an empty user agent sends no user-agent header at all" {
    // `.override` with an empty value writes a bare `user-agent: ` line.
    // That names no agent, and curl with `-A ""` sends no such header.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
        .user_agent = "",
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "user-agent:") == null);
    try testing.expect(std.mem.indexOf(u8, head, "User-Agent:") == null);
}

test "an ordinary user agent still reaches the peer" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
        .user_agent = "zurl-test/1.0 (a b; c)",
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "user-agent: zurl-test/1.0 (a b; c)\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "X-Injected") == null);
}

test "a body-bearing method with no body goes out with no framing header" {
    // **This test replaces a refusal that is now false.** The engine used
    // to answer `POST`, `PUT`, and `PATCH` with
    // `error.RequestBodyUnsupported`, because it wrote no framing header
    // and the peer could not find the end of the request. That reason is
    // gone: `writeRequestHead` writes the framing from `Request.body`.
    //
    // A null body writes neither framing header, which is what curl
    // 8.21.0 does. Measured on a loopback listener:
    //
    // ```
    // curl -X POST http://127.0.0.1:PORT/x
    // POST /x HTTP/1.1
    // Host: 127.0.0.1:PORT
    // User-Agent: curl/8.21.0
    // Accept: */*
    // (blank line, no body)
    // ```
    //
    // RFC 9112 section 6 reads a request with neither header as one with
    // no body, so the peer finds the end of it at the blank line.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .POST,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.startsWith(u8, head, "POST / HTTP/1.1\r\n"));
    try testing.expectEqual(@as(usize, 0), test_server.TestServer.countHeaders(head, "content-length"));
    try testing.expectEqual(@as(usize, 0), test_server.TestServer.countHeaders(head, "transfer-encoding"));
    try testing.expectEqualStrings("", server.requestBody(0).?);
}

/// A request body over a fixed slice, for the tests below.
///
/// It is the shape `engine.Body` asks for and nothing more: a `*anyopaque`
/// and two `callconv(.c)` functions. `zurl.request_body.Memory` is the
/// same source for a real caller, and this package cannot import it.
const TestBody = struct {
    bytes: []const u8,
    at: usize = 0,
    /// How many times `rewind` was called, so a test can prove the source
    /// was put back before each send.
    rewinds: usize = 0,
    /// Whether the body can start over. A false here gives the source no
    /// `rewind` at all, which is the shape a pipe has.
    resendable: bool = true,
    /// Whether the length is announced. False sends the body chunked.
    known_length: bool = true,

    fn source(self: *TestBody) engine.Body {
        return .{
            .len = if (self.known_length) self.bytes.len else null,
            .ctx = self,
            .read = readImpl,
            .rewind = if (self.resendable) rewindImpl else null,
            .content_type = null,
        };
    }

    fn readImpl(ctx: *anyopaque, buffer: [*]u8, len: usize) callconv(.c) isize {
        const self: *TestBody = @ptrCast(@alignCast(ctx));
        const take = @min(len, self.bytes.len - self.at);
        @memcpy(buffer[0..take], self.bytes[self.at..][0..take]);
        self.at += take;
        return @intCast(take);
    }

    fn rewindImpl(ctx: *anyopaque) callconv(.c) bool {
        const self: *TestBody = @ptrCast(@alignCast(ctx));
        self.at = 0;
        self.rewinds += 1;
        return true;
    }
};

test "a body of known length goes out with a content-length and the exact bytes" {
    // Measured against curl 8.21.0: `curl -d 'a=1&b=2'` sends
    // `Content-Length: 7`, `Content-Type: application/x-www-form-urlencoded`,
    // and the seven bytes.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    var body: TestBody = .{ .bytes = "a=1&b=2" };
    var source = body.source();
    source.content_type = "application/x-www-form-urlencoded";

    const exchange = try iface.open(.{
        .method = .POST,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
        .body = source,
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.startsWith(u8, head, "POST /x HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "content-length: 7\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "content-type: application/x-www-form-urlencoded\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "transfer-encoding") == null);
    try testing.expectEqualStrings("a=1&b=2", server.requestBody(0).?);
}

test "a body of unknown length goes out chunked, and ends on a zero-size chunk" {
    // Measured against curl 8.21.0: `printf 'hello world\n' | curl -T -`
    // sends `Transfer-Encoding: chunked` and the chunks
    // `c\r\nhello world\n\r\n0\r\n\r\n`. zurl sends the same bytes and no
    // `Expect: 100-continue`. See `writeRequestBody` for why.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    var body: TestBody = .{ .bytes = "hello world\n", .known_length = false, .resendable = false };

    const exchange = try iface.open(.{
        .method = .PUT,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
        .body = body.source(),
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "transfer-encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "content-length") == null);
    try testing.expectEqualStrings("c\r\nhello world\n\r\n0\r\n\r\n", server.requestBody(0).?);
}

test "a redirect drops the body on a 301, a 302, and a 303, and keeps it on a 307 and a 308" {
    // **The whole rule, one status at a time.** Measured against curl
    // 8.21.0 with `-L -d 'a=1&b=2'` against a loopback listener that
    // answered each status. See `Exchange.rewriteHop` for the capture.
    const test_server = @import("test_server.zig");

    const Case = struct { status: []const u8, method: []const u8, body: []const u8 };
    const cases = [_]Case{
        .{ .status = "301 Moved Permanently", .method = "GET /moved", .body = "" },
        .{ .status = "302 Found", .method = "GET /moved", .body = "" },
        .{ .status = "303 See Other", .method = "GET /moved", .body = "" },
        .{ .status = "307 Temporary Redirect", .method = "POST /moved", .body = "a=1&b=2" },
        .{ .status = "308 Permanent Redirect", .method = "POST /moved", .body = "a=1&b=2" },
    };

    for (cases) |case| {
        var redirect_buffer: [128]u8 = undefined;
        const redirect = try std.fmt.bufPrint(
            &redirect_buffer,
            "HTTP/1.1 {s}\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{case.status},
        );

        var server: test_server.TestServer = undefined;
        try server.start(&.{
            redirect,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        });
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();
        const iface = http_engine.interface();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
        defer testing.allocator.free(url_text);
        const url = try zurl_core.url.parse(url_text);

        var body: TestBody = .{ .bytes = "a=1&b=2" };
        var source = body.source();
        source.content_type = "application/x-www-form-urlencoded";

        const exchange = try iface.open(.{
            .method = .POST,
            .url = url,
            .headers = &.{},
            .redirects = .{ .follow = 3 },
            .body = source,
        });
        defer exchange.close();

        // The first hop always carries the body.
        try testing.expectEqualStrings("a=1&b=2", server.requestBody(0).?);

        const second = server.requestHead(1).?;
        try testing.expect(std.mem.startsWith(u8, second, case.method));
        try testing.expectEqualStrings(case.body, server.requestBody(1).?);

        // A hop with no body carries no framing header and no content
        // type either. The content type describes a body, and there is
        // none.
        if (case.body.len == 0) {
            try testing.expect(std.mem.indexOf(u8, second, "content-length") == null);
            try testing.expect(std.mem.indexOf(u8, second, "content-type") == null);
        } else {
            try testing.expect(std.mem.indexOf(u8, second, "content-length: 7\r\n") != null);
            try testing.expect(std.mem.indexOf(u8, second, "content-type: application/x-www-form-urlencoded\r\n") != null);
        }
    }
}

test "RedirectMethods.keeps answers each flag for its own status, and false for every other" {
    // `Exchange.rewriteHop` asks this reader before it decides anything,
    // so the reader carries the narrowness of the three flags. A status
    // with no flag must read false whatever the struct holds. If it did
    // not, a `--post301` would reach a `307`, a `308`, and a `200` too,
    // and the user asked for one status.
    const none: engine.RedirectMethods = .{};
    const only_301: engine.RedirectMethods = .{ .post301 = true };
    const only_302: engine.RedirectMethods = .{ .post302 = true };
    const only_303: engine.RedirectMethods = .{ .post303 = true };
    const all: engine.RedirectMethods = .{ .post301 = true, .post302 = true, .post303 = true };

    // Each field answers its own status and no other.
    try testing.expect(only_301.keeps(301));
    try testing.expect(!only_301.keeps(302));
    try testing.expect(!only_301.keeps(303));

    try testing.expect(!only_302.keeps(301));
    try testing.expect(only_302.keeps(302));
    try testing.expect(!only_302.keeps(303));

    try testing.expect(!only_303.keeps(301));
    try testing.expect(!only_303.keeps(302));
    try testing.expect(only_303.keeps(303));

    // The default keeps nothing, which is what curl does with no flag.
    try testing.expect(!none.keeps(301));
    try testing.expect(!none.keeps(302));
    try testing.expect(!none.keeps(303));

    // A status outside the three reads false even with every flag set.
    // A `307` and a `308` keep the method for their own reason, and a
    // `200` is not a redirect at all.
    try testing.expect(!all.keeps(200));
    try testing.expect(!all.keeps(307));
    try testing.expect(!all.keeps(308));
    try testing.expect(!none.keeps(200));
    try testing.expect(!none.keeps(307));
    try testing.expect(!none.keeps(308));
}

test "a redirect_methods flag keeps the method, the body, and the content-length of its own status" {
    // This is `--post301`, `--post302`, and `--post303`, one status at a
    // time. Measured against curl 8.21.0 with `--post302 -L -d 'a=1&b=2'`
    // against a loopback listener that answered `302 Found`: the second
    // request was `POST /moved` with `Content-Length: 7` and the same
    // seven bytes. The default drops all three, which the test above this
    // one pins.
    const test_server = @import("test_server.zig");

    const Case = struct { status: []const u8, methods: engine.RedirectMethods };
    const cases = [_]Case{
        .{ .status = "301 Moved Permanently", .methods = .{ .post301 = true } },
        .{ .status = "302 Found", .methods = .{ .post302 = true } },
        .{ .status = "303 See Other", .methods = .{ .post303 = true } },
    };

    for (cases) |case| {
        var redirect_buffer: [128]u8 = undefined;
        const redirect = try std.fmt.bufPrint(
            &redirect_buffer,
            "HTTP/1.1 {s}\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{case.status},
        );

        var server: test_server.TestServer = undefined;
        try server.start(&.{
            redirect,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        });
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();
        const iface = http_engine.interface();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
        defer testing.allocator.free(url_text);
        const url = try zurl_core.url.parse(url_text);

        var body: TestBody = .{ .bytes = "a=1&b=2" };
        var source = body.source();
        source.content_type = "application/x-www-form-urlencoded";

        const exchange = try iface.open(.{
            .method = .POST,
            .url = url,
            .headers = &.{},
            .redirects = .{ .follow = 3 },
            .body = source,
            .redirect_methods = case.methods,
        });
        defer exchange.close();

        try testing.expectEqualStrings("a=1&b=2", server.requestBody(0).?);

        // The target sees the request the user wrote, method and bytes.
        const second = server.requestHead(1).?;
        try testing.expect(std.mem.startsWith(u8, second, "POST /moved"));
        try testing.expect(std.mem.indexOf(u8, second, "content-length: 7\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, second, "content-type: application/x-www-form-urlencoded\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, second, "transfer-encoding") == null);
        try testing.expectEqualStrings("a=1&b=2", server.requestBody(1).?);
    }
}

test "a flag for one status leaves the other two rewriting to GET" {
    // **The narrowness is the point.** curl has three flags and not one,
    // because a user who trusts a `301` need not trust a `302`. A flag
    // that turned all three on at once would widen what the user asked
    // for without saying so, and the body would reach a target the user
    // never named.
    const test_server = @import("test_server.zig");

    const Case = struct { status: []const u8, methods: engine.RedirectMethods };
    const cases = [_]Case{
        .{ .status = "302 Found", .methods = .{ .post301 = true } },
        .{ .status = "303 See Other", .methods = .{ .post301 = true } },
        .{ .status = "301 Moved Permanently", .methods = .{ .post302 = true } },
        .{ .status = "303 See Other", .methods = .{ .post302 = true } },
        .{ .status = "301 Moved Permanently", .methods = .{ .post303 = true } },
        .{ .status = "302 Found", .methods = .{ .post303 = true } },
    };

    for (cases) |case| {
        var redirect_buffer: [128]u8 = undefined;
        const redirect = try std.fmt.bufPrint(
            &redirect_buffer,
            "HTTP/1.1 {s}\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{case.status},
        );

        var server: test_server.TestServer = undefined;
        try server.start(&.{
            redirect,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        });
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();
        const iface = http_engine.interface();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
        defer testing.allocator.free(url_text);
        const url = try zurl_core.url.parse(url_text);

        var body: TestBody = .{ .bytes = "a=1&b=2" };
        var source = body.source();
        source.content_type = "application/x-www-form-urlencoded";

        const exchange = try iface.open(.{
            .method = .POST,
            .url = url,
            .headers = &.{},
            .redirects = .{ .follow = 3 },
            .body = source,
            .redirect_methods = case.methods,
        });
        defer exchange.close();

        // The status the flag does not name rewrites exactly as it does
        // with no flag at all.
        const second = server.requestHead(1).?;
        try testing.expect(std.mem.startsWith(u8, second, "GET /moved"));
        try testing.expect(std.mem.indexOf(u8, second, "content-length") == null);
        try testing.expect(std.mem.indexOf(u8, second, "content-type") == null);
        try testing.expectEqualStrings("", server.requestBody(1).?);
    }
}

test "post303 keeps a PUT, which a 303 otherwise rewrites" {
    // A `303` is the one status that rewrites every method and not a
    // `POST` alone. RFC 9110 section 15.4.4 asks for the target with a
    // `GET`, so a `PUT` becomes a `GET` and loses its body. `--post303`
    // turns that off for every method and not for `POST` alone, so the
    // `PUT` and its bytes reach the target.
    const test_server = @import("test_server.zig");

    const Case = struct { methods: engine.RedirectMethods, method: []const u8, body: []const u8 };
    const cases = [_]Case{
        .{ .methods = .{}, .method = "GET /moved", .body = "" },
        .{ .methods = .{ .post303 = true }, .method = "PUT /moved", .body = "a=1&b=2" },
    };

    for (cases) |case| {
        var server: test_server.TestServer = undefined;
        try server.start(&.{
            "HTTP/1.1 303 See Other\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        });
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();
        const iface = http_engine.interface();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
        defer testing.allocator.free(url_text);
        const url = try zurl_core.url.parse(url_text);

        var body: TestBody = .{ .bytes = "a=1&b=2" };

        const exchange = try iface.open(.{
            .method = .PUT,
            .url = url,
            .headers = &.{},
            .redirects = .{ .follow = 3 },
            .body = body.source(),
            .redirect_methods = case.methods,
        });
        defer exchange.close();

        try testing.expectEqualStrings("a=1&b=2", server.requestBody(0).?);

        const second = server.requestHead(1).?;
        try testing.expect(std.mem.startsWith(u8, second, case.method));
        try testing.expectEqualStrings(case.body, server.requestBody(1).?);
        if (case.body.len == 0) {
            try testing.expect(std.mem.indexOf(u8, second, "content-length") == null);
        } else {
            try testing.expect(std.mem.indexOf(u8, second, "content-length: 7\r\n") != null);
        }
    }
}

test "a 307 and a 308 keep the method and the body with every redirect_methods flag set" {
    // Neither status permits a rewrite, so neither has a flag and neither
    // reads one. This pins that the three flags reach the three statuses
    // they name and no fourth: a later change that let `--follow` widen
    // to a `307` would alter nothing here, and a change that let it alter
    // a `307` would show up as a `GET`.
    const test_server = @import("test_server.zig");

    const all: engine.RedirectMethods = .{ .post301 = true, .post302 = true, .post303 = true };
    const cases = [_][]const u8{ "307 Temporary Redirect", "308 Permanent Redirect" };

    for (cases) |status| {
        var redirect_buffer: [128]u8 = undefined;
        const redirect = try std.fmt.bufPrint(
            &redirect_buffer,
            "HTTP/1.1 {s}\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{status},
        );

        var server: test_server.TestServer = undefined;
        try server.start(&.{
            redirect,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        });
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();
        const iface = http_engine.interface();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
        defer testing.allocator.free(url_text);
        const url = try zurl_core.url.parse(url_text);

        var body: TestBody = .{ .bytes = "a=1&b=2" };
        var source = body.source();
        source.content_type = "application/x-www-form-urlencoded";

        const exchange = try iface.open(.{
            .method = .POST,
            .url = url,
            .headers = &.{},
            .redirects = .{ .follow = 3 },
            .body = source,
            .redirect_methods = all,
        });
        defer exchange.close();

        const second = server.requestHead(1).?;
        try testing.expect(std.mem.startsWith(u8, second, "POST /moved"));
        try testing.expect(std.mem.indexOf(u8, second, "content-length: 7\r\n") != null);
        try testing.expectEqualStrings("a=1&b=2", server.requestBody(1).?);
    }
}

test "a body that cannot start over refuses the second send of a 307 chain" {
    // A pipe has no way back to its first byte. A `307` asks for the same
    // request again, so the second send would carry whatever was left,
    // which the peer would act on as a whole request. Refuse it by name.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    var body: TestBody = .{ .bytes = "a=1", .known_length = false, .resendable = false };

    try testing.expectError(error.RequestBodyNotResendable, iface.open(.{
        .method = .POST,
        .url = url,
        .headers = &.{},
        .redirects = .{ .follow = 3 },
        .body = body.source(),
    }));

    // The first hop did go out. Only the second was refused.
    try testing.expect(server.requestHead(0) != null);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "a kept body that cannot start over refuses the second send of a 301 chain" {
    // A flag that keeps the body puts a `301` under the rule a `307`
    // already runs under. The source is a pipe, so it has no way back to
    // its first byte, and the second send would start in the middle of
    // the body the first send drained. The peer would read that middle as
    // a whole request. Refuse it by name instead.
    //
    // The name here is `error.RequestBodyNotResendable`, which is what
    // the engine answers. `zurl-http/errors.zig` maps it to
    // `error.WriteError` for the front package, so a caller sees the same
    // name it sees for a `307`.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 301 Moved Permanently\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    var body: TestBody = .{ .bytes = "a=1", .known_length = false, .resendable = false };

    try testing.expectError(error.RequestBodyNotResendable, iface.open(.{
        .method = .POST,
        .url = url,
        .headers = &.{},
        .redirects = .{ .follow = 3 },
        .body = body.source(),
        .redirect_methods = .{ .post301 = true },
    }));

    // The first hop did go out. Only the second was refused.
    try testing.expect(server.requestHead(0) != null);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "a body that cannot start over is fine on a 301 with no flag, because the body is dropped" {
    // The refusal above belongs to the kept body and not to the status.
    // With no flag the `301` drops the body, so there is nothing to send
    // a second time and the chain finishes. This pins that the new path
    // did not make every pipe through a `301` an error.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 301 Moved Permanently\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    var body: TestBody = .{ .bytes = "a=1", .known_length = false, .resendable = false };

    const exchange = try iface.open(.{
        .method = .POST,
        .url = url,
        .headers = &.{},
        .redirects = .{ .follow = 3 },
        .body = body.source(),
    });
    defer exchange.close();

    const second = server.requestHead(1).?;
    try testing.expect(std.mem.startsWith(u8, second, "GET /moved"));
    try testing.expectEqualStrings("", server.requestBody(1).?);
}

test "a rewindable body is put back before every send, the first one included" {
    // One rule covers the first send and each resend, so there is no "was
    // this the first" question to get wrong. A `307` chain of two hops
    // therefore rewinds twice.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    var body: TestBody = .{ .bytes = "a=1" };
    const exchange = try iface.open(.{
        .method = .POST,
        .url = url,
        .headers = &.{},
        .redirects = .{ .follow = 3 },
        .body = body.source(),
    });
    defer exchange.close();

    try testing.expectEqual(@as(usize, 2), body.rewinds);
    try testing.expectEqualStrings("a=1", server.requestBody(0).?);
    try testing.expectEqualStrings("a=1", server.requestBody(1).?);
}

test "a HEAD response reads no body, whatever content-length it announces" {
    // RFC 9110 section 9.3.2: the answer to a `HEAD` is the head the same
    // `GET` would have, and no content. A reader that trusted the
    // announced length would wait for bytes the peer never sends, until
    // the connection timed out. `-I` fills this path.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/x", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .HEAD,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    // The engine reports the body it is about to hand over, which is none,
    // and not the length of the body the peer is not sending.
    try testing.expectEqual(@as(?u64, 0), exchange.head().content_length);

    var buffer: [64]u8 = undefined;
    const reader = exchange.bodyReader(&buffer);
    const contents = try reader.allocRemaining(testing.allocator, .limited(64));
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("", contents);
}

test "a bodiless method still reaches the peer" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .HEAD,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    try testing.expect(std.mem.startsWith(u8, server.requestHead(0).?, "HEAD / HTTP/1.1\r\n"));
}

test "a caller cannot frame the request: Host and the framing headers are refused" {
    // Each of these is a valid token with a valid value, so
    // `validateHeaders` passed them, and `std` wrote them verbatim beside
    // its own `host:` and `connection:`. Two `Host` headers, or a
    // `Content-Length: 5` on a request with no body, is the classic
    // request-smuggling shape, and the connection is pooled.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const framing = [_]std.http.Header{
        .{ .name = "Host", .value = "evil.example" },
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Connection", .value = "close" },
        .{ .name = "Expect", .value = "100-continue" },
    };
    for (framing) |header| {
        const one = [_]std.http.Header{header};
        try testing.expectError(error.InvalidHeader, iface.open(.{
            .method = .GET,
            .url = url,
            .headers = &one,
            .redirects = .unfollowed,
        }));
    }

    // The refusal comes before any connect, so the server saw nothing.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "an ordinary header, tab included, still reaches the peer" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const headers = [_]std.http.Header{
        .{ .name = "X-Test", .value = "one\ttwo" },
        .{ .name = "Accept", .value = "*/*" },
    };
    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &headers, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
}

test "a control byte in a redirect target is refused before a second request goes out" {
    // `std.http.Client.Response.Head.parse` splits a head on CRLF, so a
    // bare LF survives inside a header value, and `std.Uri` puts no rule
    // on the characters of a path. The resolved target then reached the
    // next request line exactly as the server wrote it:
    //
    //     GET /a
    //     X-Injected-By-Server: yes HTTP/1.1
    //
    // RFC 9112 section 2.2 lets a recipient read that lone LF as the end
    // of a line, so a server or a proxy reads a header nobody asked for.
    // The transfer used to return 200 with no error and no diagnostic.
    //
    // **A NUL ends the same transfer one step earlier, and with a name of
    // its own.** `engine.refuseNulInHead` reads the whole head before
    // anything parses it, so the response never reaches the redirect rule
    // and the answer is `WeirdServerReply`, exit 8, which is the code curl
    // 8.21.0 gives the same head. A CR and an LF are legal octets of a
    // head, so only the redirect rule refuses those two, and the answer
    // stays `InvalidUrl`. Both ends are refusals and neither sends a
    // second request.
    const test_server = @import("test_server.zig");
    const Case = struct { control: []const u8, want: anyerror };
    const controls = [_]Case{
        .{ .control = "\n", .want = error.InvalidUrl },
        .{ .control = "\r", .want = error.InvalidUrl },
        .{ .control = "\x00", .want = error.WeirdServerReply },
    };
    var buf: [256]u8 = undefined;

    for (controls) |case| {
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

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();
        const iface = http_engine.interface();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
        defer testing.allocator.free(url_text);
        const url = try zurl_core.url.parse(url_text);

        try testing.expectError(
            case.want,
            iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 3 } }),
        );

        // The refusal comes before the next hop, so the injected request
        // line never reached a peer.
        try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
    }
}

test "an ordinary relative redirect still resolves against the url it came from" {
    // The guard above must not cost a real chain its target. `/deep/b`
    // and `c` both have to land where `std` used to put them.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /deep/b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: c?q=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 3 } });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try testing.expect(std.mem.startsWith(u8, server.requestHead(1).?, "GET /deep/b HTTP/1.1\r\n"));
    try testing.expect(std.mem.startsWith(u8, server.requestHead(2).?, "GET /deep/c?q=1 HTTP/1.1\r\n"));
}

test "a percent escape in a redirect target reaches the wire escaped, not decoded" {
    // The engine writes a target exactly as it reads it. `%20` names one
    // resource and a raw space names another, so decoding here would ask
    // for a resource the server never named.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /a%20b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 1 } });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try testing.expect(std.mem.startsWith(u8, server.requestHead(1).?, "GET /a%20b HTTP/1.1\r\n"));
}

test "a follow count of zero refuses the redirect rather than reporting it" {
    // `unfollowed` and `.{ .follow = 0 }` are two different answers, which
    // is why `Redirects` is a union and not a count. curl with no `-L`
    // prints the 302; curl with `--max-redirs 0 -L` fails.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    try testing.expectError(
        error.TooManyRedirects,
        iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 0 } }),
    );
}

test "head().location survives the body reader invalidating the response head" {
    // The head bytes sit in the connection's read buffer, and the transfer
    // reader reads over that same buffer, so every borrowed string in the
    // response head points at reused space after the first body read. The
    // engine takes its own copy of `Location` before that happens. Nothing
    // pinned it until now.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 12\r\n" ++
            "Connection: close\r\n\r\nbody-payload",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    try testing.expectEqualStrings("/elsewhere", exchange.head().location.?);

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("body-payload", contents);

    try testing.expectEqualStrings("/elsewhere", exchange.head().location.?);
}

test "the head log keeps one response head, byte for byte" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    const reply = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
        "Content-Length: 7\r\nConnection: close\r\n\r\npayload";
    try server.start(&.{reply});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    const head = exchange.head();
    // The status line through the empty line, CRLF endings kept, and no
    // body. This is what curl 8.21.0 writes for `-D`.
    const want = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
        "Content-Length: 7\r\nConnection: close\r\n\r\n";
    try testing.expectEqualStrings(want, head.headers.?);
    // One response, so the final block is the whole log.
    try testing.expectEqualStrings(want, head.final_headers.?);
    try testing.expect(!head.headers_oversize);
    // No redirect, so the engine reports no url of its own.
    try testing.expectEqual(@as(?[]const u8, null), head.effective_url);
}

test "the head log survives the body reader invalidating the response head" {
    // `readerDecompressing` calls `head.invalidateStrings()`, which sets
    // `head.bytes` to undefined. The log holds a copy taken before that,
    // and a caller writes the log after it has read the body.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .unfollowed });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("payload", contents);

    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n",
        exchange.head().headers.?,
    );
}

test "the head log holds one block for each hop, the way curl -D -L writes them" {
    // Measured against curl 8.21.0: `curl -D - -L` over a redirect writes
    // the head of every hop, in order, each ending with its own empty
    // line. It does not write the last one alone.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    const first = "HTTP/1.1 302 Found\r\nLocation: /body\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const second = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload";
    try server.start(&.{ first, second });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 1 } });
    defer exchange.close();

    const head = exchange.head();
    const second_head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\n";
    try testing.expectEqualStrings(first ++ second_head, head.headers.?);
    // A lookup by name must read the final block alone. The 302 above
    // carries no `Content-Type`, and the 200 does.
    try testing.expectEqualStrings(second_head, head.final_headers.?);
}

test "the effective url is the final hop of a chain, and null when there is no hop" {
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /one\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /two\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 5 } });
    defer exchange.close();

    const want = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/two", .{server.port()});
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, exchange.head().effective_url.?);
}

test "a response head carries no request header of the caller's" {
    // The log holds what the peer wrote back and nothing the caller sent.
    // A secret travels in `Request.secrets`, which never reaches a
    // response head, so no path leads from that channel to this text. A
    // `Set-Cookie` is the peer's own header and does belong here.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{.{ .name = "X-Ordinary", .value = "plain" }},
        .secrets = &.{
            .{ .name = "Authorization", .value = "Basic c2VjcmV0" },
            .{ .name = "Cookie", .value = "sent=by-the-caller" },
        },
        .redirects = .unfollowed,
    });
    defer exchange.close();

    const block = exchange.head().headers.?;
    // The request went out with all three. None of them is in the answer.
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(server.requestHead(0).?, "Authorization"));
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(server.requestHead(0).?, "Cookie"));
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(block, "Authorization"));
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(block, "Cookie"));
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(block, "X-Ordinary"));
    try testing.expect(std.mem.indexOf(u8, block, "c2VjcmV0") == null);
    // The peer's own cookie header stays. It is a response header.
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(block, "Set-Cookie"));
}

test "a head log at the byte bound is kept whole, and one byte past it is dropped" {
    // The log is bounded because a redirect chain has no bound of its own
    // that a byte count can be read off: `--max-redirs` takes any `u16`.
    // A chain past the bound loses every block, never the tail of one: a
    // file holding half a head reads exactly like a file holding a whole
    // one.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    // On the heap. `head_len_max` is 300 KiB, and a buffer that size in a
    // stack frame overruns the small stacks that some builds give a
    // thread.
    const head = "HTTP/1.1 200 OK\r\nX-Pad: pad\r\n\r\n";
    const filler = try testing.allocator.alloc(u8, head_len_max);
    defer testing.allocator.free(filler);
    @memcpy(filler[0..head.len], head);
    @memset(filler[head.len..], 'x');

    // `head_log_hops_min` full-size heads fill the log exactly.
    const hops = head_log_len / head_len_max;
    try testing.expectEqual(head_log_hops_min, hops);
    for (0..hops) |_| try http_engine.logHead(filler);
    try testing.expect(!http_engine.head_log_dropped);
    try testing.expectEqual(head_log_len, http_engine.loggedHeads().all.?.len);

    // One byte more does not fit, so the whole log goes and the engine
    // says it did.
    try http_engine.logHead("x");
    try testing.expect(http_engine.head_log_dropped);
    try testing.expectEqual(@as(?[]const u8, null), http_engine.loggedHeads().all);
    try testing.expectEqual(@as(?[]const u8, null), http_engine.loggedHeads().final);

    // A drop latches for the rest of the chain. A block appended after one
    // would otherwise read as the whole answer.
    try http_engine.logHead(filler);
    try testing.expect(http_engine.head_log_dropped);
    try testing.expectEqual(@as(?[]const u8, null), http_engine.loggedHeads().all);

    // A fresh chain starts with an empty log and no drop.
    http_engine.resetHeadLog();
    try testing.expect(!http_engine.head_log_dropped);
    try http_engine.logHead(filler);
    try testing.expectEqual(head_len_max, http_engine.loggedHeads().all.?.len);
}

test "the head log grows from a small first size and never past its cap" {
    // The cap is eight full-size heads, which is far more than an ordinary
    // chain needs. A log that allocated the cap on the first head would
    // charge every transfer for a chain it does not make.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    try testing.expectEqual(@as(?[]u8, null), http_engine.head_log);

    // An ordinary head takes the first size, and no more.
    try http_engine.logHead("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n");
    try testing.expectEqual(head_log_initial_len, http_engine.head_log.?.len);

    // A chain of full-size heads grows the log, and stops at the cap.
    const filler = try testing.allocator.alloc(u8, head_len_max);
    defer testing.allocator.free(filler);
    @memset(filler, 'x');

    http_engine.resetHeadLog();
    for (0..head_log_hops_min) |_| try http_engine.logHead(filler);
    try testing.expect(!http_engine.head_log_dropped);
    try testing.expectEqual(head_log_len, http_engine.head_log.?.len);
    try testing.expectEqual(head_log_len, http_engine.loggedHeads().all.?.len);
}

test "the head bounds keep one relationship" {
    // The comptime block beside these constants fails the build when the
    // relationship breaks. This test states the same relationship for a
    // reader, and pins the numbers that curl decides.
    comptime {
        // The line bound is reachable inside the head bound. A line bound
        // over the head bound could never fire.
        std.debug.assert(head_field_len_max <= head_len_max);
        // One legal head fits the chain log.
        std.debug.assert(head_log_len >= head_len_max);
        // The field bound is reachable inside the byte bound.
        std.debug.assert(head_fields_max * 4 <= head_len_max);
        // The line bound is curl's `CURL_MAX_HTTP_HEADER`.
        std.debug.assert(head_field_len_max == 100 * 1024);
        // The head bound is curl's `MAX_HTTP_RESP_HEADER_SIZE`.
        std.debug.assert(head_len_max == 300 * 1024);
        // The two bounds are not the same number. An earlier zurl kept one
        // bound for both jobs and refused heads curl accepts.
        std.debug.assert(head_field_len_max != head_len_max);
    }

    // The head bound reaches the connection, which is what enforces it.
    // `Engine.read_buffer_len` sizes the connection's read buffer and
    // fills `std.http.Reader.max_head_len`, so a constant nothing reads
    // would leave a much smaller buffer standing.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    try testing.expectEqual(head_len_max, http_engine.read_buffer_len);
}

test "a head larger than one response may be, or with too many fields, is dropped" {
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    // A head past `head_len_max` never reaches the log, because
    // `std.http.Reader.receiveHead` answers one with
    // `error.HttpHeadersOversize`. The bound is checked here anyway: the
    // log must never rest on a check that another file makes.
    //
    // On the heap. `head_len_max` is 300 KiB, and a buffer that size in a
    // stack frame overruns the small stacks that some builds give a
    // thread.
    const too_long = try testing.allocator.alloc(u8, head_len_max + 1);
    defer testing.allocator.free(too_long);
    @memset(too_long, 'x');
    try http_engine.logHead(too_long);
    try testing.expect(http_engine.head_log_dropped);
    try testing.expectEqual(@as(?[]const u8, null), http_engine.loggedHeads().all);

    http_engine.resetHeadLog();

    // A head of exactly `head_fields_max` lines is kept, and one line more
    // is dropped whole.
    const at_bound = try buildHead(testing.allocator, head_fields_max);
    defer testing.allocator.free(at_bound);
    try testing.expectEqual(head_fields_max, countFields(at_bound));
    try http_engine.logHead(at_bound);
    try testing.expect(!http_engine.head_log_dropped);
    try testing.expectEqualStrings(at_bound, http_engine.loggedHeads().all.?);

    http_engine.resetHeadLog();

    const past_bound = try buildHead(testing.allocator, head_fields_max + 1);
    defer testing.allocator.free(past_bound);
    try http_engine.logHead(past_bound);
    try testing.expect(http_engine.head_log_dropped);
    try testing.expectEqual(@as(?[]const u8, null), http_engine.loggedHeads().all);
}

/// A response head of `fields` header lines, for the bound tests. The
/// caller owns the result.
fn buildHead(allocator: std.mem.Allocator, fields: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "HTTP/1.1 200 OK\r\n");
    for (0..fields) |i| try out.print(allocator, "X-{d}: v\r\n", .{i});
    try out.appendSlice(allocator, "\r\n");
    return out.toOwnedSlice(allocator);
}

/// The value of the `host:` line in `head`, or null when it has none.
///
/// A test helper. It reads the line the engine wrote, so a test asserts on
/// the bytes a peer receives and never on a value the test built itself.
fn hostHeaderValue(head: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        if (!std.ascii.startsWithIgnoreCase(line, "host:")) continue;
        return std.mem.trim(u8, line["host:".len..], " \t");
    }
    return null;
}

test "the host line leaves out a port that is the default for the scheme" {
    // curl 8.21.0 sends `host: example.com` for `http://example.com:80/`
    // and for `http://example.com/` alike, and `host: example.com:8080`
    // only for a port that is not the default. `zurl_core.Url.port` is
    // never null, so this engine cannot tell a typed default port from one
    // that `url.parse` supplied, and it must write neither.
    const cases = [_]struct { url: []const u8, scheme: []const u8, host: []const u8 }{
        .{ .url = "http://github.com/", .scheme = "http", .host = "github.com" },
        .{ .url = "http://github.com:80/", .scheme = "http", .host = "github.com" },
        .{ .url = "https://github.com/", .scheme = "https", .host = "github.com" },
        .{ .url = "https://github.com:443/", .scheme = "https", .host = "github.com" },
        .{ .url = "http://example.com:8080/", .scheme = "http", .host = "example.com:8080" },
        .{ .url = "https://example.com:8443/", .scheme = "https", .host = "example.com:8443" },
        // A port that is the default of the other scheme stays: it is not
        // the default of this one.
        .{ .url = "https://example.com:80/", .scheme = "https", .host = "example.com:80" },
        .{ .url = "http://example.com:443/", .scheme = "http", .host = "example.com:443" },
    };

    for (cases) |case| {
        const url = try zurl_core.url.parse(case.url);
        var buffer: [512]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try writeRequestHead(&writer, .GET, requestUri(case.scheme, url), "zurl/0.1", &.{}, null, null, null, false);
        try testing.expectEqualStrings(case.host, hostHeaderValue(writer.buffered()).?);
    }
}

test "the host line puts the brackets of an IPv6 address back" {
    // `zurl_core.url.parse` takes the brackets off, so this engine holds
    // the host `::1` and the port 8080. Written plainly that reads
    // `host: ::1:8080`, which names no port a peer can find. curl 8.21.0
    // sends `host: [::1]:8080` for the same url.
    //
    // The default port still goes out on no line at all, the same as it
    // does for a name, so an address gets one rule and not two.
    const cases = [_]struct { url: []const u8, scheme: []const u8, host: []const u8 }{
        .{ .url = "http://[::1]:8080/x", .scheme = "http", .host = "[::1]:8080" },
        .{ .url = "http://[::1]/x", .scheme = "http", .host = "[::1]" },
        .{ .url = "http://[::1]:80/x", .scheme = "http", .host = "[::1]" },
        .{ .url = "https://[2606:4700:4700::1111]/", .scheme = "https", .host = "[2606:4700:4700::1111]" },
        .{ .url = "https://[2606:4700:4700::1111]:8443/", .scheme = "https", .host = "[2606:4700:4700::1111]:8443" },
        // An IPv4 address holds no colon, so it gets no brackets.
        .{ .url = "http://127.0.0.1:8080/x", .scheme = "http", .host = "127.0.0.1:8080" },
    };

    for (cases) |case| {
        const url = try zurl_core.url.parse(case.url);
        var buffer: [512]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try writeRequestHead(&writer, .GET, requestUri(case.scheme, url), "zurl/0.1", &.{}, null, null, null, false);
        try testing.expectEqualStrings(case.host, hostHeaderValue(writer.buffered()).?);
    }
}

test "a redirect chain keeps the brackets of an IPv6 address in its url text" {
    // The chain text is what `%{url_effective}` prints and what the next
    // hop parses back. A target written as `http://::1:8080/c` names the
    // host `::1:8080`, which parses as a host and a port nobody asked for,
    // so the brackets have to survive the round trip.
    const cases = [_]struct { base: []const u8, location: []const u8, want: []const u8 }{
        .{ .base = "http://[::1]:8080/a/b", .location = "/c", .want = "http://[::1]:8080/c" },
        .{ .base = "http://[::1]/a/b", .location = "/c", .want = "http://[::1]/c" },
        .{ .base = "http://example.com/", .location = "https://[2606:4700::1111]/x", .want = "https://[2606:4700::1111]/x" },
        .{ .base = "http://[::1]:8080/a", .location = "http://127.0.0.1:9/b", .want = "http://127.0.0.1:9/b" },
    };

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    for (cases) |case| {
        var chain: ?[]u8 = null;
        defer if (chain) |storage| testing.allocator.free(storage);
        const hop: engine.Request = .{
            .method = .GET,
            .url = try zurl_core.url.parse(case.base),
            .headers = &.{},
            .redirects = .{ .follow = 1 },
        };
        const target = try Exchange.nextTarget(&http_engine, &chain, hop, case.location);
        try testing.expectEqualStrings(case.want, target);
        // The text has to parse back to the address the base named, and
        // not to a host that swallowed the port.
        const parsed = try zurl_core.url.parse(target);
        try testing.expect(std.mem.indexOfScalar(u8, parsed.host, '[') == null);
    }
}

test "a peer that copies the host line into a redirect cannot move the next hop onto a cleartext port" {
    // The whole defect, with no socket. `http://github.com/` and
    // `http://wikipedia.org/` both failed here, and each step below is the
    // engine's own code.
    //
    // The engine wrote `host: github.com:80`. github.com copies that
    // authority into the `location:` of its redirect to `https`, so the
    // engine read back `https://github.com:80/` and opened a TLS session
    // on the port that speaks cleartext HTTP. The peer answered with a
    // status line, the TLS client read `HTTP/1.1 4` as a record header,
    // and the handshake stopped at `error.TlsRecordOverflow`, which a user
    // saw as `zurl: (35) SslConnectError: github.com`.
    const first = try zurl_core.url.parse("http://github.com/");

    // Step one: the head that goes out on the plain hop.
    var head_buffer: [512]u8 = undefined;
    var head_writer: std.Io.Writer = .fixed(&head_buffer);
    try writeRequestHead(&head_writer, .GET, requestUri("http", first), "zurl/0.1", &.{}, null, null, null, false);
    const host_value = hostHeaderValue(head_writer.buffered()).?;

    // Step two: the peer copies that value, byte for byte, into a
    // redirect that changes the scheme and nothing else. This is what
    // github.com and wikipedia.org answer, measured against curl 8.21.0
    // with `-H 'Host: github.com:80'`.
    var location_buffer: [128]u8 = undefined;
    const location = try std.fmt.bufPrint(&location_buffer, "https://{s}/", .{host_value});

    // Step three: the engine reads the next hop out of that location.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    var chain: ?[]u8 = null;
    defer if (chain) |storage| testing.allocator.free(storage);
    const hop: engine.Request = .{
        .method = .GET,
        .url = first,
        .headers = &.{},
        .redirects = .{ .follow = 1 },
    };
    const target = try Exchange.nextTarget(&http_engine, &chain, hop, location);

    try testing.expectEqualStrings("https://github.com/", target);
    const second = try zurl_core.url.parse(target);
    // 443 and never 80. This one number is the difference between a
    // handshake and `error.TlsRecordOverflow`.
    try testing.expectEqual(@as(?u16, 443), second.port);
}

test "a redirect may not move the transfer to a scheme that was not allowed" {
    // A `location:` is the server's text. A server that could name
    // `file` could read any file the user can read, and `-o` would hand
    // the contents back. curl 8.21.0 refuses the same target with exit 1
    // and `Protocol "file" is disabled (in redirect)`, because its
    // `--proto-redir` default is `http,https,ftp,ftps`.
    //
    // `UnsupportedProtocol` and not `InvalidUrl`: `file:///etc/passwd` is
    // a well-formed url, and the exit code has to be curl's 1 and not
    // curl's 3.
    const refused = [_][]const u8{
        "file:///etc/passwd",
        // The case rule holds, so a server cannot spell its way past it.
        "FILE:///etc/passwd",
        "file://localhost/etc/passwd",
        // A scheme nobody wrote down is refused too. This is an
        // allowlist, so the next protocol package arrives refused.
        "gopher://example.com/1",
        "data:text/plain,hello",
    };

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const base = try zurl_core.url.parse("http://example.com/start");
    const hop: engine.Request = .{
        .method = .GET,
        .url = base,
        .headers = &.{},
        .redirects = .{ .follow = 1 },
    };

    for (refused) |location| {
        var chain: ?[]u8 = null;
        defer if (chain) |storage| testing.allocator.free(storage);
        try testing.expectError(
            error.UnsupportedProtocol,
            Exchange.nextTarget(&http_engine, &chain, hop, location),
        );
    }

    // The schemes the rule does allow still resolve, so this refuses the
    // scheme change and nothing else.
    const allowed = [_][]const u8{ "https://example.com/x", "http://example.com/x", "/x" };
    for (allowed) |location| {
        var chain: ?[]u8 = null;
        defer if (chain) |storage| testing.allocator.free(storage);
        _ = try Exchange.nextTarget(&http_engine, &chain, hop, location);
    }
}

test "the redirect rule reads the request's own set, so --proto-redir can widen or narrow it" {
    // The set on the request is the whole rule. `--proto-redir` fills it,
    // and a request that names nothing gets
    // `zurl_core.redirect.redirect_default`, which the test above pins.
    // There is no second list here to disagree with that one.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const base = try zurl_core.url.parse("http://example.com/start");

    // `--proto-redir +file` is the user asking for the one target the
    // default refuses. curl 8.21.0 reads the same flag the same way: with
    // it, `curl -L` follows a redirect into `file` and prints the file.
    const opened: engine.Request = .{
        .method = .GET,
        .url = base,
        .headers = &.{},
        .redirects = .{ .follow = 1 },
        .redirect_protocols = try zurl_core.redirect.Set.parse(
            "+file",
            zurl_core.redirect.redirect_default,
        ),
    };
    {
        var chain: ?[]u8 = null;
        defer if (chain) |storage| testing.allocator.free(storage);
        // The rule says yes, and this engine still cannot open the
        // target, so the hop goes back to the caller with the url beside
        // it. `zurl.Client.perform` is what dispatches it.
        try testing.expectError(
            error.RedirectToOtherProtocol,
            Exchange.nextTarget(&http_engine, &chain, opened, "file://localhost/etc/hosts"),
        );
        try testing.expectEqualStrings(
            "file://localhost/etc/hosts",
            http_engine.redirectHandoff().?,
        );
    }
    {
        // And a target the same list refuses never becomes a handoff. The
        // two answers must not blur: one is "the user said no" and the
        // other is "the user said yes and this engine cannot".
        var chain: ?[]u8 = null;
        defer if (chain) |storage| testing.allocator.free(storage);
        const refused: engine.Request = .{
            .method = .GET,
            .url = base,
            .headers = &.{},
            .redirects = .{ .follow = 1 },
            .redirect_protocols = try zurl_core.redirect.Set.parse(
                "+ftp",
                zurl_core.redirect.redirect_default,
            ),
        };
        try testing.expectError(
            error.UnsupportedProtocol,
            Exchange.nextTarget(&http_engine, &chain, refused, "file://localhost/etc/hosts"),
        );
    }

    // `--proto-redir -all,http` is the other direction: a redirect to
    // `https` now fails where the default let it through.
    const narrowed: engine.Request = .{
        .method = .GET,
        .url = base,
        .headers = &.{},
        .redirects = .{ .follow = 1 },
        .redirect_protocols = try zurl_core.redirect.Set.parse(
            "-all,http",
            zurl_core.redirect.redirect_default,
        ),
    };
    {
        var chain: ?[]u8 = null;
        defer if (chain) |storage| testing.allocator.free(storage);
        try testing.expectError(
            error.UnsupportedProtocol,
            Exchange.nextTarget(&http_engine, &chain, narrowed, "https://example.com/x"),
        );
    }
    {
        var chain: ?[]u8 = null;
        defer if (chain) |storage| testing.allocator.free(storage);
        _ = try Exchange.nextTarget(&http_engine, &chain, narrowed, "http://example.com/x");
    }
}

test "a redirect into file:// fails the whole transfer over a real socket" {
    // The rule above, through the engine's own redirect loop. The chain
    // stops on the first hop, so the fixture answers once and the second
    // request never happens.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: file:///etc/passwd\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/start",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    try testing.expectError(error.UnsupportedProtocol, http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .{ .follow = 5 },
    }));

    // One connection and no more. A second head would mean the engine
    // opened something after it read the refused target.
    try testing.expect(server.requestHead(0) != null);
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(1));
}

test "a redirect keeps a port the peer named, and drops one that is the scheme default" {
    // The rule cuts both ways. A peer that names port 8443 means it, and
    // a chain that dropped that port would ask a different server. A port
    // that equals the scheme default carries no meaning at all: RFC 3986
    // section 6.2.3 reads such a url and a url with no port as one url.
    const cases = [_]struct { base: []const u8, location: []const u8, want: []const u8, port: u16 }{
        .{ .base = "http://github.com/", .location = "https://github.com:80/", .want = "https://github.com:80/", .port = 80 },
        .{ .base = "http://example.com/", .location = "https://example.com:8443/x", .want = "https://example.com:8443/x", .port = 8443 },
        .{ .base = "http://example.com/", .location = "https://example.com:443/x", .want = "https://example.com/x", .port = 443 },
        // A relative target keeps the base authority. The base port here
        // is the one `url.parse` filled in, not one a person wrote, so it
        // must not reach the chain text either.
        .{ .base = "http://example.com/a/b", .location = "/c", .want = "http://example.com/c", .port = 80 },
        .{ .base = "http://example.com:8080/a/b", .location = "/c", .want = "http://example.com:8080/c", .port = 8080 },
    };

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    for (cases) |case| {
        var chain: ?[]u8 = null;
        defer if (chain) |storage| testing.allocator.free(storage);
        const hop: engine.Request = .{
            .method = .GET,
            .url = try zurl_core.url.parse(case.base),
            .headers = &.{},
            .redirects = .{ .follow = 1 },
        };
        const target = try Exchange.nextTarget(&http_engine, &chain, hop, case.location);
        try testing.expectEqualStrings(case.want, target);
        try testing.expectEqual(@as(?u16, case.port), (try zurl_core.url.parse(target)).port);
    }
}

test "every hop of a chain on a port the caller named still carries that port" {
    // The fix must not take the port off a hop that needs it. A loopback
    // server listens on a port the OS assigns, which is never 80, so every
    // `host:` line in this chain has to spell it out. A build that dropped
    // the port here would send `host: 127.0.0.1` and reach a server that
    // answered on a different port.
    //
    // This is as far as the fixture reaches. The defect above needs a
    // peer on port 80 and a TLS server behind the redirect, and this
    // suite has neither: no test may open a socket to the network, and
    // there is no in-process TLS server in `std` or in `zurl-tls`. The two
    // tests above drive the same mechanism through the same functions with
    // no socket at all.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /one\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 2 } });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    const want_host = try std.fmt.allocPrint(testing.allocator, "127.0.0.1:{d}", .{server.port()});
    defer testing.allocator.free(want_host);
    try testing.expectEqualStrings(want_host, hostHeaderValue(server.requestHead(0).?).?);
    try testing.expectEqualStrings(want_host, hostHeaderValue(server.requestHead(1).?).?);

    const want_url = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/one", .{server.port()});
    defer testing.allocator.free(want_url);
    try testing.expectEqualStrings(want_url, exchange.head().effective_url.?);
}

test "a transfer to an IPv6 literal reaches the peer and sends a bracketed host line" {
    // Both halves of the addressing defect, over a real socket and no
    // network. `::1` is loopback.
    //
    // The dial used to stop at `std.Io.net.HostName.init`, which refuses
    // every colon, so `http://[::1]:PORT/` exited 3 with `InvalidUrl` and
    // never opened a socket at all. The `host:` line is read off the wire
    // here, and not from the parsed url, because the parsed url holds no
    // brackets and only the bytes the peer receives can say whether the
    // engine put them back.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    server.startOn("::1", &.{
        "HTTP/1.1 302 Found\r\nLocation: /one\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",
    }) catch |err| switch (err) {
        // A machine with the IPv6 stack turned off cannot bind `::1`. That
        // is the machine and not this engine.
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try std.fmt.allocPrint(testing.allocator, "http://[::1]:{d}/start", .{server.port()});
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);
    try testing.expectEqualStrings("::1", url.host);

    const exchange = try iface.open(.{ .method = .GET, .url = url, .headers = &.{}, .redirects = .{ .follow = 2 } });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    const want_host = try std.fmt.allocPrint(testing.allocator, "[::1]:{d}", .{server.port()});
    defer testing.allocator.free(want_host);
    try testing.expectEqualStrings(want_host, hostHeaderValue(server.requestHead(0).?).?);
    // The redirect hop too. The chain writes its own url text, and a hop
    // that lost the brackets would ask a host named `::1:PORT`.
    try testing.expectEqualStrings(want_host, hostHeaderValue(server.requestHead(1).?).?);

    const want_url = try std.fmt.allocPrint(testing.allocator, "http://[::1]:{d}/one", .{server.port()});
    defer testing.allocator.free(want_url);
    try testing.expectEqualStrings(want_url, exchange.head().effective_url.?);
}

test "countFields reads the raw head and stops at the end of what it was given" {
    // The status line is not a header line, and the empty line ends the
    // head. A block with no empty line, and one with no line ending at
    // all, must both answer rather than read past their own end.
    try testing.expectEqual(@as(usize, 0), countFields("HTTP/1.1 200 OK\r\n\r\n"));
    try testing.expectEqual(@as(usize, 2), countFields("HTTP/1.1 200 OK\r\na: b\r\nc: d\r\n\r\n"));
    try testing.expectEqual(@as(usize, 1), countFields("HTTP/1.1 200 OK\r\na: b\r\n"));
    try testing.expectEqual(@as(usize, 0), countFields("HTTP/1.1 200 OK"));
    try testing.expectEqual(@as(usize, 0), countFields(""));
}

// The connection reuse tests below all count accepts on the loopback
// fixture. That count is the only place reuse is visible: a request that
// went out on a connection the pool held looks the same on the wire as
// one that dialed. See `test_server.TestServer.accepts`.

/// A keep-alive body of `text`, framed by its own length.
///
/// It names no `connection:` header, so HTTP/1.1 keeps the connection, and
/// `TestServer` reads another request on it when the test lets it. Every
/// other scripted response in this file says `connection: close`.
fn keptAlive(comptime text: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ text.len, text },
    );
}

/// Sends one `GET` to `url_text`, reads the whole body, and closes the
/// exchange, which is what hands the connection to the pool.
///
/// The caller owns the body. Reading the body to its end is the point: an
/// exchange closed with the body half read must not be pooled, so a helper
/// that skipped the read would test the wrong path.
fn getWholeBody(iface: engine.Engine, url_text: []const u8) ![]u8 {
    const url = try zurl_core.url.parse(url_text);
    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    var body_buffer: [256]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    return body.allocRemaining(testing.allocator, .unlimited);
}

/// The same transfer `getWholeBody` runs, with the `--compressed` offer
/// made.
///
/// **A test of a compressed answer has to ask for one.** A request with no
/// `Accept-Encoding` header reads `identity` and nothing else, so a peer
/// that answers in gzip to such a request is `error.BadContentEncoding`.
/// The two helpers sit beside each other so a reader can see which side of
/// the offer a test is on.
fn getWholeBodyCompressed(iface: engine.Engine, url_text: []const u8) ![]u8 {
    const url = try zurl_core.url.parse(url_text);
    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
        .accept_encoding = true,
    });
    defer exchange.close();

    var body_buffer: [256]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    return body.allocRemaining(testing.allocator, .unlimited);
}

/// The `http://127.0.0.1:PORT/` text for `server`. The caller owns it.
fn loopbackUrl(server: *const test_server_mod.TestServer) ![]u8 {
    return std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/", .{server.port()});
}

const test_server_mod = @import("test_server.zig");
const h2_test_server = @import("h2_test_server.zig");

/// One transfer of the shared-pool tests, on an engine of its own.
///
/// **Each task holds its own engine, because a `zurl.Client` does.** That
/// is the shape `-Z` has: one client for each worker, and therefore one
/// engine, and therefore one pool unless the run hands them a shared one.
const PoolRun = struct {
    engine_state: *Engine,
    url_text: []const u8,
    version: engine.HttpVersion,
    body: ?[]u8 = null,
    status: u16 = 0,
    fault: ?anyerror = null,

    /// Sends one request and reads the whole body.
    ///
    /// It returns `void`, because `Io.concurrent` gives a task nowhere to
    /// report to. The fault is kept and the caller raises it.
    fn run(self: *PoolRun) void {
        const url = zurl_core.url.parse(self.url_text) catch |err| {
            self.fault = err;
            return;
        };
        const exchange = self.engine_state.interface().open(.{
            .method = .GET,
            .url = url,
            .headers = &.{},
            .redirects = .unfollowed,
            .http_version = self.version,
        }) catch |err| {
            self.fault = err;
            return;
        };
        defer exchange.close();
        self.status = exchange.head().status;
        var body_buffer: [256]u8 = undefined;
        const body = exchange.bodyReader(&body_buffer);
        self.body = body.allocRemaining(testing.allocator, .unlimited) catch |err| {
            self.fault = err;
            return;
        };
    }

    fn deinit(self: *PoolRun) void {
        if (self.body) |body| testing.allocator.free(body);
    }
};

test "two tasks that share a pool put their requests on one HTTP/2 connection" {
    // **This is the saving `-Z` was missing.** Two workers, two clients,
    // two engines, and one pool: the first worker dials and publishes the
    // connection, and the second joins it with a stream of its own rather
    // than pay a second dial and a second handshake.
    //
    // A single-threaded build cannot run two tasks at once, so it cannot
    // put this question. The fixture is loopback either way.
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var server: h2_test_server.H2TestServer = undefined;
    try server.startWith(&.{
        .{ .fields = &.{.{ .name = ":status", .value = "200" }}, .body = "alpha" },
        .{ .fields = &.{.{ .name = ":status", .value = "201" }}, .body = "beta" },
    }, .{ .requests_per_connection = 2 });
    defer server.stop();

    const pool = try createSharedPool(testing.allocator, testing.io);
    defer destroySharedPool(pool);

    var first_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer first_engine.deinit();
    try first_engine.joinSharedPool(pool);

    var second_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer second_engine.deinit();
    try second_engine.joinSharedPool(pool);

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    // The fixture speaks HTTP/2 over cleartext and offers no ALPN, so the
    // flag is the whole of the choice. RFC 9113 section 3.3, and this is
    // `--http2-prior-knowledge`.
    var first: PoolRun = .{
        .engine_state = &first_engine,
        .url_text = url_text,
        .version = .prior_knowledge,
    };
    defer first.deinit();
    var second: PoolRun = .{
        .engine_state = &second_engine,
        .url_text = url_text,
        .version = .prior_knowledge,
    };
    defer second.deinit();

    var future = try testing.io.concurrent(PoolRun.run, .{&second});
    PoolRun.run(&first);
    future.await(testing.io);

    if (first.fault) |err| return err;
    if (second.fault) |err| return err;

    // Which task got which answer turns on the race, so the check is that
    // each one read the body that belongs to the status it got.
    for ([_]*const PoolRun{ &first, &second }) |each| {
        switch (each.status) {
            200 => try testing.expectEqualStrings("alpha", each.body.?),
            201 => try testing.expectEqualStrings("beta", each.body.?),
            else => return error.UnexpectedStatus,
        }
    }
    try testing.expect(first.status != second.status);

    // **One accept.** This is the whole number the change is about. Before
    // it, two engines meant two pools and this was two.
    try testing.expectEqual(@as(usize, 1), server.accepts());
}

test "only a hop that could reach HTTP/2 waits for another task's dial" {
    // **This is what keeps HTTP/1.1 exactly as it was.** A shared pool
    // holds a task back while another task opens a connection to the same
    // origin, because that connection may carry a stream for both. An
    // HTTP/1.1 connection carries one request at a time, so a hop that can
    // never reach HTTP/2 must dial at once and never wait.
    //
    // The offer is read and not the answer, because the answer does not
    // exist yet: this runs before any handshake of this task.
    var req: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
    };

    // A TLS hop with the default offer names `h2` first, so it may.
    req.http_version = .any;
    try testing.expect(Exchange.mayMultiplex(req, .tls));
    // And so does `--http2`.
    req.http_version = .http_2;
    try testing.expect(Exchange.mayMultiplex(req, .tls));
    // `--http1.1` offers `http/1.1` alone, so the peer cannot choose `h2`.
    req.http_version = .http_1_1;
    try testing.expect(!Exchange.mayMultiplex(req, .tls));
    // `--no-alpn` sends no offer at all, whatever the version flag says.
    req.http_version = .any;
    req.no_alpn = true;
    try testing.expect(!Exchange.mayMultiplex(req, .tls));
    req.no_alpn = false;

    // A cleartext hop has no ALPN, so the default and `--http2` both stay
    // on HTTP/1.1 here. The `Upgrade: h2c` stream of `--http2` belongs to
    // the one request that carried the offer and is never published.
    req.http_version = .any;
    try testing.expect(!Exchange.mayMultiplex(req, .plain));
    req.http_version = .http_2;
    try testing.expect(!Exchange.mayMultiplex(req, .plain));

    // `--http2-prior-knowledge` speaks HTTP/2 with no offer at all, over
    // TLS and over cleartext both. RFC 9113 section 3.3.
    req.http_version = .prior_knowledge;
    try testing.expect(Exchange.mayMultiplex(req, .plain));
    try testing.expect(Exchange.mayMultiplex(req, .tls));

    // And no HTTP/3 flag reaches this at all, because `openOnce` ends a
    // QUIC hop before it dials. Reading them as "no" is the safe answer.
    req.http_version = .http_3;
    try testing.expect(!Exchange.mayMultiplex(req, .tls));
    req.http_version = .http_3_only;
    try testing.expect(!Exchange.mayMultiplex(req, .tls));
}

test "a pool records the origin one task is dialing, and gives the record back" {
    // The record is what makes one connection out of eight: seven workers
    // wait for it rather than open seven of their own. A record left
    // behind would make every later request to that origin wait for a dial
    // that already ended, so `clearDialing` is as load-bearing as
    // `markDialing`.
    const pool = try Pool.create(testing.allocator, testing.io);
    defer pool.destroy();

    const req: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
    };
    const dial: engine.DialTarget = .{ .host = "example.com", .port = 443, .overridden = false };
    const one = Origin.init(.tls, "example.com", 443, dial, null, req, no_trust).?;
    const other_dial: engine.DialTarget = .{ .host = "other.test", .port = 443, .overridden = false };
    const two = Origin.init(.tls, "other.test", 443, other_dial, null, req, no_trust).?;

    try testing.expect(!pool.isDialing(&one));
    try testing.expect(pool.markDialing(&one));
    try testing.expect(pool.isDialing(&one));
    // Another origin is not this one, so a task for it never waits here.
    try testing.expect(!pool.isDialing(&two));

    pool.clearDialing(&one);
    try testing.expect(!pool.isDialing(&one));

    // **A full table costs a connection and never a stall.** The task that
    // found no room dials with no record, and the tasks behind it dial too
    // rather than wait for a record that nobody will clear.
    var filled: usize = 0;
    while (filled < pool_dialing_max) : (filled += 1) {
        var each = one;
        each.port = @intCast(1000 + filled);
        try testing.expect(pool.markDialing(&each));
    }
    try testing.expect(!pool.markDialing(&two));
    try testing.expect(!pool.isDialing(&two));

    // Every record goes back, and the table empties in any order.
    filled = pool_dialing_max;
    while (filled > 0) {
        filled -= 1;
        var each = one;
        each.port = @intCast(1000 + filled);
        pool.clearDialing(&each);
    }
    try testing.expectEqual(@as(usize, 0), pool.dialing_len);
}

test "a shared pool serves a second request on the connection the first left" {
    // The plain pool rule, over two engines. A connection one engine put
    // back must answer the other engine's request for the same origin, or
    // sharing a pool buys nothing for a run that is not parallel.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(
        &.{ keptAlive("first"), keptAlive("second") },
        .{ .responses_per_connection = null },
    );
    defer server.stop();

    const pool = try createSharedPool(testing.allocator, testing.io);
    defer destroySharedPool(pool);

    var first_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer first_engine.deinit();
    try first_engine.joinSharedPool(pool);

    var second_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer second_engine.deinit();
    try second_engine.joinSharedPool(pool);

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const first = try getWholeBody(first_engine.interface(), url_text);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("first", first);

    const second = try getWholeBody(second_engine.interface(), url_text);
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("second", second);

    try testing.expectEqual(@as(usize, 1), server.accepts());
}

test "a pool an engine already used cannot be shared" {
    // A connection this engine opened sits in the pool it had, so joining
    // another one would leave that connection with nobody to close it.
    // The call is refused rather than half done.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{keptAlive("body")}, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);
    const body = try getWholeBody(http_engine.interface(), url_text);
    defer testing.allocator.free(body);

    const pool = try createSharedPool(testing.allocator, testing.io);
    defer destroySharedPool(pool);
    try testing.expectError(error.PoolInUse, http_engine.joinSharedPool(pool));

    // And a second join is refused too, so an engine holds one pool and
    // gives back exactly one hold at `deinit`.
    var fresh: Engine = .init(testing.allocator, testing.io, .{});
    defer fresh.deinit();
    try fresh.joinSharedPool(pool);
    try testing.expectError(error.PoolInUse, fresh.joinSharedPool(pool));
}

test "a connection verified against other trust roots is never reused" {
    // **A certificate is checked once, at the handshake.** Nothing reads
    // the chain back off an open socket, so a pooled connection carries
    // the roots of the transfer that opened it for the rest of its life.
    // A shared pool holds connections that several clients opened, so the
    // roots have to be in the key.
    const req: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
    };
    const dial: engine.DialTarget = .{ .host = "example.com", .port = 443, .overridden = false };

    var other_trust: [std.crypto.hash.sha2.Sha256.digest_length]u8 = @splat(0);
    other_trust[0] = 1;

    const default_roots = Origin.init(.tls, "example.com", 443, dial, null, req, no_trust).?;
    const other_roots = Origin.init(.tls, "example.com", 443, dial, null, req, other_trust).?;

    try testing.expect(!default_roots.eql(&other_roots));
    try testing.expect(!other_roots.eql(&default_roots));
    // And two requests that named the same roots do share one socket,
    // which is what keeps the pool useful at all.
    try testing.expect(default_roots.eql(
        &Origin.init(.tls, "example.com", 443, dial, null, req, no_trust).?,
    ));
}

test "two requests to one origin travel on one connection" {
    // The defect this closes: every request dialed, and every `https`
    // request handshook, however many requests one command line made to
    // one host.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(
        &.{ keptAlive("first"), keptAlive("second") },
        .{ .responses_per_connection = null },
    );
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const first = try getWholeBody(iface, url_text);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("first", first);

    const second = try getWholeBody(iface, url_text);
    defer testing.allocator.free(second);
    // The second body, and not the first one again, so the connection was
    // at the start of the second response and not somewhere inside the
    // first.
    try testing.expectEqualStrings("second", second);

    try testing.expectEqual(@as(usize, 1), server.accepts());
}

/// One gzip member over `text`, for a test of a compressed answer.
///
/// The caller owns what comes back. `Compress.init` asserts the output
/// holds more than eight octets, so the buffer starts with room.
fn gzipAlloc(gpa: std.mem.Allocator, text: []const u8) ![]u8 {
    var packed_body: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    errdefer packed_body.deinit();
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var deflate = try std.compress.flate.Compress.init(&packed_body.writer, window, .gzip, .default);
    try deflate.writer.writeAll(text);
    try deflate.finish();
    return packed_body.toOwnedSlice();
}

test "a chunked gzip body keeps the connection" {
    // **A content decoder ends at the end of its own stream.** `gzip`
    // stops at the last octet of the compressed member and asks the
    // transfer reader for nothing more, so the terminating chunk stayed on
    // the socket, `std.http.Reader.state` stayed away from `ready`, and
    // `reusable` closed a connection the peer was ready to serve again.
    //
    // `h2.Exchange.finishFraming` closes the same defect over
    // `END_STREAM`, where it cost a TLS handshake for every request to a
    // host that answers in that shape.
    const gpa = testing.allocator;
    const member = try gzipAlloc(gpa, "compressed payload");
    defer gpa.free(member);
    const reply = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" ++
            "{x}\r\n{s}\r\n0\r\n\r\n",
        .{ member.len, member },
    );
    defer gpa.free(reply);

    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{ reply, reply }, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    const first = try getWholeBodyCompressed(iface, url_text);
    defer gpa.free(first);
    try testing.expectEqualStrings("compressed payload", first);
    const second = try getWholeBodyCompressed(iface, url_text);
    defer gpa.free(second);
    // The second body, and not the first one again, so the connection was
    // at the start of the second response.
    try testing.expectEqualStrings("compressed payload", second);
    try testing.expectEqual(@as(usize, 1), server.accepts());
}

test "octets after the gzip member stay unread, and the connection goes" {
    // **The end of a content stream is not a promise that the peer sent
    // nothing else.** A peer that writes a further chunk after the
    // compressed member disagrees with its own content encoding, and the
    // decoder never reads it. The octets stay where they are, the state
    // stays away from `ready`, and the connection is closed rather than
    // pooled: a pooled connection with unread octets would hand them to
    // the next request.
    const gpa = testing.allocator;
    const member = try gzipAlloc(gpa, "compressed payload");
    defer gpa.free(member);
    const reply = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" ++
            "{x}\r\n{s}\r\n10\r\nAAAAAAAAAAAAAAAA\r\n0\r\n\r\n",
        .{ member.len, member },
    );
    defer gpa.free(reply);

    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{ reply, reply }, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    const first = try getWholeBodyCompressed(iface, url_text);
    defer gpa.free(first);
    try testing.expectEqualStrings("compressed payload", first);
    const second = try getWholeBodyCompressed(iface, url_text);
    defer gpa.free(second);
    try testing.expectEqualStrings("compressed payload", second);
    try testing.expectEqual(@as(usize, 2), server.accepts());
}

test "a chunked gzip body abandoned part way through still closes the connection" {
    // The rule that reusing a compressed answer must not weaken.
    // `finishFraming` runs only where the content stream ended, so a
    // caller that stopped part way through leaves the transfer open and
    // the connection goes.
    //
    // The payload is larger than `transfer_buffer_len` and it does not
    // compress, so the member does not arrive whole in one read and the
    // octets the caller abandoned really are still on the socket.
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(payload);
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    prng.random().bytes(payload);

    const member = try gzipAlloc(gpa, payload);
    defer gpa.free(member);
    try testing.expect(member.len > transfer_buffer_len);

    const first_reply = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" ++
            "{x}\r\n{s}\r\n0\r\n\r\n",
        .{ member.len, member },
    );
    defer gpa.free(first_reply);

    var server: test_server_mod.TestServer = undefined;
    try server.startWith(
        &.{ first_reply, keptAlive("second") },
        .{ .responses_per_connection = null },
    );
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    {
        const url = try zurl_core.url.parse(url_text);
        const exchange = try iface.open(.{
            .method = .GET,
            .url = url,
            .headers = &.{},
            .redirects = .unfollowed,
            // The offer, so the gzip answer below is one this request
            // asked for. See `getWholeBodyCompressed`.
            .accept_encoding = true,
        });
        defer exchange.close();
        var body_buffer: [256]u8 = undefined;
        const body = exchange.bodyReader(&body_buffer);
        var taken: [4]u8 = undefined;
        try body.readSliceAll(&taken);
        try testing.expectEqualSlices(u8, payload[0..4], &taken);
    }

    const second = try getWholeBody(iface, url_text);
    defer gpa.free(second);
    // The second response, and not the tail of the first one.
    try testing.expectEqualStrings("second", second);
    try testing.expectEqual(@as(usize, 2), server.accepts());
}

test "a request with no offer writes no accept-encoding header at all" {
    // **The default, read off the wire.** Measured against curl 8.21.0 on
    // a loopback listener, a plain `curl http://127.0.0.1:PORT/path`
    // writes the request line, `Host`, `User-Agent`, and `Accept`, and no
    // `Accept-Encoding`. This engine wrote `accept-encoding: gzip,
    // deflate` on every request, so a server could compress for zurl where
    // it sent curl the plain body.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const body = try getWholeBody(http_engine.interface(), url_text);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("ok", body);

    const sent = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 0), test_server_mod.countHeaders(sent, "accept-encoding"));
}

test "an offer writes the header curl writes, with br struck out" {
    // The other half. `--compressed` reaches the engine as
    // `Request.accept_encoding`, and one header goes out.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const body = try getWholeBodyCompressed(http_engine.interface(), url_text);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("ok", body);

    const sent = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server_mod.countHeaders(sent, "accept-encoding"));
    try testing.expect(std.mem.indexOf(
        u8,
        sent,
        "accept-encoding: " ++ accept_encoding_value ++ "\r\n",
    ) != null);
}

test "an unsolicited gzip body reaches the caller undecoded" {
    // **A request that asked for no decoding gets the peer's own
    // octets.** Measured against curl 8.21.0 on a loopback listener: a
    // plain `curl -o file` answered `Content-Encoding: gzip` wrote the
    // compressed member out and exited 0. Real servers send an unsolicited
    // `Content-Encoding`, and refusing it broke commands that work under
    // curl.
    //
    // `body_decoded` is false with it, so `Content-Length` describes the
    // octets the caller really reads.
    const gpa = testing.allocator;
    const member = try gzipAlloc(gpa, "compressed payload");
    defer gpa.free(member);
    const reply = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ member.len, member },
    );
    defer gpa.free(reply);

    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{reply});
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    const url = try zurl_core.url.parse(url_text);
    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    const head = exchange.head();
    try testing.expect(!head.body_decoded);
    try testing.expectEqual(@as(?u64, member.len), head.content_length);

    var body_buffer: [256]u8 = undefined;
    const body = try exchange.bodyReader(&body_buffer).allocRemaining(gpa, .unlimited);
    defer gpa.free(body);
    // The member itself, not the 18 octets it decodes to.
    try testing.expectEqualSlices(u8, member, body);
}

test "a zstd body is decoded when the request offered zstd" {
    // **The coding `--compressed` adds that curl also offers.**
    // `std.compress.zstd` ships a decoder, so this needed no new
    // dependency, which is the whole point: zurl carries no C library
    // beyond libc.
    const gpa = testing.allocator;
    const frame = try test_server_mod.zstdFrame(gpa, &.{ "zstd ", "payload" }, &.{});
    defer gpa.free(frame);

    const reply = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ frame.len, frame },
    );
    defer gpa.free(reply);

    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{reply});
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    const body = try getWholeBodyCompressed(http_engine.interface(), url_text);
    defer gpa.free(body);
    try testing.expectEqualStrings("zstd payload", body);
}

test "a zstd body with no offer is passed through, like any other coding" {
    // The rule the gzip test above holds, for the coding this change
    // added. Nothing about zstd is special: the offer decides decoding,
    // and without one the frame goes to the caller as it arrived. No zstd
    // window is taken either, so an unsolicited zstd answer costs no
    // memory.
    const gpa = testing.allocator;
    const frame = try test_server_mod.zstdFrame(gpa, &.{"payload"}, &.{});
    defer gpa.free(frame);

    const reply = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ frame.len, frame },
    );
    defer gpa.free(reply);

    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{reply});
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    const body = try getWholeBody(http_engine.interface(), url_text);
    defer gpa.free(body);
    try testing.expectEqualSlices(u8, frame, body);
}

test "a coding std has no enumerator for still yields a head, and passes through" {
    // **The head `std` refuses, and the reason `h1` used to answer exit 26
    // for it.** `std.http.Client.Response.Head.parse` returns
    // `error.HttpContentEncodingUnsupported` for `br` and gives back no
    // head at all, so the status and the framing went with it.
    // `parseRefusedHead` reads the head anyway.
    //
    // Measured against curl 8.21.0: a plain `curl` answered
    // `Content-Encoding: br` wrote the octets out and exited 0.
    const gpa = testing.allocator;
    for ([_][]const u8{ "br", "gzip, br", "exotic" }) |coding| {
        const reply = try std.fmt.allocPrint(
            gpa,
            "HTTP/1.1 203 Non-Authoritative Information\r\nContent-Encoding: {s}\r\n" ++
                "Content-Length: 4\r\nConnection: close\r\n\r\nABCD",
            .{coding},
        );
        defer gpa.free(reply);

        var server: test_server_mod.TestServer = undefined;
        try server.start(&.{reply});
        defer server.stop();

        var http_engine: Engine = .init(gpa, testing.io, .{});
        defer http_engine.deinit();

        const url_text = try loopbackUrl(&server);
        defer gpa.free(url_text);

        const url = try zurl_core.url.parse(url_text);
        const exchange = try http_engine.interface().open(.{
            .method = .GET,
            .url = url,
            .headers = &.{},
            .redirects = .unfollowed,
        });
        defer exchange.close();

        // The head really was read: the status and the framing came back,
        // not a default.
        const head = exchange.head();
        try testing.expectEqual(@as(u16, 203), head.status);
        try testing.expectEqual(@as(?u64, 4), head.content_length);
        try testing.expect(!head.body_decoded);

        var body_buffer: [64]u8 = undefined;
        const body = try exchange.bodyReader(&body_buffer).allocRemaining(gpa, .unlimited);
        defer gpa.free(body);
        try testing.expectEqualStrings("ABCD", body);

        // **And the header log shows what the server wrote.**
        // `parseRefusedHead` hides the field from `std` by overwriting one
        // octet of its name in a copy, then puts that octet back, so
        // nothing a user reads through `-D` was changed.
        const logged = http_engine.loggedHeads().final.?;
        const line = try std.fmt.allocPrint(gpa, "Content-Encoding: {s}\r\n", .{coding});
        defer gpa.free(line);
        try testing.expect(std.mem.indexOf(u8, logged, line) != null);
    }
}

test "a coding with no decoder is refused where the request asked to decode" {
    // **The other half: `--compressed` promises the body, and a coding
    // this build cannot decode breaks that promise.** Measured against
    // curl 8.21.0, `curl --compressed` answered in a coding it has no
    // decoder for exits 61. `br` is to zurl what that coding is to curl,
    // and a curl built without brotli answers 61 for `br` too.
    //
    // This is also why zurl does not advertise `br`: a client that asks
    // for a coding it cannot read asks a peer for octets it must then
    // refuse, so a transfer that would have worked fails.
    const gpa = testing.allocator;
    for ([_][]const u8{ "br", "gzip, br", "exotic", "compress" }) |coding| {
        const reply = try std.fmt.allocPrint(
            gpa,
            "HTTP/1.1 200 OK\r\nContent-Encoding: {s}\r\nContent-Length: 4\r\n" ++
                "Connection: close\r\n\r\nABCD",
            .{coding},
        );
        defer gpa.free(reply);

        var server: test_server_mod.TestServer = undefined;
        try server.start(&.{reply});
        defer server.stop();

        var http_engine: Engine = .init(gpa, testing.io, .{});
        defer http_engine.deinit();

        const url_text = try loopbackUrl(&server);
        defer gpa.free(url_text);

        try testing.expectError(
            error.BadContentEncoding,
            getWholeBodyCompressed(http_engine.interface(), url_text),
        );
    }
}

test "a caller's own Accept-Encoding header goes out alone, and decodes nothing" {
    // **A caller header puts an offer on the wire and asks for no
    // decoding.** Measured against curl 8.21.0 on a loopback listener:
    // `curl -H 'Accept-Encoding: gzip'` with no `--compressed`, answered
    // in gzip, wrote the 64 compressed octets out and exited 0. Only
    // `--compressed` decodes.
    //
    // An earlier version of this engine raised the offer from the header
    // and decoded. That was a divergence invented to avoid a regression,
    // and passing the body through removes the regression instead.
    //
    // The engine still writes no second header beside the caller's: two
    // offers on one request name two sets and a peer may answer either.
    const gpa = testing.allocator;
    const member = try gzipAlloc(gpa, "compressed payload");
    defer gpa.free(member);
    const reply = try std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n{s}",
        .{ member.len, member },
    );
    defer gpa.free(reply);

    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{reply});
    defer server.stop();

    var http_engine: Engine = .init(gpa, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer gpa.free(url_text);

    const url = try zurl_core.url.parse(url_text);
    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = url,
        .headers = &.{.{ .name = "Accept-Encoding", .value = "gzip" }},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    try testing.expect(!exchange.head().body_decoded);

    var body_buffer: [256]u8 = undefined;
    const body = try exchange.bodyReader(&body_buffer).allocRemaining(gpa, .unlimited);
    defer gpa.free(body);
    // The member itself, undecoded, which is what curl writes here.
    try testing.expectEqualSlices(u8, member, body);

    // Exactly one offer went out, and it is the caller's own.
    const sent = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server_mod.countHeaders(sent, "accept-encoding"));
    try testing.expect(std.mem.indexOf(u8, sent, "Accept-Encoding: gzip\r\n") != null);
}

test "two requests to two origins travel on two connections" {
    // The rule the pool exists to keep. A connection to one origin must
    // never carry a request for another, whatever the pool holds.
    var first_server: test_server_mod.TestServer = undefined;
    try first_server.startWith(&.{keptAlive("alpha")}, .{ .responses_per_connection = null });
    defer first_server.stop();

    var second_server: test_server_mod.TestServer = undefined;
    try second_server.startWith(&.{keptAlive("beta")}, .{ .responses_per_connection = null });
    defer second_server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const first_url = try loopbackUrl(&first_server);
    defer testing.allocator.free(first_url);
    const second_url = try loopbackUrl(&second_server);
    defer testing.allocator.free(second_url);

    const first = try getWholeBody(iface, first_url);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("alpha", first);

    const second = try getWholeBody(iface, second_url);
    defer testing.allocator.free(second);
    // The second origin's own answer. A pool that matched on nothing would
    // have sent this request down the first origin's socket and read
    // `alpha` back, or read nothing at all.
    try testing.expectEqualStrings("beta", second);

    try testing.expectEqual(@as(usize, 1), first_server.accepts());
    try testing.expectEqual(@as(usize, 1), second_server.accepts());
}

test "a second host name on loopback is a second origin" {
    // The port alone does not prove the host is part of the key: two
    // servers on one address differ only in port. Every address in
    // 127.0.0.0/8 is loopback, so `127.0.0.2` gives a second host name
    // that reaches this machine and never the network.
    var first_server: test_server_mod.TestServer = undefined;
    try first_server.startWith(&.{keptAlive("alpha")}, .{ .responses_per_connection = null });
    defer first_server.stop();

    var second_server: test_server_mod.TestServer = undefined;
    second_server.startWith(&.{keptAlive("beta")}, .{
        .host = "127.0.0.2",
        .responses_per_connection = null,
    }) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer second_server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const first_url = try loopbackUrl(&first_server);
    defer testing.allocator.free(first_url);
    const second_url = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.2:{d}/",
        .{second_server.port()},
    );
    defer testing.allocator.free(second_url);

    const first = try getWholeBody(iface, first_url);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("alpha", first);

    const second = try getWholeBody(iface, second_url);
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("beta", second);

    try testing.expectEqual(@as(usize, 1), first_server.accepts());
    try testing.expectEqual(@as(usize, 1), second_server.accepts());
}

test "a connection: close answer is honoured and the next request dials" {
    // The peer's own instruction. A pool that kept this connection would
    // write the next request onto a socket the peer is closing.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfirst",
        keptAlive("second"),
    }, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const first = try getWholeBody(iface, url_text);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("first", first);

    const second = try getWholeBody(iface, url_text);
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("second", second);

    try testing.expectEqual(@as(usize, 2), server.accepts());
}

test "an http/1.0 answer defaults to close, even with no connection header" {
    // HTTP/1.0 has the opposite default: a connection ends with the
    // response unless the peer asks to keep it. A pool that read the
    // version wrong would keep a socket the peer has already closed, and
    // hide it behind a retry on every request.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{
        "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nfirst",
        keptAlive("second"),
    }, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const first = try getWholeBody(iface, url_text);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("first", first);

    const second = try getWholeBody(iface, url_text);
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("second", second);

    try testing.expectEqual(@as(usize, 2), server.accepts());
}

test "connection: keep-alive, close is a close, whatever std reads it as" {
    // `std.http.Client.Response.Head.parse` compares the whole
    // `connection:` value against `close`, so a value that lists more than
    // one token reads as keep-alive. `peerKeepsAlive` reads the tokens.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive, close\r\n\r\nfirst",
        keptAlive("second"),
    }, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const first = try getWholeBody(iface, url_text);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("first", first);

    const second = try getWholeBody(iface, url_text);
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("second", second);

    try testing.expectEqual(@as(usize, 2), server.accepts());
}

test "a connection the peer dropped while idle costs one retry and no failure" {
    // The fixture answers with no `connection: close` and then closes
    // anyway, which is a keep-alive connection dropped while it sat idle.
    // A peer may do that at any time and owes the client no warning, so
    // the second request must go out again on a fresh connection and the
    // caller must see nothing of it.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(
        &.{ keptAlive("first"), keptAlive("second") },
        .{ .responses_per_connection = 1 },
    );
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const first = try getWholeBody(iface, url_text);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("first", first);

    // The pool holds the dead connection now. This request finds it dead,
    // and the caller must still get the answer.
    const second = try getWholeBody(iface, url_text);
    defer testing.allocator.free(second);
    try testing.expectEqualStrings("second", second);

    // Two accepts, and not three. The retry dials once, and the fresh
    // connection is not a pooled one, so nothing can retry again.
    try testing.expectEqual(@as(usize, 2), server.accepts());
    try testing.expectEqual(@as(usize, 2), server.capture_count.load(.acquire));
}

test "a request the peer answered is never sent a second time" {
    // The other half of the retry rule. The peer answers a head and then
    // cuts the body short, which is a fault the caller must see. Sending
    // the request again would ask a peer that already acted on it to act
    // on it twice.
    //
    // The response announces five bytes and sends two, on a connection the
    // fixture then closes.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{
        keptAlive("first"),
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nno",
    }, .{ .responses_per_connection = 1 });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const first = try getWholeBody(iface, url_text);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("first", first);

    // The dead pooled connection costs the retry, and the fresh
    // connection carries the short answer. The short body is reported and
    // never papered over with a third request.
    const url = try zurl_core.url.parse(url_text);
    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    try testing.expectError(error.ReadFailed, body.allocRemaining(testing.allocator, .unlimited));
    try testing.expectError(error.PartialFile, exchange.check());

    // Two requests reached the server, not three: the head that arrived
    // ended the retry rule for this request.
    try testing.expectEqual(@as(usize, 2), server.capture_count.load(.acquire));
}

test "a head the peer answered with is reported, and the request is not resent" {
    // The narrow half of the retry rule. The peer answered a head on the
    // pooled connection, and the head is not HTTP. The peer has acted on
    // the request, so the fault is reported and the request stays sent
    // once. A rule that retried on any fault at all would send it again.
    //
    // The third scripted response is the trap. A wrong retry would get a
    // `200` here and this test would read a body where it expects a named
    // fault, rather than hang on a script that ran out.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{
        keptAlive("first"),
        "HTTP/9.9 200 OK\r\n\r\n",
        keptAlive("third"),
    }, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const first = try getWholeBody(iface, url_text);
    defer testing.allocator.free(first);
    try testing.expectEqualStrings("first", first);

    try testing.expectError(error.ReadError, iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .unfollowed,
    }));

    // Two requests reached the server, and not three.
    try testing.expectEqual(@as(usize, 2), server.capture_count.load(.acquire));
    try testing.expectEqual(@as(usize, 1), server.accepts());
}

test "a body abandoned part way through does not poison the next request" {
    // A caller may stop reading a body at any point. The bytes it did not
    // read are still on the socket, so a connection put back with them on
    // it would hand the next request the tail of this response.
    //
    // The body has to be larger than one read buffers, or this proves
    // nothing: a short body is drawn off the socket whole by the first
    // read, whatever the caller then does with it, and the connection
    // really is at the start of the next response. Three thousand bytes is
    // past both buffers in the path, the caller's and
    // `transfer_buffer_len`.
    const long_body = "A" ** 3000;
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(
        &.{ keptAlive(long_body), keptAlive("clean") },
        .{ .responses_per_connection = null },
    );
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    {
        const exchange = try iface.open(.{
            .method = .GET,
            .url = url,
            .headers = &.{},
            .redirects = .unfollowed,
        });
        defer exchange.close();

        var body_buffer: [64]u8 = undefined;
        const body = exchange.bodyReader(&body_buffer);
        // Four bytes of three thousand, and then the caller walks away.
        var taken: [4]u8 = undefined;
        try body.readSliceAll(&taken);
        try testing.expectEqualStrings("AAAA", &taken);
    }

    const second = try getWholeBody(iface, url_text);
    defer testing.allocator.free(second);
    // `clean`, and not a run of `A`. A pooled connection with the rest of
    // the first body still on it would have answered with that tail.
    try testing.expectEqualStrings("clean", second);

    try testing.expectEqual(@as(usize, 2), server.accepts());
}

test "a redirect hop with an empty body keeps the connection for the next hop" {
    // A redirect hop is the shape that pays most for a pool: `followChain`
    // closes each hop's exchange without ever reading its body. A hop that
    // announced no body leaves the connection at the start of the next
    // response, so it is reusable although nothing read it.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{
        "HTTP/1.1 302 Found\r\nLocation: /landed\r\nContent-Length: 0\r\n\r\n",
        keptAlive("landed"),
    }, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);
    const url = try zurl_core.url.parse(url_text);

    const exchange = try iface.open(.{
        .method = .GET,
        .url = url,
        .headers = &.{},
        .redirects = .{ .follow = 2 },
    });
    defer exchange.close();

    var body_buffer: [64]u8 = undefined;
    const body = exchange.bodyReader(&body_buffer);
    const contents = try body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("landed", contents);

    try testing.expectEqual(@as(usize, 1), server.accepts());
}

test "the pool keeps no more than pool_idle_max connections" {
    // The bound is a memory budget, so a pool that quietly kept one more
    // than it says would cost 350 KiB nobody accounted for. This drives
    // one more origin than the bound through the pool and shows that the
    // oldest one, and only the oldest one, was dropped.
    //
    // A test written for a particular number would go quiet if the bound
    // changed, so the origins are counted from `pool_idle_max` itself.
    const origins = pool_idle_max + 1;
    var servers: [origins]test_server_mod.TestServer = undefined;
    var started: usize = 0;
    defer for (servers[0..started]) |*s| s.stop();
    while (started < origins) : (started += 1) {
        try servers[started].startWith(
            &.{ keptAlive("one"), keptAlive("two") },
            .{ .responses_per_connection = null },
        );
    }

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    const iface = http_engine.interface();

    var urls: [origins][]u8 = undefined;
    var built: usize = 0;
    defer for (urls[0..built]) |u| testing.allocator.free(u);
    while (built < origins) : (built += 1) urls[built] = try loopbackUrl(&servers[built]);

    // One request to every origin, in order. The pool is full after the
    // first `pool_idle_max` of them, so the last one evicts the first.
    for (urls) |u| {
        const body = try getWholeBody(iface, u);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("one", body);
    }
    for (servers[0..origins]) |*s| try testing.expectEqual(@as(usize, 1), s.accepts());

    // The origin that was asked for first is the one the pool dropped, so
    // this request dials.
    {
        const body = try getWholeBody(iface, urls[0]);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("two", body);
    }
    try testing.expectEqual(@as(usize, 2), servers[0].accepts());

    // And the origin that was asked for last is still held, so this one
    // does not. A pool that dropped the newest instead of the oldest would
    // fail here and pass the line above.
    {
        const body = try getWholeBody(iface, urls[origins - 1]);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("two", body);
    }
    try testing.expectEqual(@as(usize, 1), servers[origins - 1].accepts());
}

test "an engine that closes drops every connection its pool still holds" {
    // `Engine.deinit` is the only path that closes an idle connection, so
    // a pool it did not walk would leak a socket and 300 KiB of buffers
    // for every origin a command line touched. The testing allocator fails
    // this test on the leak.
    var server: test_server_mod.TestServer = undefined;
    try server.startWith(&.{keptAlive("held")}, .{ .responses_per_connection = null });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    const iface = http_engine.interface();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const body = try getWholeBody(iface, url_text);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("held", body);

    // The connection is idle in the pool at this point, not closed.
    try testing.expect(http_engine.pool != null);
    try testing.expectEqual(@as(usize, 1), http_engine.pool.?.len);

    http_engine.deinit();
    try testing.expectEqual(@as(?*Pool, null), http_engine.pool);
}

test "an engine that opened nothing allocates no pool" {
    // The pool is built at the first request, not at `init`, so an engine
    // a caller never used costs nothing. `Engine.init` also returns an
    // `Engine` by value and has no way to report an allocation failure.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();
    try testing.expectEqual(@as(?*Pool, null), http_engine.pool);
}

test "a request verifies the peer unless it asked not to" {
    // **The bad-certificate proof at the one seam that decides it.**
    // zurl has no TLS server fixture, so no test here can complete a
    // handshake against a bad certificate. What a test can do is name the
    // checks the engine asks for, which is what decides whether a bad
    // certificate is refused: `HostCheck.explicit` with `TrustCheck.bundle`
    // is the pair that refuses an expired chain, a self-signed chain, and
    // a wrong host name, and `.none` with `.none` is the pair that accepts
    // all three.
    //
    // Measured against the real binary, which is the other half of this
    // proof: `zurl https://expired.badssl.com/` exits 60, and the same
    // url with `-k` exits 0. The same split holds for
    // `self-signed.badssl.com` and `wrong.host.badssl.com`, and curl
    // 8.21.0 answers each of the six the same way.
    var lock: std.Io.RwLock = .init;
    var bundle: std.crypto.Certificate.Bundle = .empty;

    const base: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
    };

    // **The default verifies.** Nothing in the request said otherwise, so
    // the chain must reach a root in the bundle and the certificate must
    // carry the host the url names.
    const verifying = tlsSetup(base, &lock, &bundle);
    try testing.expectEqualStrings("example.com", verifying.host.explicit);
    try testing.expectEqual(&bundle, verifying.trust.bundle.bundle);
    try testing.expectEqual(&lock, verifying.trust.bundle.lock);

    // Every other field a caller can set leaves the two checks alone. A
    // TLS floor, a TLS ceiling, a redirect policy, and a trusted-secrets
    // answer are not reasons to stop verifying a peer.
    var loaded = base;
    loaded.tls_min_version = .tls_1_3;
    loaded.tls_max_version = .tls_1_2;
    loaded.redirects = .{ .follow = 5 };
    loaded.trusted_secrets = true;
    loaded.tcp_no_delay = false;
    const still_verifying = tlsSetup(loaded, &lock, &bundle);
    try testing.expectEqualStrings("example.com", still_verifying.host.explicit);
    try testing.expectEqual(&bundle, still_verifying.trust.bundle.bundle);

    // **The ALPN offer holds every protocol this engine can parse.** A
    // request that named nothing offers `h2` and then `http/1.1`, and
    // `sendOn` reads the peer's answer back to decide which engine speaks.
    try testing.expectEqual(@as(usize, 2), verifying.alpn_protocols.len);
    try testing.expectEqualStrings("h2", verifying.alpn_protocols[0]);
    try testing.expectEqualStrings("http/1.1", verifying.alpn_protocols[1]);

    // `--http1.1` narrows the offer to one name, so the peer cannot choose
    // HTTP/2 and the transfer takes the path it always took.
    var older = base;
    older.http_version = .http_1_1;
    const one = tlsSetup(older, &lock, &bundle);
    try testing.expectEqual(@as(usize, 1), one.alpn_protocols.len);
    try testing.expectEqualStrings("http/1.1", one.alpn_protocols[0]);

    // `--http2` names the default offer, because over TLS the peer already
    // gets to choose HTTP/2. What that flag changes is a cleartext hop; see
    // `upgradeOffer`.
    var two = base;
    two.http_version = .http_2;
    const both = tlsSetup(two, &lock, &bundle);
    try testing.expectEqual(@as(usize, 2), both.alpn_protocols.len);
    try testing.expectEqualStrings("h2", both.alpn_protocols[0]);
    try testing.expectEqualStrings("http/1.1", both.alpn_protocols[1]);

    // **`--http2-prior-knowledge` narrows the offer the other way.** `h2`
    // alone, so a peer that speaks no HTTP/2 has nothing to choose and RFC
    // 7301 section 3.2 has it end the handshake. Measured against curl
    // 8.21.0 and an `openssl s_server` offering `http/1.1` alone: curl
    // reported `tlsv1 alert no application protocol` and exited 35 for
    // this flag, and exited 0 on HTTP/1.1 for `--http2`.
    var prior = base;
    prior.http_version = .prior_knowledge;
    const demanded = tlsSetup(prior, &lock, &bundle);
    try testing.expectEqual(@as(usize, 1), demanded.alpn_protocols.len);
    try testing.expectEqualStrings("h2", demanded.alpn_protocols[0]);

    // **`--http3` and `--http3-only` offer the default pair here, and
    // neither of them names `h3`.** A hop that reaches this function runs
    // on TCP, and HTTP/3 runs on QUIC alone, so a peer that chose `h3` on
    // a stream socket would leave the connection with no protocol either
    // side can speak. What this offer is for is the fallback: measured,
    // `curl -v --http3 https://example.com/` printed
    // `ALPN: curl offers h2,http/1.1` on the TCP hop it fell back to.
    var three = base;
    three.http_version = .http_3;
    const fallback = tlsSetup(three, &lock, &bundle);
    try testing.expectEqual(@as(usize, 2), fallback.alpn_protocols.len);
    try testing.expectEqualStrings("h2", fallback.alpn_protocols[0]);
    try testing.expectEqualStrings("http/1.1", fallback.alpn_protocols[1]);

    var three_only = base;
    three_only.http_version = .http_3_only;
    const only = tlsSetup(three_only, &lock, &bundle);
    try testing.expectEqual(@as(usize, 2), only.alpn_protocols.len);
    try testing.expectEqualStrings("h2", only.alpn_protocols[0]);

    // And no offer this function can build names `h3`, for any command
    // line at all. One loop over every value, so a value added later
    // fails this test rather than a connection.
    for (std.enums.values(engine.HttpVersion)) |version| {
        var any_flag = base;
        any_flag.http_version = version;
        for (tlsSetup(any_flag, &lock, &bundle).alpn_protocols) |name| {
            try testing.expect(!std.mem.eql(u8, name, "h3"));
        }
    }

    // And `--no-alpn` empties the list, which leaves the extension out of
    // the hello. A peer that was offered nothing chooses nothing, so that
    // hop is HTTP/1.1 too.
    var quiet = base;
    quiet.no_alpn = true;
    try testing.expectEqual(@as(usize, 0), tlsSetup(quiet, &lock, &bundle).alpn_protocols.len);

    // `--no-alpn` wins over `--http1.1`, because an empty list is already
    // the narrowest offer there is.
    var quiet_older = base;
    quiet_older.no_alpn = true;
    quiet_older.http_version = .http_1_1;
    try testing.expectEqual(@as(usize, 0), tlsSetup(quiet_older, &lock, &bundle).alpn_protocols.len);

    // **Only the flag reaches the other answer, and it turns off both
    // halves.**
    var unverified = base;
    unverified.insecure = true;
    const skipping = tlsSetup(unverified, &lock, &bundle);
    try testing.expectEqual(zurl_net.Connection.HostCheck.none, skipping.host);
    try testing.expectEqual(zurl_net.Connection.TrustCheck.none, skipping.trust);
}

test "--location-trusted carries the secret to every hop, and the default carries it to none" {
    // The two halves of one rule, in one test, so neither can be changed
    // without the other being read. The default half is the security
    // default: it must keep working exactly as it did.
    const test_server = @import("test_server.zig");

    const responses = [_][]const u8{
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    };
    const secrets = [_]std.http.Header{
        .{ .name = "Authorization", .value = "Basic Ym9iOmh1bnRlcjI=" },
        .{ .name = "Cookie", .value = "session=super-secret-session" },
    };

    // The trusting half: every hop carries the secret.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&responses);
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
        defer testing.allocator.free(url_text);

        const exchange = try http_engine.interface().open(.{
            .method = .GET,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .secrets = &secrets,
            .redirects = .{ .follow = 3 },
            .trusted_secrets = true,
        });
        defer exchange.close();

        try testing.expectEqual(@as(u16, 200), exchange.head().status);
        // No probe was sent and thrown away, so the chain is two hops and
        // both of them carried the credential.
        try testing.expect(!exchange.head().credential_withheld);
        try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(server.requestHead(0).?));
        try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(server.requestHead(1).?));
        try testing.expect(std.mem.indexOf(u8, server.requestHead(1).?, "super-secret-session") != null);
    }

    // The default half: the same request with the field left alone sends
    // the target nothing at all.
    {
        var server: test_server.TestServer = undefined;
        try server.start(&(.{responses[0]} ++ responses));
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();

        const url_text = try std.fmt.allocPrint(testing.allocator, "http://127.0.0.1:{d}/start", .{server.port()});
        defer testing.allocator.free(url_text);

        const exchange = try http_engine.interface().open(.{
            .method = .GET,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .secrets = &secrets,
            .redirects = .{ .follow = 3 },
        });
        defer exchange.close();

        try testing.expectEqual(@as(u16, 200), exchange.head().status);
        try testing.expect(exchange.head().credential_withheld);
        // Request 0 is the probe, which reaches the origin the url named
        // and carries the secret. Every request after it is a hop of the
        // chain, and none of them carries anything.
        try testing.expectEqual(@as(usize, 1), test_server.countAuthorizationHeaders(server.requestHead(0).?));
        try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(server.requestHead(1).?));
        try testing.expectEqual(@as(usize, 0), test_server.countAuthorizationHeaders(server.requestHead(2).?));
        try testing.expect(std.mem.indexOf(u8, server.requestHead(2).?, "super-secret-session") == null);
    }
}

test "an origin compares every field and no shortcut" {
    // `Origin.eql` is the rule that stops one origin's request, and the
    // credential on it, going out on another origin's socket. Each field
    // is checked on its own here, because a compare that dropped one would
    // still pass a test that changed the host alone.
    const base: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
    };
    // The dial target of a transfer that named no `--resolve` and no
    // `--connect-to`: the url's own host and port.
    const plain_dial: engine.DialTarget = .{ .host = "example.com", .port = 443, .overridden = false };
    const a = directOrigin(.tls, "example.com", 443, plain_dial, base).?;

    try testing.expect(a.eql(&directOrigin(.tls, "example.com", 443, plain_dial, base).?));
    try testing.expect(!a.eql(&directOrigin(.plain, "example.com", 443, plain_dial, base).?));
    try testing.expect(!a.eql(&directOrigin(.tls, "other.example", 443, .{
        .host = "other.example",
        .port = 443,
        .overridden = false,
    }, base).?));
    try testing.expect(!a.eql(&directOrigin(.tls, "example.com", 8443, .{
        .host = "example.com",
        .port = 8443,
        .overridden = false,
    }, base).?));

    // A host that differs only in case is a different key here. DNS reads
    // the two as one name, so this is stricter than it has to be, and
    // stricter is the side to be wrong on.
    try testing.expect(!a.eql(&directOrigin(.tls, "EXAMPLE.com", 443, .{
        .host = "EXAMPLE.com",
        .port = 443,
        .overridden = false,
    }, base).?));

    // **The dial target, and this row is the second security one.** Two
    // requests can name one url and still reach two different peers, when
    // a `--resolve` sends them to two different addresses. A pooled
    // connection reaches whichever peer it was opened at, so a socket
    // dialed at one address must never answer a request that would have
    // dialed the other.
    const moved: engine.DialTarget = .{ .host = "127.0.0.1", .port = 443, .overridden = true };
    const elsewhere: engine.DialTarget = .{ .host = "127.0.0.2", .port = 443, .overridden = true };
    const other_port: engine.DialTarget = .{ .host = "127.0.0.1", .port = 8443, .overridden = true };
    try testing.expect(!a.eql(&directOrigin(.tls, "example.com", 443, moved, base).?));
    try testing.expect(!directOrigin(.tls, "example.com", 443, moved, base).?
        .eql(&directOrigin(.tls, "example.com", 443, elsewhere, base).?));
    try testing.expect(!directOrigin(.tls, "example.com", 443, moved, base).?
        .eql(&directOrigin(.tls, "example.com", 443, other_port, base).?));
    // Two requests that were moved the same way share one socket, which
    // is what keeps the pool useful under `--resolve`.
    try testing.expect(directOrigin(.tls, "example.com", 443, moved, base).?
        .eql(&directOrigin(.tls, "example.com", 443, moved, base).?));

    // The two TLS bounds travel on the request, so a floor a caller raised
    // must not be answered over a session that was opened under a lower
    // one.
    var raised = base;
    raised.tls_min_version = .tls_1_3;
    try testing.expect(!a.eql(&directOrigin(.tls, "example.com", 443, plain_dial, raised).?));

    var lowered = base;
    lowered.tls_max_version = .tls_1_2;
    try testing.expect(!a.eql(&directOrigin(.tls, "example.com", 443, plain_dial, lowered).?));

    // **The verification answer, and this row is the security one.** A
    // connection opened under `-k` carries a peer nobody authenticated,
    // and nothing reads that back off the socket afterward. A later
    // request that asked for verification must never take it out of the
    // pool.
    var unverified = base;
    unverified.insecure = true;
    try testing.expect(!a.eql(&directOrigin(.tls, "example.com", 443, plain_dial, unverified).?));

    // Nagle's algorithm is set once on the socket and never read back
    // either, so a pooled connection with the option on would silently
    // ignore a later `--no-tcp-nodelay`.
    var nagling = base;
    nagling.tcp_no_delay = false;
    try testing.expect(!a.eql(&directOrigin(.tls, "example.com", 443, plain_dial, nagling).?));

    // The ALPN offer is made once, in the client hello, and it cannot be
    // made again on an open session. A connection that negotiated a
    // protocol must therefore never answer a request that asked for none.
    var no_alpn = base;
    no_alpn.no_alpn = true;
    try testing.expect(!a.eql(&directOrigin(.tls, "example.com", 443, plain_dial, no_alpn).?));

    // A host longer than the storage is not poolable. Nothing reaches this
    // through `openOnce`, because a name that long cannot be dialed, but
    // the branch must answer rather than write past the buffer.
    const too_long = "x" ** (masked_host_max + 1);
    try testing.expectEqual(@as(?Origin, null), directOrigin(.plain, too_long, 80, .{
        .host = too_long,
        .port = 80,
        .overridden = false,
    }, base));
    // And a dial target longer than the storage answers the same way, so
    // an override that cannot be kept leaves a connection that is used
    // once and closed rather than one keyed on a truncated address.
    try testing.expectEqual(@as(?Origin, null), directOrigin(.plain, "example.com", 80, .{
        .host = too_long,
        .port = 80,
        .overridden = true,
    }, base));
}

/// `Origin.init` for a test about a transfer that named no proxy.
///
/// The proxy argument is spelled out at every real call site, so a reader
/// of `openOnce` sees it. A test that is about another field says so by
/// calling this instead of writing `null` twenty times.
fn directOrigin(
    protocol: Protocol,
    host_text: []const u8,
    port: u16,
    target: engine.DialTarget,
    req: engine.Request,
) ?Origin {
    return Origin.init(protocol, host_text, port, target, null, req, no_trust);
}

/// The trust digest an engine carries before an owner writes one.
///
/// A test that is about another field of `Origin` uses this, so the two
/// sides of a compare agree on the trust roots and only the field under
/// test differs. See `Origin.trust`.
const no_trust: [std.crypto.hash.sha2.Sha256.digest_length]u8 = @splat(0);

/// `Origin.init` with `no_trust`. See `directOrigin` for why the tests
/// have a helper at all.
fn testOrigin(
    protocol: Protocol,
    host_text: []const u8,
    port: u16,
    target: engine.DialTarget,
    proxy: ?engine.Proxy,
    req: engine.Request,
) ?Origin {
    return Origin.init(protocol, host_text, port, target, proxy, req, no_trust);
}

test "a pooled connection through one proxy never serves a request for another" {
    // **This is the pool's proxy rule, and it is a security rule.** A
    // connection through a proxy ends at that proxy: a tunnel reaches the
    // origin because that proxy chose to carry it, and a direct connection
    // reaches the origin itself. Handing one to a request that named a
    // different proxy, or no proxy, sends the request and every secret on
    // it to a peer the caller never named.
    const req: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
    };
    const dial: engine.DialTarget = .{ .host = "example.com", .port = 443, .overridden = false };
    const first: engine.Proxy = .{ .kind = .http, .host = "127.0.0.1", .port = 3128 };

    const direct = testOrigin(.tls, "example.com", 443, dial, null, req).?;
    const via_first = testOrigin(.tls, "example.com", 443, dial, first, req).?;

    // A proxied connection and a direct one are two different peers.
    try testing.expect(!direct.eql(&via_first));
    try testing.expect(!via_first.eql(&direct));
    // And two requests through the same proxy do share one socket, which is
    // what keeps the pool useful behind a proxy at all.
    try testing.expect(via_first.eql(&testOrigin(.tls, "example.com", 443, dial, first, req).?));

    // Another proxy host, another port, and another kind are each a
    // different peer.
    var other = first;
    other.host = "127.0.0.2";
    try testing.expect(!via_first.eql(&testOrigin(.tls, "example.com", 443, dial, other, req).?));

    other = first;
    other.port = 3129;
    try testing.expect(!via_first.eql(&testOrigin(.tls, "example.com", 443, dial, other, req).?));

    other = first;
    other.kind = .socks5;
    try testing.expect(!via_first.eql(&testOrigin(.tls, "example.com", 443, dial, other, req).?));

    // **The proxy's own verification answer.** A connection to a proxy
    // nobody authenticated must never answer a request that asked for one,
    // for exactly the reason `Origin.insecure` gives about the origin.
    other = first;
    other.insecure = true;
    try testing.expect(!via_first.eql(&testOrigin(.tls, "example.com", 443, dial, other, req).?));

    // A proxy host longer than the storage is not poolable, the same
    // answer a url host that long gets.
    other = first;
    other.host = "x" ** (masked_host_max + 1);
    try testing.expectEqual(
        @as(?Origin, null),
        testOrigin(.tls, "example.com", 443, dial, other, req),
    );
}

test "a tunnel opened with one proxy credential never carries another" {
    // A `CONNECT` authorises a tunnel once, and nothing on the open tunnel
    // can carry a second `Proxy-Authorization`. So a request that named a
    // different proxy credential must never run on it: that would be one
    // user borrowing another user's proxy authorisation.
    const req: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
    };
    const dial: engine.DialTarget = .{ .host = "example.com", .port = 443, .overridden = false };
    const anonymous: engine.Proxy = .{ .kind = .http, .host = "127.0.0.1", .port = 3128 };
    var alice = anonymous;
    alice.authorization = "Basic YWxpY2U6b25l";
    var bob = anonymous;
    bob.authorization = "Basic Ym9iOnR3bw==";

    const via_alice = testOrigin(.tls, "example.com", 443, dial, alice, req).?;
    try testing.expect(!via_alice.eql(&testOrigin(.tls, "example.com", 443, dial, bob, req).?));
    try testing.expect(!via_alice.eql(&testOrigin(.tls, "example.com", 443, dial, anonymous, req).?));
    try testing.expect(via_alice.eql(&testOrigin(.tls, "example.com", 443, dial, alice, req).?));

    // The SOCKS halves count too, and they are length-prefixed before they
    // are hashed, so a user of `ab` with password `c` and a user of `a`
    // with password `bc` are two different keys.
    var run_together = anonymous;
    run_together.user = "ab";
    run_together.password = "c";
    var split = anonymous;
    split.user = "a";
    split.password = "bc";
    try testing.expect(!testOrigin(.tls, "example.com", 443, dial, run_together, req).?
        .eql(&testOrigin(.tls, "example.com", 443, dial, split, req).?));

    // **The key holds a digest and never the credential.** An idle
    // connection can sit in the pool for the whole life of a client, and a
    // credential in it would sit there too.
    try testing.expect(std.mem.indexOf(u8, &via_alice.proxy_credential, alice.authorization) == null);
    // And a key with no proxy at all still holds a digest, of nothing, so
    // the compare needs no special case.
    const direct = testOrigin(.tls, "example.com", 443, dial, null, req).?;
    var empty: [std.crypto.hash.sha2.Sha256.digest_length]u8 = @splat(0);
    try testing.expect(!std.mem.eql(u8, &direct.proxy_credential, &empty));
    empty = proxyCredentialDigest(null);
    try testing.expectEqualSlices(u8, &empty, &direct.proxy_credential);
}

/// A jar for the tests in this file.
///
/// It keeps no cookie and applies no rule: this file's tests are about the
/// seam, not about the rules. `lib/zurl/Jar.zig` holds the real jar and
/// `zurl_core.cookie` holds every rule it reads. This one records which
/// url it was asked about and what it was told, so a test can prove that
/// the engine asks once for each hop with that hop's own url.
const TestJar = struct {
    /// What `send` answers, or null to send no cookie.
    answer: ?[]const u8 = null,
    /// The path of each url `send` was asked about, in order.
    ///
    /// Copied and not borrowed. The engine walks a chain inside one
    /// buffer, so the text of a hop is gone once the next hop is resolved.
    asked: [8][128]u8 = undefined,
    asked_len: [8]usize = @splat(0),
    asked_count: usize = 0,
    /// Each `Set-Cookie` value handed to `receive`, in order.
    received: [8][256]u8 = undefined,
    received_len: [8]usize = @splat(0),
    received_count: usize = 0,

    fn interface(self: *TestJar) engine.CookieJar {
        return .{ .ptr = self, .send = sendFn, .receive = receiveFn };
    }

    fn sendFn(ptr: *anyopaque, url: zurl_core.Url, out: []u8) ?[]const u8 {
        const self: *TestJar = @ptrCast(@alignCast(ptr));
        if (self.asked_count < self.asked.len and url.path.len <= self.asked[0].len) {
            @memcpy(self.asked[self.asked_count][0..url.path.len], url.path);
            self.asked_len[self.asked_count] = url.path.len;
            self.asked_count += 1;
        }
        const answer = self.answer orelse return null;
        @memcpy(out[0..answer.len], answer);
        return out[0..answer.len];
    }

    fn receiveFn(ptr: *anyopaque, url: zurl_core.Url, set_cookie: []const u8) void {
        _ = url;
        const self: *TestJar = @ptrCast(@alignCast(ptr));
        if (self.received_count == self.received.len) return;
        if (set_cookie.len > self.received[0].len) return;
        @memcpy(self.received[self.received_count][0..set_cookie.len], set_cookie);
        self.received_len[self.received_count] = set_cookie.len;
        self.received_count += 1;
    }

    fn receivedText(self: *const TestJar, index: usize) []const u8 {
        return self.received[index][0..self.received_len[index]];
    }

    fn askedText(self: *const TestJar, index: usize) []const u8 {
        return self.asked[index][0..self.asked_len[index]];
    }
};

test "a jar's cookies reach the wire as one cookie line" {
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    var jar: TestJar = .{ .answer = "a=1; b=2" };
    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .cookies = jar.interface(),
    });
    defer exchange.close();

    // Measured against curl 8.21.0: `curl -b 'a=1; b=2'` sends exactly
    // `Cookie: a=1; b=2`, one header and one separator of a semicolon and
    // a space.
    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "Cookie: a=1; b=2\r\n") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "ookie:"));
}

test "a jar that sends nothing writes no cookie line at all" {
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    var jar: TestJar = .{ .answer = null };
    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .cookies = jar.interface(),
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, head, "ookie:"));
}

test "the jar is asked again for every hop, with that hop's own url" {
    // **This is what lets a cookie stay inside its own host.** The engine
    // asks the jar per hop, so the jar's domain rule reads the host of the
    // hop that is about to go out and not the host the caller named. A
    // jar asked once for the whole chain could only answer for the first.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /third\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    var jar: TestJar = .{ .answer = "sid=1" };
    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/first",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .{ .follow = 5 },
        .cookies = jar.interface(),
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try testing.expectEqual(@as(usize, 3), jar.asked_count);
    try testing.expectEqualStrings("/first", jar.askedText(0));
    try testing.expectEqualStrings("/second", jar.askedText(1));
    try testing.expectEqualStrings("/third", jar.askedText(2));
}

test "a jar cookie crosses a redirect, unlike a secret the caller wrote" {
    // The two paths differ on purpose, and this pins the difference. A
    // `Cookie` in `secrets` is withheld on every redirect, because the
    // engine cannot know which host that value belongs to. A jar carries
    // the domain of each cookie, so the engine asks it again per hop.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    var jar: TestJar = .{ .answer = "fromjar=1" };
    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/first",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .secrets = &.{.{ .name = "Cookie", .value = "fromflag=2" }},
        .redirects = .{ .follow = 3 },
        .cookies = jar.interface(),
    });
    defer exchange.close();

    // The chain the engine walked after it dropped the secret. `open`
    // sends one probe first, so the hops of the chain start at index 1.
    const hop = server.requestHead(1).?;
    try testing.expect(std.mem.indexOf(u8, hop, "fromjar=1") != null);
    try testing.expect(std.mem.indexOf(u8, hop, "fromflag=2") == null);
    try testing.expect(exchange.head().credential_withheld);
}

test "a jar cookie and the caller's own cookie join into one header line" {
    // Measured against curl 8.21.0 with `-b 'pre=set'` and a jar holding
    // one cookie: the wire carried `Cookie: hop=one; pre=set`, one header,
    // the jar's cookie first and the command line's text last.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    var jar: TestJar = .{ .answer = "hop=one" };
    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .secrets = &.{.{ .name = "Cookie", .value = "pre=set" }},
        .redirects = .unfollowed,
        .cookies = jar.interface(),
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, head, "Cookie: hop=one; pre=set\r\n") != null);
    // One line, and never two. A peer reads a second one as a second
    // cookie list.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "ookie:"));
}

test "every Set-Cookie of every hop reaches the jar" {
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\n" ++
            "Connection: close\r\nSet-Cookie: hop=one\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n" ++
            "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    var jar: TestJar = .{};
    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/first",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .{ .follow = 3 },
        .cookies = jar.interface(),
    });
    defer exchange.close();

    // The redirect hop's own header counts. A jar that only saw the last
    // response would lose the session a redirect set.
    try testing.expectEqual(@as(usize, 3), jar.received_count);
    try testing.expectEqualStrings("hop=one", jar.receivedText(0));
    try testing.expectEqualStrings("a=1", jar.receivedText(1));
    try testing.expectEqualStrings("b=2", jar.receivedText(2));
}

test "a request with no jar drops every Set-Cookie, which is curl's default" {
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nSet-Cookie: a=1\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    const head = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, head, "ookie:"));
}

test "a jar value carrying a CRLF is an error, not an injected header" {
    // A jar is built out of a file and out of what a server sent, so its
    // answer is untrusted input that reaches a header value.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    var jar: TestJar = .{ .answer = "a=1\r\nX-Injected: yes" };
    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    try testing.expectError(error.InvalidHeader, http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .cookies = jar.interface(),
    }));
    // Nothing went out at all, so nothing could be injected.
    try testing.expectEqual(@as(?[]const u8, null), server.requestHead(0));
}

test "a Cookie header and a jar too large to join are refused, not cut in half" {
    // A value cut short is a different cookie list, and a server would
    // read it as a session that never existed.
    var buffer: [cookie_buffer_len]u8 = undefined;
    @memset(&buffer, 'a');
    const jar_value = buffer[0..engine.cookie_header_len_max];
    const caller_value = "b" ** (engine.cookie_header_len_max - 1);
    try testing.expectError(error.InvalidHeader, mergeCookies(&buffer, jar_value, caller_value));

    // One byte under the bound joins, and the join is the two values with
    // a semicolon and a space between them.
    var room: [cookie_buffer_len]u8 = undefined;
    @memcpy(room[0..3], "a=1");
    const joined = try mergeCookies(&room, room[0..3], "b=2");
    try testing.expectEqualStrings("a=1; b=2", joined);
}

test "--resolve moves the dial and never the name the certificate is checked against" {
    // **The security proof for `--resolve` and `--connect-to`, and it
    // needs no socket.** The two answers come out of two different
    // functions, so this reads both for one request and asserts they
    // disagree exactly where they must: the dial goes to the address the
    // flag named, and the TLS check stays on the host the url wrote.
    //
    // Without the second half, either flag would be a way to send a
    // request meant for one host to a peer that holds a certificate for
    // another, and the transfer would still report success. That is the
    // whole thing certificate verification exists to stop, and it would
    // then be reachable with no `-k` on the command line.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const overrides = [_]engine.HostOverride{.{
        .from_host = "example.com",
        .from_port = 443,
        .to_host = "127.0.0.1",
        .to_port = 8443,
    }};
    const req: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
        .connect_to = &overrides,
    };

    // The dial: the address the flag named, on the port it named.
    const target = engine.dialTarget(req.connect_to, req.url.host, req.url.port.?);
    try testing.expectEqualStrings("127.0.0.1", target.host);
    try testing.expectEqual(@as(u16, 8443), target.port);
    try testing.expect(target.overridden);

    // The certificate: the host the url wrote, and nothing the flag said.
    const setup = tlsSetup(req, &http_engine.ca_bundle_lock, &http_engine.ca_bundle);
    try testing.expectEqualStrings("example.com", setup.host.explicit);
    // And the roots are still the ones the owner loaded, so the chain
    // still has to reach a trusted root as well as carry the name.
    try testing.expect(setup.trust == .bundle);

    // `-k` is still the only way either check goes away, and the override
    // beside it changes neither answer.
    var unverified = req;
    unverified.insecure = true;
    const open_setup = tlsSetup(unverified, &http_engine.ca_bundle_lock, &http_engine.ca_bundle);
    try testing.expect(open_setup.host == .none);
    try testing.expect(open_setup.trust == .none);
}

test "the hop to a proxy carries the tls version bounds the transfer named" {
    // **The field one of two mirror image functions lost.** `tlsSetup`
    // carried `--tlsv1.3` to the origin and `proxyTlsSetup` carried it
    // nowhere, so the hop to an `https` proxy settled on whatever the
    // proxy offered. A cleartext origin behind that proxy puts the whole
    // request on that session, `Proxy-Authorization` and all.
    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    var req: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("http://plain.example/file"),
        .headers = &.{},
        .redirects = .unfollowed,
    };
    req.tls_min_version = .tls_1_3;
    req.tls_max_version = .tls_1_3;

    const proxy: engine.Proxy = .{ .kind = .https, .host = "proxy.example", .port = 443 };
    const setup = proxyTlsSetup(
        req,
        proxy,
        &http_engine.proxy_ca_bundle_lock,
        &http_engine.proxy_ca_bundle,
    );

    // The proxy's own name and roots, which is the rule this function
    // already kept.
    try testing.expectEqualStrings("proxy.example", setup.host.explicit);
    try testing.expect(setup.trust == .bundle);

    // And the same two bounds `tlsSetup` gives the origin.
    const origin = tlsSetup(req, &http_engine.ca_bundle_lock, &http_engine.ca_bundle);
    try testing.expectEqual(origin.min_version, setup.min_version);
    try testing.expectEqual(origin.max_version, setup.max_version);
    try testing.expectEqual(req.tls_min_version, setup.min_version);
    try testing.expectEqual(req.tls_max_version, setup.max_version);
}

test "--connect-to reaches another address and still sends the url's own host line" {
    // The other half of the proof, on a real socket. The url names a host
    // that resolves nowhere, so the transfer can only reach the fixture
    // through the override, and the `host:` line on the wire must still
    // be the name the url wrote.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const port = server.port();
    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://example.invalid:{d}/x",
        .{port},
    );
    defer testing.allocator.free(url_text);

    const overrides = [_]engine.HostOverride{.{
        .from_host = "example.invalid",
        .from_port = port,
        .to_host = "127.0.0.1",
        .to_port = port,
    }};

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .connect_to = &overrides,
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    const head = server.requestHead(0).?;
    const host_line = try std.fmt.allocPrint(
        testing.allocator,
        "host: example.invalid:{d}\r\n",
        .{port},
    );
    defer testing.allocator.free(host_line);
    try testing.expect(std.mem.indexOf(u8, head, host_line) != null);
    // And nothing put the dialed address on the wire.
    try testing.expect(std.mem.indexOf(u8, head, "127.0.0.1") == null);
}

test "auto_referer sends the previous hop's url on each hop and none on the first" {
    // Measured against curl 8.21.0 with `-L -e ';auto'` through a `302`:
    // the first request carried no `Referer` and the second carried the
    // url of the first.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const port = server.port();
    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/first",
        .{port},
    );
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .{ .follow = 5 },
        .auto_referer = true,
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    // The first request came from nowhere, so it names no page.
    try testing.expectEqual(@as(usize, 0), test_server.countHeaders(server.requestHead(0).?, "referer"));

    // The second names the first, once.
    const second = server.requestHead(1).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(second, "referer"));
    const line = try std.fmt.allocPrint(
        testing.allocator,
        "Referer: http://127.0.0.1:{d}/first\r\n",
        .{port},
    );
    defer testing.allocator.free(line);
    try testing.expect(std.mem.indexOf(u8, second, line) != null);
}

test "auto_referer replaces the caller's own Referer and never adds a second one" {
    // Measured: `-L -e 'http://a/;auto'` sent `Referer: http://a/` on the
    // first request and the previous hop's url on the second. Two lines
    // on one hop would let a peer read one request as coming from two
    // pages.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /third\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const port = server.port();
    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/first",
        .{port},
    );
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{
        .{ .name = "Referer", .value = "http://written.test/" },
        .{ .name = "X-Keep", .value = "1" },
    };

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &headers,
        .redirects = .{ .follow = 5 },
        .auto_referer = true,
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);

    // The first request carries what the caller wrote.
    const first = server.requestHead(0).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(first, "referer"));
    try testing.expect(std.mem.indexOf(u8, first, "http://written.test/") != null);

    // The second names the first, and the caller's own value is gone.
    const second = server.requestHead(1).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(second, "referer"));
    try testing.expect(std.mem.indexOf(u8, second, "http://written.test/") == null);
    const second_line = try std.fmt.allocPrint(
        testing.allocator,
        "Referer: http://127.0.0.1:{d}/first\r\n",
        .{port},
    );
    defer testing.allocator.free(second_line);
    try testing.expect(std.mem.indexOf(u8, second, second_line) != null);

    // The third names the second, so each hop starts from the caller's
    // list again and no chain gathers two values.
    const third = server.requestHead(2).?;
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(third, "referer"));
    const third_line = try std.fmt.allocPrint(
        testing.allocator,
        "Referer: http://127.0.0.1:{d}/second\r\n",
        .{port},
    );
    defer testing.allocator.free(third_line);
    try testing.expect(std.mem.indexOf(u8, third, third_line) != null);

    // Every other header the caller wrote still travels.
    try testing.expectEqual(@as(usize, 1), test_server.countHeaders(third, "x-keep"));
}

test "a chain with no auto_referer sends the caller's own Referer to every hop" {
    // The guard on the flag itself. Measured: `-L -e 'http://a/'` sent
    // that one value on both hops, so the automatic half must reach no
    // transfer that did not ask for it.
    const test_server = @import("test_server.zig");
    var server: test_server.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try std.fmt.allocPrint(
        testing.allocator,
        "http://127.0.0.1:{d}/first",
        .{server.port()},
    );
    defer testing.allocator.free(url_text);

    const headers = [_]std.http.Header{.{ .name = "Referer", .value = "http://written.test/" }};
    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &headers,
        .redirects = .{ .follow = 5 },
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    for (0..2) |hop| {
        const head = server.requestHead(hop).?;
        try testing.expectEqual(@as(usize, 1), test_server.countHeaders(head, "referer"));
        try testing.expect(std.mem.indexOf(u8, head, "http://written.test/") != null);
    }
}

test "peerAnswered says whether any peer answered the last open" {
    // **This is the signal a `--retry` reads before it sends a request
    // again.** A request the peer answered has been acted on, so a caller
    // that resent it would ask the peer to act twice.
    const test_server = @import("test_server.zig");

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    // Before any open at all: nobody has answered anything.
    try testing.expect(!http_engine.peerAnswered());

    {
        var server: test_server.TestServer = undefined;
        try server.start(&.{"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"});
        defer server.stop();

        const url_text = try std.fmt.allocPrint(
            testing.allocator,
            "http://127.0.0.1:{d}/x",
            .{server.port()},
        );
        defer testing.allocator.free(url_text);

        const exchange = try http_engine.interface().open(.{
            .method = .GET,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .redirects = .unfollowed,
        });
        defer exchange.close();
        try testing.expectEqual(@as(u16, 503), exchange.head().status);
        // A status is an answer, whatever the status says.
        try testing.expect(http_engine.peerAnswered());
    }

    {
        // A port nobody listens on. The request never left this machine,
        // so no peer can have acted on it, and a retry of it is safe.
        const dead_port = try test_server.closedPort("127.0.0.1");

        const url_text = try std.fmt.allocPrint(
            testing.allocator,
            "http://127.0.0.1:{d}/x",
            .{dead_port},
        );
        defer testing.allocator.free(url_text);

        try testing.expectError(error.CouldNotConnect, http_engine.interface().open(.{
            .method = .GET,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .redirects = .unfollowed,
        }));
        // And the flag of the open before this one is gone, so a caller
        // cannot read a stale answer.
        try testing.expect(!http_engine.peerAnswered());
    }
}

// ---------------------------------------------------------------------
// The HTTP/3 route: `--http3` and `--http3-only`, from `Request` to the
// `h3` engine and back.
//
// Every test below drives a real QUIC connection to
// `h3_test_server.zig`, which binds 127.0.0.1 on a port the operating
// system picks. **No test here touches the real network.** The fixture
// holds a self-signed certificate for `zurl.test`, so a test that wants
// the transfer to run names that host, moves the dial to the loopback
// address with a `connect_to` entry, and says `insecure`. A test about
// verification is the one that leaves `insecure` off.
// ---------------------------------------------------------------------

const h3_test_server_mod = @import("h3_test_server.zig");

/// The `connect_to` entry every HTTP/3 test uses.
///
/// An empty `from_host` matches every host, so a chain that redirects to a
/// second name still dials the fixture. `to_port` is null, which keeps the
/// port the url named, so two names on one fixture stay two origins.
fn h3LoopbackOverride() [1]engine.HostOverride {
    return .{.{ .to_host = "127.0.0.1" }};
}

/// The url of one path on the fixture, under the host name its certificate
/// carries.
fn h3Url(port: u16, path: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        testing.allocator,
        "https://" ++ h3_test_server_mod.host_name ++ ":{d}{s}",
        .{ port, path },
    );
}

test "a request under --http3 goes out over QUIC and comes back as HTTP/3" {
    // **This is the route the whole task is about.** The flag sets
    // `Request.http_version`, `h3Choice` answers `.quic`, `sendOnH3`
    // opens the connection, and the answer arrives through the same
    // `engine.Exchange` seam HTTP/1.1 and HTTP/2 report through.
    var server: h3_test_server_mod = .{};
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "text/plain" },
            .{ .name = "content-length", .value = "5" },
        },
        .body = "hello",
    }});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try h3Url(server.port(), "/page");
    defer testing.allocator.free(url_text);
    const overrides = h3LoopbackOverride();

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .http_version = .http_3,
        .insecure = true,
        .connect_to = &overrides,
    });
    defer exchange.close();

    const head = exchange.head();
    try testing.expectEqual(@as(u16, 200), head.status);
    // **What `-w %{http_version}` reads.** curl 8.21.0 prints `3` for an
    // HTTP/3 transfer, measured against `https://www.cloudflare.com/`.
    try testing.expectEqual(engine.WireVersion.http_3, head.wire_version);
    try testing.expectEqual(@as(?u64, 5), head.content_length);

    // **What `-D` writes.** The version and the status, with no reason
    // phrase, which is the shape curl writes for HTTP/2 as well.
    const block = head.final_headers.?;
    try testing.expect(std.mem.startsWith(u8, block, "HTTP/3 200 \r\n"));
    try testing.expect(std.mem.indexOf(u8, block, "content-type: text/plain\r\n") != null);

    // And the body reads back whole.
    var buffer: [64]u8 = undefined;
    const reader = exchange.bodyReader(&buffer);
    var sink: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&sink);
    _ = try reader.streamRemaining(&out);
    try testing.expectEqualStrings("hello", out.buffered());

    // The `:authority` the request carried is the url's own host and
    // port, which is the rule that writes the `host:` line over HTTP/1.1.
    const request_head = server.requestHead(0).?;
    try testing.expect(std.mem.indexOf(u8, request_head, ":authority: " ++
        h3_test_server_mod.host_name) != null);
    try testing.expect(std.mem.indexOf(u8, request_head, ":path: /page") != null);
    try testing.expect(std.mem.indexOf(u8, request_head, ":scheme: https") != null);
}

test "a cross-origin redirect over HTTP/3 withholds the credential" {
    // **This is the test the HTTP/3 report called vacuous, made real.**
    // Nothing used to build an `h3.Open`, so no credential had ever passed
    // through that engine and the rule held for a file no caller reached.
    // The route exists now, so this drives a real credential through a
    // real QUIC connection and reads the wire back.
    //
    // The rule itself is `h1.Engine.open`'s and not the engine's: a
    // credentialed request that meets a redirect is sent again, from the
    // first hop, with no secrets at all. So HTTP/3 withholds exactly what
    // HTTP/1.1 withholds, and `h3.zig` holds no copy of the rule.
    //
    // Three replies, because `open` sends one probe and throws its answer
    // away: the probe, then the two hops of the chain the resend walks.
    var server: h3_test_server_mod = .{};
    try server.start(&.{
        .{ .fields = &.{
            .{ .name = ":status", .value = "302" },
            .{ .name = "location", .value = "https://other.test:1/second" },
        } },
        .{ .fields = &.{
            .{ .name = ":status", .value = "302" },
            .{ .name = "location", .value = "https://other.test:1/second" },
        } },
        .{ .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        }, .body = "ok" },
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try h3Url(server.port(), "/first");
    defer testing.allocator.free(url_text);
    // **The second hop is a second origin.** `other.test` is not the host
    // the first url named, and the port differs too, so nothing about this
    // chain is same-origin. Both names dial the fixture, because the entry
    // matches every host, and the port of the target url is rewritten to
    // the fixture's own.
    const overrides = [_]engine.HostOverride{.{ .to_host = "127.0.0.1", .to_port = server.port() }};

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .secrets = &.{.{ .name = "Authorization", .value = "Basic c2VjcmV0" }},
        .redirects = .{ .follow = 3 },
        .http_version = .http_3,
        .insecure = true,
        .connect_to = &overrides,
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try testing.expectEqual(engine.WireVersion.http_3, exchange.head().wire_version);
    // The caller asked for a credential and got an answer built without
    // one, and the exchange says so. Recovery is never silent.
    try testing.expect(exchange.head().credential_withheld);

    // The probe carried the secret, because it never left the origin the
    // url named.
    try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "c2VjcmV0") != null);
    // Neither hop of the chain carried it, the first one included. The
    // engine compares no origins: it drops every secret on the first hop
    // rather than decide which hop may keep one.
    try testing.expect(std.mem.indexOf(u8, server.requestHead(1).?, "c2VjcmV0") == null);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(2).?, "c2VjcmV0") == null);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(2).?, "authorization") == null);
    // And the last hop really is the second origin.
    try testing.expect(std.mem.indexOf(u8, server.requestHead(2).?, ":authority: other.test") != null);
}

test "--location-trusted is the one way a credential crosses an HTTP/3 redirect" {
    // The mirror of the test above. `Request.trusted_secrets` is the only
    // branch in this engine that lets a secret leave the origin the url
    // names, and it reaches HTTP/3 the same way it reaches HTTP/1.1:
    // `Engine.open` walks the chain with the secrets instead of without
    // them, and no engine below knows the difference.
    //
    // Two replies and no probe, because a trusted chain sends no probe.
    var server: h3_test_server_mod = .{};
    try server.start(&.{
        .{ .fields = &.{
            .{ .name = ":status", .value = "302" },
            .{ .name = "location", .value = "https://other.test:1/second" },
        } },
        .{ .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        }, .body = "ok" },
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try h3Url(server.port(), "/first");
    defer testing.allocator.free(url_text);
    const overrides = [_]engine.HostOverride{.{ .to_host = "127.0.0.1", .to_port = server.port() }};

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .secrets = &.{.{ .name = "Authorization", .value = "Basic c2VjcmV0" }},
        .redirects = .{ .follow = 3 },
        .trusted_secrets = true,
        .http_version = .http_3,
        .insecure = true,
        .connect_to = &overrides,
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    // Nothing was withheld, so nothing is reported as withheld.
    try testing.expect(!exchange.head().credential_withheld);
    // Both hops carried it, the cross-origin one included.
    try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "c2VjcmV0") != null);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(1).?, "c2VjcmV0") != null);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(1).?, ":authority: other.test") != null);
}

test "a certificate that does not verify fails over HTTP/3" {
    // **The chain walk is reached over QUIC, and it refuses.** The fixture
    // signs its own certificate, and this engine holds no root that issued
    // it, so `lib/zurl-tls/Client.zig` refuses the chain and the transfer
    // ends at exit 60 with no body. `-k` is the only way past it, which
    // the second half of this test shows.
    //
    // The two halves differ in one input and in nothing else. That is the
    // whole point: `connectH3` reads `req.insecure` once, the way
    // `tlsSetup` reads it once, and no other input can reach the second
    // answer.
    var server: h3_test_server_mod = .{};
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "ok",
    }});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try h3Url(server.port(), "/");
    defer testing.allocator.free(url_text);
    const overrides = h3LoopbackOverride();

    // **`--http3-only`, so nothing falls back.** A fallback here would
    // dial TCP against a UDP socket and report the wrong fault, and the
    // test would then say nothing about the certificate.
    try testing.expectError(error.PeerFailedVerification, http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .http_version = .http_3_only,
        .connect_to = &overrides,
    }));

    // The same transfer with `-k` runs, so the refusal above was the
    // certificate and not the transport.
    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .http_version = .http_3_only,
        .insecure = true,
        .connect_to = &overrides,
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
}

test "a request body, a cookie jar, and a HEAD all work over HTTP/3" {
    // Everything the command line does above the engine has to work here
    // too, so each of the three is driven through the route and read back
    // off the wire.
    var server: h3_test_server_mod = .{};
    try server.start(&.{
        .{ .fields = &.{
            .{ .name = ":status", .value = "201" },
            .{ .name = "content-length", .value = "4" },
            .{ .name = "set-cookie", .value = "sid=1; Path=/" },
        }, .body = "made" },
        .{ .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "99" },
        } },
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try h3Url(server.port(), "/upload");
    defer testing.allocator.free(url_text);
    const overrides = h3LoopbackOverride();

    var jar: TestJar = .{ .answer = "hop=one" };
    var payload: TestBody = .{ .bytes = "k=v" };

    {
        const exchange = try http_engine.interface().open(.{
            .method = .POST,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .redirects = .unfollowed,
            .http_version = .http_3,
            .insecure = true,
            .connect_to = &overrides,
            .cookies = jar.interface(),
            .body = payload.source(),
        });
        defer exchange.close();
        try testing.expectEqual(@as(u16, 201), exchange.head().status);
    }

    // The body reached the peer, with the length in front of it.
    try testing.expectEqualStrings("k=v", server.requestBody(0).?);
    try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "content-length: 3") != null);
    // The jar was asked for this hop's url, and its line went out.
    try testing.expectEqual(@as(usize, 1), jar.asked_count);
    try testing.expectEqualStrings("/upload", jar.askedText(0));
    try testing.expect(std.mem.indexOf(u8, server.requestHead(0).?, "cookie: hop=one") != null);
    // And the `set-cookie` the peer sent reached the jar.
    try testing.expectEqual(@as(usize, 1), jar.received_count);
    try testing.expectEqualStrings("sid=1; Path=/", jar.receivedText(0));

    // **A `HEAD` reports no body whatever the head announced.** RFC 9110
    // section 9.3.2, and the number `-w %{size_download}` reads has to be
    // the bytes that are coming and not the number the peer wrote.
    const head_url = try h3Url(server.port(), "/thing");
    defer testing.allocator.free(head_url);
    const exchange = try http_engine.interface().open(.{
        .method = .HEAD,
        .url = try zurl_core.url.parse(head_url),
        .headers = &.{},
        .redirects = .unfollowed,
        .http_version = .http_3,
        .insecure = true,
        .connect_to = &overrides,
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
    try testing.expectEqual(@as(?u64, 0), exchange.head().content_length);
}

test "a redirect chain over HTTP/3 keeps one head block for each hop" {
    // What `-D -L` writes, and what `-w %{url_effective}` reads. Both come
    // off the same chain the engine walked, and both have to work over
    // HTTP/3 exactly as they work over HTTP/1.1.
    var server: h3_test_server_mod = .{};
    try server.start(&.{
        .{ .fields = &.{
            .{ .name = ":status", .value = "301" },
            .{ .name = "location", .value = "/second" },
        } },
        .{ .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        }, .body = "ok" },
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try h3Url(server.port(), "/first");
    defer testing.allocator.free(url_text);
    const overrides = h3LoopbackOverride();

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .{ .follow = 3 },
        .http_version = .http_3,
        .insecure = true,
        .connect_to = &overrides,
    });
    defer exchange.close();

    const head = exchange.head();
    try testing.expectEqual(@as(u16, 200), head.status);
    // One block for each hop, in the order they arrived, which is what
    // `curl -D - -L` writes.
    const all = head.headers.?;
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, all, "HTTP/3 "));
    try testing.expect(std.mem.startsWith(u8, all, "HTTP/3 301 \r\n"));
    try testing.expect(std.mem.startsWith(u8, head.final_headers.?, "HTTP/3 200 \r\n"));
    // The url the transfer finished on.
    try testing.expect(std.mem.endsWith(u8, head.effective_url.?, "/second"));
}

test "the caller's stop flag ends an HTTP/3 transfer, and --http3 does not fall back on it" {
    // **This is what `-m`/`--max-time` needs over QUIC.** The caller's own
    // cancel reaches a blocked TCP read and does not reach a datagram
    // wait, so the caller hands the flag down and every QUIC wait reads
    // it. Measured before the flag existed: `--http3 --max-time 0.05`
    // against a 1.3 MB page exited 0 with the whole body, where the same
    // page over HTTP/2 exited 28.
    //
    // **And the fallback must not answer it.** A cancelled QUIC hop that
    // went out over TCP instead would finish the transfer the bound was
    // there to stop, which is what happened before `h3Fallback` refused
    // this fault by name. The flag is raised before the transfer here, so
    // a hop that fell back would answer 200 and fail this test.
    var server: h3_test_server_mod = .{};
    try server.start(&.{.{
        .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = "2" },
        },
        .body = "ok",
    }});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try h3Url(server.port(), "/");
    defer testing.allocator.free(url_text);
    const overrides = h3LoopbackOverride();

    var stop: std.atomic.Value(bool) = .init(true);
    try testing.expectError(error.Canceled, http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        // `--http3` and not `--http3-only`, so a hop that fell back would
        // be answered by the loopback server and this test would pass a
        // 200 back instead of the fault.
        .http_version = .http_3,
        .insecure = true,
        .connect_to = &overrides,
        .stop = &stop,
    }));
    // Nothing fell back, so nothing was counted as a fallback.
    try testing.expectEqual(@as(usize, 0), http_engine.h3_fallbacks);

    // With the flag down the same transfer runs, so the refusal above was
    // the flag and nothing else.
    stop.store(false, .release);
    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .http_version = .http_3,
        .insecure = true,
        .connect_to = &overrides,
        .stop = &stop,
    });
    defer exchange.close();
    try testing.expectEqual(@as(u16, 200), exchange.head().status);
}

test "a QUIC fault that is not about HTTP/3 is never answered with HTTP/2" {
    // `h3Fallback` is the whole rule, read one fault at a time. Each of
    // the three below would turn a fault the user has to act on into a
    // transfer over another protocol.
    try testing.expect(!h3Fallback(error.Canceled));
    try testing.expect(!h3Fallback(error.PeerFailedVerification));
    try testing.expect(!h3Fallback(error.OutOfMemory));

    // And every fault that says "there is no HTTP/3 here" does fall back,
    // which is the whole point of `--http3`.
    try testing.expect(h3Fallback(error.CouldNotConnect));
    try testing.expect(h3Fallback(error.OperationTimedOut));
    try testing.expect(h3Fallback(error.SslConnectError));
    try testing.expect(h3Fallback(error.ReadError));
}

test "h3Choice answers for every command line, and HTTP/3 is never the default" {
    // The whole routing decision, read one input at a time. Each row is
    // measured against curl 8.21.0; see the doc comment of `h3Choice`.
    const direct: Route = .{
        .proxy = null,
        .host = "example.com",
        .port = 443,
        .proxied_head = null,
        .tls = .origin,
        .step = null,
    };
    const proxied: Route = .{
        .proxy = .{ .host = "127.0.0.1", .port = 3128, .kind = .http },
        .host = "127.0.0.1",
        .port = 3128,
        .proxied_head = null,
        .tls = .none,
        .step = null,
    };

    var req: engine.Request = .{
        .method = .GET,
        .url = try zurl_core.url.parse("https://example.com/"),
        .headers = &.{},
        .redirects = .unfollowed,
    };

    // **No version flag never opens QUIC.** HTTP/3 is not the default, and
    // this is the line that says so.
    for ([_]engine.HttpVersion{ .any, .http_1_1, .http_2, .prior_knowledge }) |version| {
        req.http_version = version;
        try testing.expectEqual(H3Choice.tcp, h3Choice(req, .tls, direct));
        try testing.expectEqual(H3Choice.tcp, h3Choice(req, .plain, direct));
    }

    // The two flags that do open it, on a TLS hop with no proxy.
    req.http_version = .http_3;
    try testing.expectEqual(H3Choice.quic, h3Choice(req, .tls, direct));
    req.http_version = .http_3_only;
    try testing.expectEqual(H3Choice.quic, h3Choice(req, .tls, direct));

    // A hop through a proxy never opens QUIC, whichever flag asked.
    req.http_version = .http_3;
    try testing.expectEqual(H3Choice.tcp, h3Choice(req, .tls, proxied));
    req.http_version = .http_3_only;
    try testing.expectEqual(H3Choice.tcp, h3Choice(req, .tls, proxied));

    // And a cleartext url parts the two flags: one falls back, one is
    // refused. Measured: `curl --http3 http://example.com/` answered on
    // HTTP/1.1 and exited 0, and `curl --http3-only http://example.com/`
    // wrote `HTTP/3 requested for non-HTTPS URL` and exited 3.
    req.http_version = .http_3;
    try testing.expectEqual(H3Choice.tcp, h3Choice(req, .plain, direct));
    req.http_version = .http_3_only;
    try testing.expectEqual(H3Choice.refuse_cleartext, h3Choice(req, .plain, direct));
}

test "--http3 on a cleartext url runs over HTTP/1.1, and --http3-only refuses it" {
    // The `.tcp` and the `.refuse_cleartext` arms of `h3Choice`, driven
    // end to end against a loopback listener. No QUIC socket is opened on
    // either path.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    {
        const exchange = try http_engine.interface().open(.{
            .method = .GET,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .redirects = .unfollowed,
            .http_version = .http_3,
        });
        defer exchange.close();
        try testing.expectEqual(@as(u16, 200), exchange.head().status);
        try testing.expectEqual(engine.WireVersion.http_1_1, exchange.head().wire_version);
    }
    // The fallback is counted, so it is not silent. A cleartext hop under
    // `--http3` opened no QUIC connection at all, so nothing fell back
    // here and the count stays zero.
    try testing.expectEqual(@as(usize, 0), http_engine.h3_fallbacks);

    try testing.expectError(error.InvalidUrl, http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .http_version = .http_3_only,
    }));
    try testing.expectEqualStrings(
        http3_cleartext_message,
        http_engine.interface().cause().?,
    );
}

test "--http3 falls back to the TCP hop when QUIC does not answer" {
    // **The fallback curl makes, with no word on standard error.**
    // Measured against curl 8.21.0 and `https://example.com/`, a host with
    // no HTTP/3: exit 0 and `%{http_version} 2`.
    //
    // Here the peer is a closed UDP port on the loopback address, so the
    // QUIC handshake ends at once and the hop goes out over TCP instead.
    // The url is a cleartext one on the fixture's own port, which is what
    // makes the TCP half of this reachable with no TLS listener: the QUIC
    // attempt is forced by naming `.tls` in the request and the fallback
    // is read back through `h3_fallbacks`.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"});
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{
        // A short bound, so a network that drops the datagram with no
        // reply does not hold this test for the whole default.
        .connect_timeout = .{ .duration = .{ .raw = .fromMilliseconds(400), .clock = .awake } },
    });
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    // `--http3` on a cleartext url opens no QUIC connection, so this
    // test drives the QUIC attempt through `sendOnH3` directly: it is the
    // one call the fallback path wraps, and a failure of it is what the
    // fallback answers.
    const dead_port = try test_server_mod.closedPort("127.0.0.1");
    const host: zurl_net.tcp.Host = try .init("127.0.0.1");
    const route: Route = .{
        .proxy = null,
        .host = "127.0.0.1",
        .port = dead_port,
        .proxied_head = null,
        .tls = .origin,
        .step = null,
    };
    var answered = false;
    try testing.expectError(error.CouldNotConnect, sendOnH3(
        &http_engine,
        .{
            .method = .GET,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .redirects = .unfollowed,
            .http_version = .http_3,
            .insecure = true,
        },
        requestUri("https", try zurl_core.url.parse(url_text)),
        &.{},
        host,
        route,
        &answered,
    ));
    // The peer answered nothing, which is what lets the caller send the
    // same request again over TCP.
    try testing.expect(!answered);
}

// The tests below cover the response framing grammar, the challenge a
// redirect target may not offer, and the zstd window count. Each one fails
// without the change it names.

test "a Content-Length that is not 1*DIGIT is refused" {
    // **The framing finding.** `std.http.Client.Response.Head.parse` reads
    // this field with `std.fmt.parseInt`, which takes a leading `+` and
    // Zig's `_` digit separators, so `+5` framed five octets and `1_0`
    // framed ten. Measured against curl 8.21.0 on a loopback listener with
    // a body of `ABCDEFGHIJ`: curl exited 8 and wrote nothing for both,
    // and zurl exited 0 and wrote the body.
    //
    // A client that frames a response where no compliant parser in the
    // path frames it is the response-splitting half of request smuggling.
    const cases = [_][]const u8{ "+5", "1_0", "-5", "5, 5", "0x5" };
    for (cases) |value| {
        const reply = try std.fmt.allocPrint(
            testing.allocator,
            "HTTP/1.1 200 OK\r\nContent-Length: {s}\r\nConnection: close\r\n\r\nABCDEFGHIJ",
            .{value},
        );
        defer testing.allocator.free(reply);

        var server: test_server_mod.TestServer = undefined;
        try server.start(&.{reply});
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();

        const url_text = try loopbackUrl(&server);
        defer testing.allocator.free(url_text);

        try testing.expectError(error.ReadError, http_engine.interface().open(.{
            .method = .GET,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .redirects = .unfollowed,
        }));
    }
}

test "a Content-Length with leading zeroes is read, because curl reads it" {
    // RFC 9112 section 6.2 writes `1*DIGIT`, and `005` is that. Measured
    // against curl 8.21.0 on the same listener: exit 0, and `ABCDE`
    // written. The grammar check must not reach past what the grammar
    // says.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Length: 005\r\nConnection: close\r\n\r\nABCDEFGHIJ",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
    });
    defer exchange.close();

    try testing.expectEqual(@as(?u64, 5), exchange.head().content_length);
}

test "a second Content-Length that is malformed is refused whatever the order" {
    // Every field of the head is read, not the first one. A head that
    // carries one legal length and one illegal one is a head no two
    // parsers in a path agree about.
    const heads = [_][]const u8{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: +5\r\nConnection: close\r\n\r\nABCDEFGHIJ",
        "HTTP/1.1 200 OK\r\nContent-Length: +5\r\nContent-Length: 5\r\nConnection: close\r\n\r\nABCDEFGHIJ",
    };
    for (heads) |reply| {
        var server: test_server_mod.TestServer = undefined;
        try server.start(&.{reply});
        defer server.stop();

        var http_engine: Engine = .init(testing.allocator, testing.io, .{});
        defer http_engine.deinit();

        const url_text = try loopbackUrl(&server);
        defer testing.allocator.free(url_text);

        try testing.expectError(error.ReadError, http_engine.interface().open(.{
            .method = .GET,
            .url = try zurl_core.url.parse(url_text),
            .headers = &.{},
            .redirects = .unfollowed,
        }));
    }
}

test "a chunk size holding an octet that is not a hexadecimal digit is refused" {
    // **`std.http.ChunkParser` folds the whole alphabet into the value.**
    // `'a'...'z' => |b| b - 'a' + 10` reads `g` as 16, so `1g` was read as
    // 32 where curl 8.21.0 read it as 1: curl exited 56 after one octet,
    // and zurl exited 0 after 32.
    try testing.expectError(error.ReadFailed, firstChunkOctet("1g"));
    try testing.expectError(error.ReadFailed, firstChunkOctet("1z"));
    try testing.expectError(error.ReadFailed, firstChunkOctet("1G"));
    try testing.expectError(error.ReadFailed, firstChunkOctet("1Z"));
    // `0x5` is the same defect wearing a familiar prefix: `x` is folded in
    // as 33. curl gave exit 8 for it.
    try testing.expectError(error.ReadFailed, firstChunkOctet("0x5"));
}

test "a chunk size field with no hexadecimal digit at all is refused" {
    // **This one reported success.** Every octet the parser does not fold
    // starts a chunk extension, so a size field beginning with one leaves
    // the value at zero, which `std` reads as the last chunk. The body
    // ended there, the octets behind it stayed on the connection, and the
    // transfer exited 0. On a connection the pool keeps, those octets are
    // the head of the next response.
    //
    // Measured against curl 8.21.0: ` 5` and `+5` both gave exit 56.
    try testing.expectError(error.ReadFailed, firstChunkOctet(" 5"));
    try testing.expectError(error.ReadFailed, firstChunkOctet("+5"));
    try testing.expectError(error.ReadFailed, firstChunkOctet(";ext=1"));
}

test "a chunk extension and a trailing space still frame a body" {
    // The legal shapes, and the check must not reach them. A chunk
    // extension starts at the first octet the parser does not fold, so `;`
    // and a space both leave the value alone. Measured against curl
    // 8.21.0: `5;ext=1`, `5 ` and `05` each gave exit 0 and `ABCDE`.
    try testing.expectEqual(@as(u8, 'a'), try firstChunkOctet("5;ext=1"));
    try testing.expectEqual(@as(u8, 'a'), try firstChunkOctet("5 "));
    try testing.expectEqual(@as(u8, 'a'), try firstChunkOctet("05"));
}

test "a challenge from a redirect target is not reported to the caller" {
    // **The credential-over-chosen-parameters finding.** The engine walks
    // the whole chain inside one `open`, so the head the caller reads is
    // the last hop's. A redirect target that answers `401` therefore chose
    // the `realm` and the `nonce` a Digest response would be computed
    // under, and `zurl.Client` sent that response to the url the caller
    // named, which never issued the challenge.
    //
    // The chain past its first hop carries no secret. The rule here is the
    // mirror: a hop that may not carry the credential may not have its
    // challenge answered.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"attacker\", nonce=\"chosen\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .{ .follow = 3 },
    });
    defer exchange.close();

    try testing.expectEqual(@as(u16, 401), exchange.head().status);
    try testing.expectEqual(@as(?[]const u8, null), exchange.head().www_authenticate);
}

test "a challenge from the first hop of a chain is still reported" {
    // The rule must take only the hops a server chose. A `401` on the url
    // the caller named is the ordinary start of every authenticated
    // exchange, and refusing to report it would stop `--digest` working at
    // all.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"test\", nonce=\"abc\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .{ .follow = 3 },
    });
    defer exchange.close();

    try testing.expectEqualStrings(
        "Digest realm=\"test\", nonce=\"abc\"",
        exchange.head().www_authenticate.?,
    );
}

test "--location-trusted keeps the challenge a redirect target offers" {
    // The flag says the whole chain may hold the secret, so every hop of
    // it is a hop the caller named as trusted, and a challenge from one is
    // the caller's to answer. The same `followChain` walks the same hops.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"named\", nonce=\"abc\"\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .secrets = &.{.{ .name = "Authorization", .value = "Basic Ym9iOmh1bnRlcjI=" }},
        .redirects = .{ .follow = 3 },
        .trusted_secrets = true,
    });
    defer exchange.close();

    try testing.expectEqualStrings(
        "Digest realm=\"named\", nonce=\"abc\"",
        exchange.head().www_authenticate.?,
    );
}

test "the zstd window count is bounded and every window is given back" {
    // **The 8.1 MiB per exchange finding.** The size of one window is the
    // RFC 8878 ceiling and cannot come down. What was unbounded is how
    // many of them live at once: every exchange answered `zstd` took one
    // and nothing counted them.
    //
    // This drives the counter directly, because holding
    // `zstd_windows_max + 1` real exchanges open would hold 73 MiB of test
    // memory to prove an arithmetic rule.
    const pool = try Pool.create(testing.allocator, testing.io);
    defer pool.destroy();

    var taken: usize = 0;
    while (pool.takeZstdWindow()) taken += 1;
    try testing.expectEqual(zstd_windows_max, taken);
    try testing.expectEqual(zstd_windows_max, pool.zstd_windows);

    // One that closed gives its room back, and the next exchange gets it.
    pool.releaseZstdWindow();
    try testing.expect(pool.takeZstdWindow());
    try testing.expect(!pool.takeZstdWindow());

    while (taken != 0) : (taken -= 1) pool.releaseZstdWindow();
    try testing.expectEqual(@as(usize, 0), pool.zstd_windows);
}

test "a zstd answer takes a window and closing the exchange gives it back" {
    // The count follows a real exchange, not only the arithmetic. The
    // reply is not valid zstd, so a body read would fail, and the head is
    // all this test reads: the window is taken from the head's
    // `Content-Encoding` and freed by `close`.
    var server: test_server_mod.TestServer = undefined;
    try server.start(&.{
        "HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
    });
    defer server.stop();

    var http_engine: Engine = .init(testing.allocator, testing.io, .{});
    defer http_engine.deinit();

    const url_text = try loopbackUrl(&server);
    defer testing.allocator.free(url_text);

    const exchange = try http_engine.interface().open(.{
        .method = .GET,
        .url = try zurl_core.url.parse(url_text),
        .headers = &.{},
        .redirects = .unfollowed,
        .accept_encoding = true,
    });
    try testing.expectEqual(@as(usize, 1), http_engine.pool.?.zstd_windows);
    exchange.close();
    try testing.expectEqual(@as(usize, 0), http_engine.pool.?.zstd_windows);
}
