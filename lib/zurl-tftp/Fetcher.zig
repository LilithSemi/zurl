//! Runs one `tftp://` download: the read request, the block
//! acknowledgement, and the retransmission. RFC 1350.
//!
//! **This is the one protocol package that reads no stream.** There is no
//! connection and no `zurl_net.Connection`: a TFTP transfer is a series of
//! datagrams, each one acknowledged, and the client is what recovers a
//! datagram the network dropped. `std.Io.net.IpAddress.bind` with
//! `.mode = .dgram` gives the socket, and `Socket.receiveTimeout` gives
//! the bound that every retransmission is built on.
//!
//! A `Fetcher` owns the file of the transfer in play. `open` frees
//! whatever the last call left and holds the new one, so one `Fetcher`
//! serves one transfer at a time.
//!
//! **A `Fetcher` must not move once `open` has run.** The body reader it
//! hands back points into this value. Keep one where it will stay, and
//! pass a pointer.
//!
//! **Every bound this transfer keeps**, and what passing one does:
//!
//! - `Options.max_response_bytes`, the size of the file.
//!   `error.FileSizeExceeded`, exit 63.
//! - `Options.block_timeout` and `Options.max_retries`, the wait for one
//!   datagram and how many times it is asked for again. A peer that never
//!   answered at all is `error.CouldNotConnect`, exit 7, and one that
//!   answered and then stopped is `error.OperationTimedOut`, exit 28.
//! - a count of datagrams, computed from the two bounds above. A server
//!   that answers forever with blocks already acknowledged never grows the
//!   file, so the size bound alone would not stop it.
//!   `error.OperationTimedOut`, exit 28.
//!
//! What this does not do: no upload, because that is `WRQ` and this build
//! has no `-T` for a `tftp://` url. No `netascii` mode, because this build
//! has no `-B`.
//!
//! `Options.send_options` is `--tftp-no-options` and `Options.block_size`
//! is `--tftp-blksize`. With neither one named the request carries the
//! options curl's own default carries.
//!
//! This file imports `zurl-core` and `zurl-net`. It does not import
//! `zurl`, and it never will. See `protocol`.

const Fetcher = @This();

const std = @import("std");
const zurl_core = @import("zurl-core");
const zurl_net = @import("zurl-net");

const packet = @import("packet.zig");

const Io = std.Io;
const Error = zurl_core.Error;
const Diagnostics = zurl_core.Diagnostics;

/// The scheme this package handles.
pub const scheme = "tftp";

/// The port a `tftp` url uses when it names none. RFC 1350 assigns 69.
pub const default_port: ?u16 = 69;

/// The status a `tftp://` transfer reports.
///
/// Zero, because RFC 1350 has no status: a server either sends the file or
/// sends an `err` packet. This is what curl reports for `%{http_code}` on
/// a protocol with no status of its own.
pub const status: u16 = 0;

/// How many bytes of file this package reads by default.
///
/// A TFTP file has a length only when the server answers the `tsize`
/// option, and RFC 2347 lets it answer nothing. So the transfer needs a
/// bound of its own, and this is it.
///
/// 16 MiB is far past the boot images and configuration files TFTP is used
/// for. It is also under the 32 MiB where a 16 bit block number would wrap
/// at 512 bytes a block, which is why nothing here has to read a wrapped
/// block number: the size bound stops the transfer first. See
/// `blockCeiling`.
pub const default_max_response_bytes: u64 = 16 * 1024 * 1024;

/// How long one datagram is waited for before it is asked for again.
///
/// One second, which is shorter than the six the request's own `timeout`
/// option asks the server for. See `packet.default_server_timeout_seconds`.
/// The shorter of the two is the client's, so the client asks for a block
/// again before the server would send it, and the recovery is the client's.
pub const default_block_timeout: Io.Timeout = .{
    .duration = .{ .raw = .fromSeconds(1), .clock = .awake },
};

/// How many times one datagram is asked for again before the transfer
/// gives up.
///
/// Five, so a transfer on a lossy path costs at most six seconds for one
/// block at the default timeout, and a peer that has gone away is reported
/// rather than waited on forever.
pub const default_max_retries: usize = 5;

allocator: std.mem.Allocator,
io: Io,
/// The file of the transfer in play, or null when none is held. `open`
/// frees this before it reads another, and `deinit` frees it.
file: ?[]u8,
/// Reads `file`. Valid only while `file` holds something.
body: Io.Reader,
/// Backs the read request. A field and not a stack buffer, so the bound is
/// one named number and not a frame size.
request_storage: [packet.max_request_bytes]u8,
/// Holds the percent-decoded file name.
name_storage: [packet.max_filename_bytes]u8,
/// Holds one datagram from the server.
datagram_storage: [packet.max_datagram_bytes]u8,

/// What one transfer may ask for.
///
/// A struct of this package's own, and not `zurl.Transfer.Options`,
/// because this package must build with no `zurl` in its import table.
/// `Dispatch` fills it from the front package's own options.
pub const Options = struct {
    /// The bound on the file. See `default_max_response_bytes`.
    max_response_bytes: u64 = default_max_response_bytes,
    /// How long one datagram is waited for. `.none` waits forever, which
    /// leaves the transfer with no bound at all and is never what a
    /// caller wants here.
    block_timeout: Io.Timeout = default_block_timeout,
    /// How many times one datagram is asked for again.
    max_retries: usize = default_max_retries,
    /// Whether the read request carries the RFC 2347 options. True is
    /// curl's own default, measured. False writes exactly the bytes
    /// `curl --tftp-no-options` writes.
    send_options: bool = true,
    /// The block size the `blksize` option asks for. RFC 2348, and
    /// `curl --tftp-blksize`.
    ///
    /// It lies between `packet.min_block_size` and
    /// `packet.max_block_size`. A number outside that range is
    /// `error.TftpIllegalOperation` before any datagram goes out, and is
    /// never clamped. See `packet.max_block_size` for why the ceiling is
    /// under the one RFC 2348 permits.
    ///
    /// **The server answers with the size it accepts**, which RFC 2348
    /// holds at or below this one. A server that answers with more is a
    /// fault. A `send_options` of false carries no `blksize` at all, so
    /// the transfer then runs at `packet.default_block_size` whatever
    /// this holds.
    block_size: u16 = packet.default_block_size,
    /// Where a url naming one host and port sends its first datagram
    /// instead. This is `--resolve` and `--connect-to`.
    ///
    /// **An entry moves the peer and nothing else.** TFTP writes no host
    /// name into a packet and opens no TLS, so the address is all there is
    /// to move here. The server still answers from a port of its own, and
    /// `sameAddress` still holds every later datagram to the address this
    /// gives. See `zurl_net.override`.
    connect_to: []const zurl_net.override.HostOverride = &.{},
};

/// A `Fetcher` that holds no file yet.
pub fn init(allocator: std.mem.Allocator, io: Io) Fetcher {
    return .{
        .allocator = allocator,
        .io = io,
        .file = null,
        .body = undefined,
        .request_storage = undefined,
        .name_storage = undefined,
        .datagram_storage = undefined,
    };
}

/// Frees the file this `Fetcher` holds. Safe to call more than once, and
/// safe on a `Fetcher` that never opened anything.
pub fn deinit(f: *Fetcher) void {
    f.release();
}

fn release(f: *Fetcher) void {
    const held = f.file orelse return;
    f.allocator.free(held);
    f.file = null;
}

/// The file of one `tftp://` transfer.
pub const Body = struct {
    /// Streams the file. Valid until the next `open` on this `Fetcher`, or
    /// until `deinit`, whichever comes first.
    reader: *Io.Reader,
    /// How many bytes the file holds.
    length: u64,
    /// The size the server announced in its `tsize` option, or null when
    /// it announced none. Always equal to `length` for a transfer that
    /// finished, and reported apart so a caller can see whether the server
    /// answered the option at all.
    announced_size: ?u64,
};

/// The file name `url` asks for.
///
/// The url path with one leading `/` off, percent-decoded. Measured
/// against curl 8.21.0: `tftp://h/hello.txt` names `hello.txt`,
/// `tftp://h/a/b/c.bin` names `a/b/c.bin`, and `tftp://h/f.txt?x=1` names
/// `f.txt`, so the query is not part of the name.
///
/// An escape that does not decode leaves the text alone, which is what
/// `zurl-file`, `zurl-dict`, and `zurl-gopher` all do with one.
fn decodeName(f: *Fetcher, url: zurl_core.Url, d: ?*Diagnostics) Error![]const u8 {
    const path = if (url.path.len > 0 and url.path[0] == '/') url.path[1..] else url.path;
    const out: []u8 = &f.name_storage;
    if (path.len > out.len) return fail(d, error.InvalidUrl, &.{
        "the file name is longer than the ",
        std.fmt.comptimePrint("{d}", .{packet.max_filename_bytes}),
        " bytes zurl sends",
    });

    return zurl_core.url.percentDecode(out, path) catch |err| switch (err) {
        error.InvalidEscape => escape: {
            @memcpy(out[0..path.len], path);
            break :escape out[0..path.len];
        },
        // The decoded form is never longer than the escaped form, and the
        // check above already refused a text that does not fit. A named
        // fault and not an `unreachable`, which a ReleaseFast build turns
        // into undefined behaviour.
        error.NoSpaceLeft => fail(d, error.InvalidUrl, &.{
            "the file name is longer than zurl sends",
        }),
    };
}

/// Downloads what `url` names and returns it.
///
/// Frees whatever the previous call held first, so a `Fetcher` never holds
/// two files at once.
///
/// **The request is byte for byte what curl 8.21.0 sends by default**,
/// measured against a `socat` listener on UDP:
///
/// ```
/// 00 01 'hello.txt' 00 'octet' 00
/// 'tsize' 00 '0' 00 'blksize' 00 '512' 00 'timeout' 00 '6' 00
/// ```
///
/// The faults, and the exit code each carries:
///
/// - a url that names no file at all is `error.TftpIllegalOperation`, exit
///   71, and no datagram goes out. Measured: `curl tftp://127.0.0.1:69/`
///   exits 71 and sends nothing.
/// - a url whose decoded name holds a NUL, a CR, or an LF is
///   `error.InvalidUrl`, exit 3. curl refuses the NUL with the same code,
///   measured on `tftp://h/a%00b`.
/// - a peer that answers nothing is `error.CouldNotConnect`, exit 7.
///   Measured: `curl tftp://127.0.0.1:1/x` with no flag waits about 350
///   seconds and then exits 7, because a refused UDP port is not a refused
///   connection and only the wait says the peer is not there. zurl waits
///   for six tries instead and gives the same number. A peer that answered
///   and then stopped is `error.OperationTimedOut`, exit 28.
/// - an `err` packet is the fault its own code names, exit 68 through 74.
///   See `packet.errorFor`.
/// - a file past `options.max_response_bytes` is `error.FileSizeExceeded`,
///   exit 63, and no byte of it is returned.
pub fn open(f: *Fetcher, url: zurl_core.Url, options: Options, d: ?*Diagnostics) Error!Body {
    f.release();

    const name = try f.decodeName(url, d);
    // curl answers a url that names no file with exit 71 and writes no
    // datagram at all, measured. This is the same answer, before the
    // socket exists.
    if (name.len == 0) return fail(d, error.TftpIllegalOperation, &.{
        "a tftp url names a file, and this one names none",
    });

    const request = packet.writeReadRequest(
        &f.request_storage,
        name,
        .octet,
        options.send_options,
        options.block_size,
    ) catch |err| switch (err) {
        error.RequestTooLong => return fail(d, error.InvalidUrl, &.{
            "the read request this url builds is longer than zurl writes",
        }),
        // **A block size outside the range is refused and never
        // clamped.** curl names this fault `CURLE_TFTP_ILLEGAL`, exit 71,
        // and this gives the same number. A clamp would put digits on the
        // wire that the user never wrote.
        error.BlockSizeOutOfRange => return failNumber(
            d,
            error.TftpIllegalOperation,
            std.fmt.comptimePrint(
                "a tftp block size lies between {d} and {d} bytes, and this transfer asked for ",
                .{ packet.min_block_size, packet.max_block_size },
            ),
            options.block_size,
            "",
        ),
        // **The injection refusal.** A NUL ends the name field of a read
        // request, so `a\x00b` would name the file `a` and read `b` as the
        // transfer mode. See `packet.writeReadRequest`.
        error.NameHasFramingByte => return fail(d, error.InvalidUrl, &.{
            "the file name holds a NUL, a CR, or an LF, and a NUL would end the name field of the request early",
        }),
    };

    const port = url.port orelse return fail(d, error.InvalidUrl, &.{
        "a tftp url names a port, and this one names none",
    });
    // **`--resolve` and `--connect-to` move this peer and nothing else.**
    // A TFTP read request carries a file name and a mode, and no host
    // name at all, so the address is the whole of what an entry reaches.
    // See `zurl_net.override`.
    const target = zurl_net.override.dialTarget(options.connect_to, url.host, port);
    const server = Io.net.IpAddress.resolve(f.io, target.host, target.port) catch
        return fail(d, error.CouldNotResolveHost, &.{ "no address for ", target.host });

    // The local socket takes the address family of the peer and a port the
    // operating system picks. RFC 1350 calls that port the client's own
    // transfer id, and the server answers to it from a port of its own.
    var local: Io.net.IpAddress = switch (server) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const socket = local.bind(f.io, .{ .mode = .dgram }) catch |err| return fail(
        d,
        error.CouldNotConnect,
        &.{ "zurl did not open a udp socket: ", @errorName(err) },
    );
    defer socket.close(f.io);

    return f.run(socket, server, request, options, d);
}

/// The datagram loop: send, wait, acknowledge, and ask again.
///
/// Split out of `open` so the socket has exactly one `defer` that closes
/// it, whichever way this returns.
fn run(
    f: *Fetcher,
    socket: Io.net.Socket,
    server: Io.net.IpAddress,
    request: []const u8,
    options: Options,
    d: ?*Diagnostics,
) Error!Body {
    var collected: std.ArrayList(u8) = .empty;
    defer collected.deinit(f.allocator);

    // The peer this transfer talks to, which is not known until the first
    // datagram arrives. RFC 1350 makes the server answer from a port of
    // its own, so the address in the url is where the request goes and
    // never where the answer comes from.
    //
    // **The port is free and the address is not.** RFC 1350 section 4
    // moves the port and says nothing that lets the address move, so
    // `server` is the rule until this holds a value. See `sameAddress`.
    var peer: ?Io.net.IpAddress = null;
    // The number the request asked for, which bounds what an `oack` may
    // answer. An option free request carries no `blksize` at all, so such
    // a transfer runs at the size RFC 1350 fixes whatever the caller
    // named. See `packet.writeReadRequest`.
    const requested_block_size = if (options.send_options)
        options.block_size
    else
        packet.default_block_size;
    // The size in play. It holds the requested number until the server
    // answers, and the answer never grows it. `negotiated` says whether
    // the answer has arrived: a server that sends a block instead of an
    // `oack` read no option, and RFC 2347 puts that transfer at the RFC
    // 1350 default of 512.
    var block_size: u16 = requested_block_size;
    var negotiated = false;
    var announced_size: ?u64 = null;
    // The block number this transfer is waiting for.
    var wanted: u16 = 1;
    // The block number of the last `ack` written, which is what a
    // retransmission writes again. Zero before any block arrived, which
    // is also the number an `oack` is acknowledged with.
    var last_ack: u16 = 0;
    var acked_anything = false;
    var retries: usize = 0;
    var datagrams: usize = 0;

    // How many datagrams this transfer may read. The number is built from
    // the block size in play, and the negotiation may shrink that size, so
    // it is computed again every time `block_size` moves. A ceiling left
    // at the requested size would stop a transfer that the server moved to
    // a smaller block, because a smaller block needs more datagrams.
    var ceiling = blockCeiling(options.max_response_bytes, block_size);

    socket.send(f.io, &server, request) catch |err| return fail(d, error.CouldNotConnect, &.{
        "zurl did not write the tftp read request: ",
        @errorName(err),
    });

    while (true) {
        datagrams += 1;
        // **The bound that a size bound alone cannot keep.** A server that
        // sends a block this transfer already acknowledged adds no byte to
        // the file, so it could answer forever under the size bound. This
        // counts every datagram instead, at four times the number a
        // transfer of the largest allowed file needs.
        if (datagrams > ceiling) return fail(d, error.OperationTimedOut, &.{
            "the server kept sending datagrams and never finished the file",
        });

        const message = socket.receiveTimeout(
            f.io,
            &f.datagram_storage,
            options.block_timeout,
        ) catch |err| switch (err) {
            error.Timeout => {
                if (retries >= options.max_retries) return failNumber(
                    d,
                    // **A peer that never answered at all is exit 7, and a
                    // transfer that stalled part way is exit 28.**
                    // Measured: `curl tftp://127.0.0.1:1/x` with no flag
                    // retries for about 350 seconds and then exits 7,
                    // `CURLE_COULDNT_CONNECT`. A refused UDP port is not a
                    // refused connection, so nothing but the wait says the
                    // peer is not there, and 7 is the number curl gives
                    // it. Once a block has arrived the peer was there, so
                    // a wait that runs out after that is the transfer
                    // timing out and carries 28.
                    if (acked_anything) error.OperationTimedOut else error.CouldNotConnect,
                    "the tftp server did not answer after ",
                    options.max_retries + 1,
                    " tries",
                );
                retries += 1;
                // Before any block has arrived the request itself is what
                // goes out again, to the port the url named. After one
                // has, the last `ack` goes out again, to the peer's own
                // port. RFC 1350 section 2 puts the recovery on both
                // sides, and this is the client's half of it.
                try f.resend(socket, peer orelse server, request, last_ack, acked_anything, d);
                continue;
            },
            error.ConcurrencyUnavailable => return fail(d, error.ReadError, &.{
                "this build has no concurrency, so a tftp read cannot be bounded, and an unbounded one would wait for a peer that may never answer",
            }),
            else => return fail(d, error.ReadError, &.{
                "zurl did not read a tftp datagram: ",
                @errorName(err),
            }),
        };

        // **A datagram from another peer is dropped and never answered.**
        // RFC 1350 invites a client to send `err` code 5 back to such a
        // source. This does not: the source address of a datagram is
        // whatever the sender wrote, so answering it would let anybody who
        // can guess this port use zurl to write a packet at a third
        // machine. Dropping costs one datagram of the count bound and
        // nothing else.
        //
        // **The rule holds from the first datagram, and not from the
        // second.** The socket binds the unspecified address, so it reads
        // a datagram from any sender. Before this transfer has a peer the
        // address that `resolve` gave is the rule, and only the port is
        // free. Without that half, whoever put the first datagram on this
        // port became the peer, and a netboot image came from them.
        if (peer) |known| {
            if (!known.eql(&message.from)) continue;
        } else if (!sameAddress(server, message.from)) continue;

        // The buffer holds one whole block of the largest size this
        // package reads, and the request asked for no more than that, so a
        // datagram that did not fit is a server answering something it was
        // never offered. A datagram that fits the buffer and still carries
        // more than the size in play is caught on the block itself, below.
        if (message.flags.trunc) return fail(d, error.ReadError, &.{
            "the server sent a datagram larger than the largest block zurl reads",
        });

        const parsed = packet.parse(message.data, requested_block_size) catch |err| switch (err) {
            error.Truncated => return fail(d, error.ReadError, &.{
                "the server sent a datagram shorter than a tftp packet header",
            }),
            error.BlockSizeTooLarge => return fail(d, error.ReadError, &.{
                "the server answered with a block size larger than the request asked for",
            }),
        };

        switch (parsed) {
            .err => |e| return fail(d, packet.errorFor(e.code), &.{
                "the tftp server refused: ",
                if (e.message.len > 0) e.message else "no reason given",
            }),
            .oack => |answered| {
                // An `oack` answers the request and nothing else, so one
                // that arrives after a block is a server repeating itself
                // or a second server answering. Either way it names no
                // new block, and re-acknowledging block 0 would restart
                // the file.
                if (acked_anything) continue;
                peer = message.from;
                // RFC 2347: an `oack` names the options the server took,
                // so a `blksize` it left out is a `blksize` it refused,
                // and the transfer runs at the RFC 1350 default. The
                // number it names is never above the requested one,
                // because `packet.parse` refuses that datagram.
                block_size = answered.block_size orelse packet.default_block_size;
                negotiated = true;
                ceiling = blockCeiling(options.max_response_bytes, block_size);
                announced_size = answered.total_size;
                if (announced_size) |size| {
                    if (size > options.max_response_bytes) return failNumber(
                        d,
                        error.FileSizeExceeded,
                        "the server announced a file larger than the ",
                        options.max_response_bytes,
                        " bytes zurl reads from a tftp transfer",
                    );
                }
                try f.writeAck(socket, message.from, 0, d);
                last_ack = 0;
                acked_anything = true;
                retries = 0;
            },
            .data => |block| {
                if (peer == null) peer = message.from;

                // **A block instead of an `oack` is a server that read no
                // option.** RFC 2347 lets it answer that way, and the
                // transfer then runs at the size RFC 1350 fixes. Without
                // this a request that asked for a larger block would read
                // the first 512 byte block as the short block that ends
                // the file, and the download would stop one block in.
                if (!negotiated) {
                    negotiated = true;
                    block_size = packet.default_block_size;
                    ceiling = blockCeiling(options.max_response_bytes, block_size);
                }

                // A block larger than the size in play is a server
                // sending more than it was offered. The datagram fits the
                // read buffer, so nothing but this says so.
                if (block.bytes.len > block_size) return failNumber(
                    d,
                    error.ReadError,
                    "the tftp server sent a block larger than the ",
                    block_size,
                    " bytes the transfer runs at",
                );

                // A block this transfer already took is the network or
                // the server repeating itself. The `ack` goes out again,
                // because the one that was lost is why the block came
                // back, and the bytes are dropped.
                if (block.block != wanted) {
                    if (acked_anything and block.block == last_ack) {
                        try f.writeAck(socket, message.from, last_ack, d);
                    }
                    continue;
                }

                if (collected.items.len + block.bytes.len > options.max_response_bytes) {
                    return failNumber(
                        d,
                        error.FileSizeExceeded,
                        "the server sent more than the ",
                        options.max_response_bytes,
                        " bytes zurl reads from a tftp transfer",
                    );
                }
                collected.appendSlice(f.allocator, block.bytes) catch
                    return Diagnostics.record(d, error.OutOfMemory, .{});

                try f.writeAck(socket, message.from, block.block, d);
                last_ack = block.block;
                acked_anything = true;
                retries = 0;

                // RFC 1350 section 1: a block shorter than the block size
                // is the last one. A file whose size is a whole number of
                // blocks ends with a block of no bytes at all, which this
                // reads the same way.
                if (block.bytes.len < block_size) break;

                // The size bound above stops the transfer before the
                // block number can reach 65535 at 512 bytes a block or
                // more, so this addition never wraps for such a transfer.
                // It is written with `+%` so a caller that raised the
                // bound, or asked for a block smaller than 256 bytes,
                // gets a wrapped number and not undefined behaviour, and
                // the count bound then ends the transfer.
                wanted +%= 1;
            },
            .unusable => |opcode| return failNumber(
                d,
                error.ReadError,
                "the tftp server sent opcode ",
                @intFromEnum(opcode),
                ", which a download has no use for",
            ),
        }
    }

    const file = collected.toOwnedSlice(f.allocator) catch
        return Diagnostics.record(d, error.OutOfMemory, .{});
    f.file = file;
    f.body = .fixed(file);
    return .{ .reader = &f.body, .length = file.len, .announced_size = announced_size };
}

/// Whether two addresses name the same host, whatever port each one holds.
///
/// **This is the half of the transfer identifier that a server may not
/// change.** RFC 1350 section 4 gives the server a new port for the
/// transfer, so the port of an answer is not the port the request went to.
/// It gives the server no new address. So the address of the peer is fixed
/// from the moment the url resolved, and this is the comparison that says
/// so.
///
/// The families must match as well. An IPv4 address and an IPv4-mapped
/// IPv6 address are different addresses here, which is the safe direction:
/// the socket takes its family from the address that `resolve` gave, so an
/// answer of the other family is a sender this transfer never asked.
fn sameAddress(a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |left| switch (b) {
            .ip4 => |right| std.mem.eql(u8, &left.bytes, &right.bytes),
            .ip6 => false,
        },
        .ip6 => |left| switch (b) {
            .ip4 => false,
            .ip6 => |right| std.mem.eql(u8, &left.bytes, &right.bytes),
        },
    };
}

/// How many datagrams one transfer may read.
///
/// Four for each block of a file at the size bound, plus a margin for the
/// `oack` and for a few datagrams from another peer. A server that never
/// finishes is stopped by this and not by the size bound, because a block
/// already acknowledged adds no byte to the file.
fn blockCeiling(max_response_bytes: u64, block_size: u16) usize {
    const blocks = max_response_bytes / block_size + 1;
    const bounded = @min(blocks, @as(u64, std.math.maxInt(usize) / 8));
    return @intCast(bounded * 4 + 64);
}

/// Writes the read request again, or the last `ack` again.
fn resend(
    f: *Fetcher,
    socket: Io.net.Socket,
    to: Io.net.IpAddress,
    request: []const u8,
    block: u16,
    acked_anything: bool,
    d: ?*Diagnostics,
) Error!void {
    if (!acked_anything) {
        var target = to;
        socket.send(f.io, &target, request) catch |err| return fail(d, error.WriteError, &.{
            "zurl did not write the tftp read request again: ",
            @errorName(err),
        });
        return;
    }
    return f.writeAck(socket, to, block, d);
}

/// Writes one `ack` to `to`.
fn writeAck(
    f: *Fetcher,
    socket: Io.net.Socket,
    to: Io.net.IpAddress,
    block: u16,
    d: ?*Diagnostics,
) Error!void {
    var storage: [4]u8 = undefined;
    var target = to;
    socket.send(f.io, &target, packet.writeAck(&storage, block)) catch |err|
        return fail(d, error.WriteError, &.{
            "zurl did not write a tftp acknowledgement: ",
            @errorName(err),
        });
}

/// Writes `parts`, one after another, into `d`'s own message storage,
/// records `err` with that message, and returns `err`.
///
/// The text goes into `Diagnostics.message_storage` because the sentence
/// names a host and a server's own message, and neither outlives the next
/// transfer. A message longer than the storage loses its tail, because a
/// diagnostic that says less is a cost and one that is not written at all
/// is a fault.
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

/// Returns the dispatch entry that registers this fetcher with a client.
///
/// `Front` is the front package's own namespace, taken as a comptime
/// parameter. Passing the namespace rather than importing it is what keeps
/// this package free of a `zurl` import: the front package imports no
/// protocol package, and no protocol package imports the front package, so
/// a build can leave any protocol out and a program outside this
/// repository can bring its own in.
///
/// **`f` must outlive every transfer the client runs on this scheme**, and
/// must not move: the entry carries `f` as its opaque pointer, and the
/// body reader points inside it.
pub fn protocol(f: *Fetcher, comptime Front: type) Front.protocol.Protocol {
    return .{
        .scheme = scheme,
        .default_port = default_port,
        .ptr = f,
        .vtable = &Dispatch(Front).vtable,
        // TFTP runs on UDP datagrams, and every proxy this build speaks
        // carries a TCP stream, so there is nothing to carry it through. A
        // transfer that named a proxy is refused by name rather than run
        // direct. See `Front.protocol.Unread`.
        .unread = .{ .proxy = true },
    };
}

/// The vtable for one front package. One instantiation for each `Front`,
/// and each one holds a single comptime constant, so the table lives in
/// the binary's own read-only data and never on a stack.
fn Dispatch(comptime Front: type) type {
    return struct {
        const vtable: Front.protocol.Protocol.VTable = .{ .perform = performTftp };

        /// Runs one `tftp://` download.
        ///
        /// `c` goes unread. The client holds a connection pool and a trust
        /// store, and this reads neither: TFTP has no connection to pool
        /// and no TLS at all.
        fn performTftp(
            ptr: ?*anyopaque,
            c: *Front.Client,
            url: zurl_core.Url,
            options: Front.Transfer.Options,
            d: ?*Diagnostics,
        ) Error!Front.Response {
            _ = c;
            const f: *Fetcher = @ptrCast(@alignCast(ptr.?));
            const body = try f.open(url, translate(options), d);
            return .{
                .status = status,
                .content_length = body.length,
                .transfer_encoding = .none,
                .body = body.reader,
            };
        }

        /// Reads the front package's own options into this package's.
        ///
        /// **`--max-filesize` narrows the bound and never widens it.** A
        /// zero there means the user named none, so the package bound
        /// stands.
        ///
        /// `--connect-timeout` becomes the wait for one datagram. TFTP has
        /// no connect at all, and the first datagram is the nearest thing
        /// to one: it is what says whether a peer is there. A caller that
        /// named no timeout keeps `default_block_timeout`.
        ///
        /// **`--tftp-blksize` reaches this package as it was written.** A
        /// null is the user naming no size, which keeps the 512 bytes RFC
        /// 1350 fixes. Every other number goes through, and one outside
        /// the range this package reads is refused by name in `open`
        /// before any datagram goes out. Nothing here clamps it, because a
        /// clamp would run the transfer at a size nobody asked for.
        fn translate(options: Front.Transfer.Options) Options {
            return .{
                .max_response_bytes = if (options.max_size == 0)
                    default_max_response_bytes
                else
                    @min(options.max_size, default_max_response_bytes),
                .block_timeout = switch (options.connect_timeout) {
                    .none => default_block_timeout,
                    else => options.connect_timeout,
                },
                .send_options = options.tftp_send_options,
                .block_size = options.tftp_block_size orelse packet.default_block_size,
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
const StubFront = struct {
    const Client = struct {};

    const Transfer = struct {
        const Options = struct {
            connect_timeout: Io.Timeout = .none,
            max_size: u64 = 0,
            tftp_block_size: ?u16 = null,
            tftp_send_options: bool = true,
            connect_to: []const zurl_net.override.HostOverride = &.{},
        };
    };

    const Response = struct {
        status: u16,
        content_length: ?u64,
        transfer_encoding: std.http.TransferEncoding,
        body: *Io.Reader,
        effective_url: []const u8 = "",
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

/// Parses `text` the way `zurl.Client` does, with `tftp` registered.
fn parseTftpUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = scheme, .default_port = default_port });
    return zurl_core.url.parseWith(text, &schemes);
}

/// The options every test here uses: a short wait, so a test that expects
/// a timeout does not cost seconds.
const quick: Options = .{
    .block_timeout = .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } },
    .max_retries = 1,
};

test {
    _ = packet;
    _ = test_server;
}

test "the package names the scheme and the port RFC 1350 assigns" {
    try testing.expectEqualStrings("tftp", scheme);
    try testing.expectEqual(@as(?u16, 69), default_port);
}

test "a whole file arrives, block by block, and every block is acknowledged" {
    // Three blocks: two whole ones and a short one that ends the file.
    var payload: [1100]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i);

    var server: test_server.Server = undefined;
    try server.start(.{ .file = &payload });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/hello.bin", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseTftpUrl(text), quick, null);
    try testing.expectEqual(@as(u64, payload.len), body.length);

    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualSlices(u8, &payload, contents);

    // The request is curl's own default request, byte for byte.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 } ++
        "hello.bin\x00octet\x00tsize\x000\x00blksize\x00512\x00timeout\x006\x00".*, server.request());
    // Every block was acknowledged, in order, and the `oack` was
    // acknowledged with block 0 before them. `wait` first: the client
    // returns as soon as it has written its last acknowledgement, and the
    // server has not always read that one by then.
    server.wait();
    try testing.expectEqualSlices(u16, &.{ 0, 1, 2, 3 }, server.acks());
    // The server answered `tsize`, so the size was known before the file
    // finished arriving.
    try testing.expectEqual(@as(?u64, payload.len), body.announced_size);
}

test "a file whose size is a whole number of blocks ends with an empty block" {
    // RFC 1350 section 1: a transfer ends on a block shorter than the
    // block size, so a file of exactly 512 bytes needs a second block
    // carrying nothing.
    var payload: [512]u8 = undefined;
    @memset(&payload, 'z');

    var server: test_server.Server = undefined;
    try server.start(.{ .file = &payload });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/z.bin", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseTftpUrl(text), quick, null);
    try testing.expectEqual(@as(u64, 512), body.length);
    server.wait();
    try testing.expectEqualSlices(u16, &.{ 0, 1, 2 }, server.acks());
}

test "a server that sends no oack still finishes the transfer" {
    // RFC 2347 lets a server ignore every option and answer with the
    // first block. `curl --tftp-no-options` asks for exactly that, and a
    // server that does it on its own must work the same way.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "no options here", .answer_options = false });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseTftpUrl(text), quick, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("no options here", contents);
    // No `oack`, so no block 0 acknowledgement.
    server.wait();
    try testing.expectEqualSlices(u16, &.{1}, server.acks());
    try testing.expectEqual(@as(?u64, null), body.announced_size);
}

test "a request with no options is byte for byte curl --tftp-no-options" {
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "x", .answer_options = false });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/hello.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var options = quick;
    options.send_options = false;
    // A block size beside the option free request reaches no wire. The
    // request carries no option block, so the transfer runs at the 512
    // bytes RFC 1350 fixes and the bytes stay what curl writes.
    options.block_size = 4096;
    _ = try fetcher.open(try parseTftpUrl(text), options, null);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x00, 0x01 } ++ "hello.txt\x00octet\x00".*,
        server.request(),
    );
}

test "the read request carries the block size the transfer asked for" {
    // **`--tftp-blksize` end to end.** The number reaches the request, the
    // server answers it, and every block after that carries it. Three
    // blocks of 1024 bytes: two whole ones and a short one that ends the
    // file.
    var payload: [2500]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i *% 7);

    var server: test_server.Server = undefined;
    try server.start(.{ .file = &payload, .block_size = 1024 });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/big.bin", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var options = quick;
    options.block_size = 1024;
    const body = try fetcher.open(try parseTftpUrl(text), options, null);
    try testing.expectEqual(@as(u64, payload.len), body.length);

    // The whole file arrived, and every byte of it is in its own place.
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualSlices(u8, &payload, contents);

    // The request is curl's own request with the asked for number in the
    // `blksize` option and nothing else moved.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 } ++
        "big.bin\x00octet\x00tsize\x000\x00blksize\x001024\x00timeout\x006\x00".*, server.request());

    // Three blocks and not five, so the larger block was read as one
    // block and not cut into the 512 bytes RFC 1350 fixes.
    server.wait();
    try testing.expectEqualSlices(u16, &.{ 0, 1, 2, 3 }, server.acks());
}

test "a block size outside the range is refused before any datagram goes out" {
    // RFC 2348 floors the option at 8, and `packet.max_block_size` is the
    // ceiling this package's read buffer holds. A number outside either
    // one is refused by name, with the exit code curl names
    // `CURLE_TFTP_ILLEGAL`, and nothing is clamped: a clamp would run the
    // transfer at a size nobody asked for.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "never read" });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    for ([_]u16{ 0, 1, 7, packet.max_block_size + 1, 65464, 65535 }) |size| {
        var options = quick;
        options.block_size = size;
        var d: Diagnostics = .{};
        try testing.expectError(
            error.TftpIllegalOperation,
            fetcher.open(try parseTftpUrl(text), options, &d),
        );
        try testing.expectEqual(@as(u32, 71), d.curl_code.?);
        // The message names the range and the number the user wrote, so a
        // reader knows which end was crossed.
        try testing.expect(std.mem.indexOf(u8, d.message.?, "8192") != null);
    }

    // Not one datagram left the client, so no server ever saw the number.
    try testing.expectEqual(@as(usize, 0), server.request().len);
}

test "a server that answers a block size above the one asked for is a fault" {
    // RFC 2348 lets a server shrink the block and never grow it. A larger
    // answer names a datagram the request never offered to read, so it is
    // a fault and never a size to grow into. The rule follows the number
    // the request carried, so it moves with `--tftp-blksize`.
    const rows = [_]struct { asked: u16, answered: u16 }{
        .{ .asked = packet.default_block_size, .answered = 1024 },
        .{ .asked = 2048, .answered = 4096 },
        .{ .asked = packet.max_block_size, .answered = 65464 },
    };
    for (rows) |row| {
        var server: test_server.Server = undefined;
        try server.start(.{
            .file = "never read",
            .block_size = packet.default_block_size,
            .announce_block_size = row.answered,
        });
        defer server.stop();

        var url_buffer: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(
            &url_buffer,
            "tftp://127.0.0.1:{d}/f.txt",
            .{server.port()},
        );

        var fetcher: Fetcher = .init(testing.allocator, testing.io);
        defer fetcher.deinit();

        var options = quick;
        options.block_size = row.asked;
        var d: Diagnostics = .{};
        try testing.expectError(
            error.ReadError,
            fetcher.open(try parseTftpUrl(text), options, &d),
        );
        try testing.expect(std.mem.indexOf(u8, d.message.?, "block size") != null);
        // The `oack` was refused, so no block was ever asked for. `acks`
        // reads a list the client finished writing before it gave up, and
        // `wait` would hang here: the fixture waits for an
        // acknowledgement that never comes.
        try testing.expectEqual(@as(usize, 0), server.acks().len);
    }
}

test "a server that reads no option runs at 512 whatever the request asked for" {
    // RFC 2347: a server may answer a request with the first block and no
    // `oack` at all, and that answer takes every option out of play. So a
    // transfer that asked for 4096 bytes a block reads 512 byte blocks
    // here. A client that held the number it asked for would read the
    // first 512 byte block as the short block that ends the file, and the
    // download would stop with 512 of the 700 bytes.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "a" ** 700, .answer_options = false });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.bin", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var options = quick;
    options.block_size = 4096;
    const body = try fetcher.open(try parseTftpUrl(text), options, null);
    try testing.expectEqual(@as(u64, 700), body.length);
    // Two blocks of the RFC 1350 size, and no `oack` to acknowledge.
    server.wait();
    try testing.expectEqualSlices(u16, &.{ 1, 2 }, server.acks());
}

test "a block the network dropped is asked for again" {
    // The server drops the first copy of block 2. The client waits, sends
    // its `ack` for block 1 again, and the server answers with block 2.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "a" ** 700, .drop_block = 2 });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.bin", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseTftpUrl(text), quick, null);
    try testing.expectEqual(@as(u64, 700), body.length);
    // Block 1 was acknowledged twice: once when it arrived, and once as
    // the retransmission that asked for block 2 again.
    server.wait();
    try testing.expectEqualSlices(u16, &.{ 0, 1, 1, 2 }, server.acks());
}

test "a block that arrives twice is acknowledged again and counted once" {
    // The Sorcerer's Apprentice shape. A duplicate must not be appended
    // to the file, and it must still be acknowledged, because the `ack`
    // the peer missed is why it came back.
    //
    // Block 1 is the duplicate, and the file runs to a second block, so
    // the duplicate arrives while the transfer is still running. A
    // duplicate of the last block could never be read: the transfer ends
    // on the short block that carries it.
    const payload = "a" ** 600;
    var server: test_server.Server = undefined;
    try server.start(.{ .file = payload, .duplicate_block = 1 });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseTftpUrl(text), quick, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    // Six hundred bytes and not eleven hundred and twelve.
    try testing.expectEqual(@as(usize, 600), contents.len);
    try testing.expectEqualStrings(payload, contents);
    // Block 1 was acknowledged twice, and the file still holds it once.
    server.wait();
    try testing.expectEqualSlices(u16, &.{ 0, 1, 1, 2 }, server.acks());
}

test "an err packet is the fault its own code names" {
    const rows = [_]struct { code: u16, want: Error, exit: u32 }{
        .{ .code = 1, .want = error.TftpNotFound, .exit = 68 },
        .{ .code = 2, .want = error.TftpPermission, .exit = 69 },
        .{ .code = 3, .want = error.TftpDiskFull, .exit = 70 },
        .{ .code = 4, .want = error.TftpIllegalOperation, .exit = 71 },
        .{ .code = 5, .want = error.TftpUnknownId, .exit = 72 },
        .{ .code = 6, .want = error.TftpFileExists, .exit = 73 },
        .{ .code = 7, .want = error.TftpNoSuchUser, .exit = 74 },
    };
    for (rows) |row| {
        var server: test_server.Server = undefined;
        try server.start(.{ .file = "", .refuse = .{ .code = row.code, .message = "no" } });
        defer server.stop();

        var url_buffer: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/x", .{server.port()});

        var fetcher: Fetcher = .init(testing.allocator, testing.io);
        defer fetcher.deinit();

        var d: Diagnostics = .{};
        try testing.expectError(row.want, fetcher.open(try parseTftpUrl(text), quick, &d));
        try testing.expectEqual(row.exit, d.curl_code.?);
        try testing.expect(std.mem.indexOf(u8, d.message.?, "no") != null);
    }
}

test "a url that names no file is refused before any datagram goes out" {
    // Measured: `curl tftp://127.0.0.1:69/` exits 71 and writes no
    // datagram at all.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "never read" });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.TftpIllegalOperation,
        fetcher.open(try parseTftpUrl(text), quick, &d),
    );
    try testing.expectEqual(@as(u32, 71), d.curl_code.?);
    try testing.expectEqual(@as(usize, 0), server.request().len);
}

test "a percent escaped framing byte in the name never forges a field" {
    // **The injection proof.** A NUL ends the file name field of a read
    // request, so `a%00b` would name the file `a` and read `b` as the
    // transfer mode. curl refuses the same url with exit 3, measured.
    //
    // A CR and an LF are refused too. curl sends both: `tftp://h/a%0d%0ab`
    // reaches the wire from curl with the two bytes inside the name,
    // measured.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "never read" });
    defer server.stop();

    var url_buffer: [96]u8 = undefined;
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    for ([_][]const u8{ "a%00b", "a%0d%0ab", "a%0db", "a%0ab" }) |name| {
        const text = try std.fmt.bufPrint(
            &url_buffer,
            "tftp://127.0.0.1:{d}/{s}",
            .{ server.port(), name },
        );
        var d: Diagnostics = .{};
        try testing.expectError(error.InvalidUrl, fetcher.open(try parseTftpUrl(text), quick, &d));
        try testing.expectEqual(@as(u32, 3), d.curl_code.?);
        try testing.expect(std.mem.indexOf(u8, d.message.?, "NUL") != null);
    }
    try testing.expectEqual(@as(usize, 0), server.request().len);

    // A space is not a framing byte, and a real file name can hold one.
    // curl sends `tftp://h/a%20b.txt` as the name `a b.txt`, measured.
    var ok: Fetcher = .init(testing.allocator, testing.io);
    defer ok.deinit();
    const url = try parseTftpUrl("tftp://127.0.0.1:1/a%20b.txt");
    try testing.expectEqualStrings("a b.txt", try ok.decodeName(url, null));
}

test "the name is the path with one slash off, and the query is not part of it" {
    // Measured against curl 8.21.0: `tftp://h/a/b/c.bin` names
    // `a/b/c.bin`, and `tftp://h/f.txt?x=1` names `f.txt`.
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    try testing.expectEqualStrings(
        "a/b/c.bin",
        try fetcher.decodeName(try parseTftpUrl("tftp://h:69/a/b/c.bin"), null),
    );
    try testing.expectEqualStrings(
        "f.txt",
        try fetcher.decodeName(try parseTftpUrl("tftp://h:69/f.txt?x=1"), null),
    );
    try testing.expectEqualStrings(
        "",
        try fetcher.decodeName(try parseTftpUrl("tftp://h:69/"), null),
    );
    // An escape that does not decode stays as it reads.
    try testing.expectEqualStrings(
        "f%zz.txt",
        try fetcher.decodeName(try parseTftpUrl("tftp://h:69/f%zz.txt"), null),
    );
}

test "a peer that answers nothing is reported after the retries run out" {
    // Measured: `curl tftp://127.0.0.1:1/x` with no flag beside it waits
    // about 350 seconds and then exits 7. A refused UDP port is not a
    // refused connection, so nothing but the wait says the peer is not
    // there. zurl gives up after six tries instead of after 350 seconds,
    // and reports the same number.
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.CouldNotConnect,
        fetcher.open(try parseTftpUrl("tftp://127.0.0.1:1/x"), quick, &d),
    );
    try testing.expectEqual(@as(u32, 7), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "tries") != null);
}

test "a transfer that stalls after a block is a timeout and not a refused peer" {
    // The other half of the rule above. The peer answered, so it was
    // there, and a wait that runs out after that says the transfer timed
    // out. The fixture answers the request with an `oack` and then sends
    // nothing at all.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "never sent", .stall_after_options = true });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(
        error.OperationTimedOut,
        fetcher.open(try parseTftpUrl(text), quick, &d),
    );
    try testing.expectEqual(@as(u32, 28), d.curl_code.?);
}

test "a file past the bound is refused and none of it is returned" {
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "0123456789", .answer_options = false });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var options = quick;
    options.max_response_bytes = 4;
    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        fetcher.open(try parseTftpUrl(text), options, &d),
    );
    try testing.expectEqual(@as(u32, 63), d.curl_code.?);
    try testing.expect(std.mem.indexOf(u8, d.message.?, "4 bytes") != null);
    try testing.expectEqual(@as(?[]u8, null), fetcher.file);
}

test "a tsize larger than the bound is refused before a byte arrives" {
    // The `oack` names the size, so the transfer can stop before the
    // first block instead of after the last one that fits.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "0123456789" });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var options = quick;
    options.max_response_bytes = 4;
    var d: Diagnostics = .{};
    try testing.expectError(
        error.FileSizeExceeded,
        fetcher.open(try parseTftpUrl(text), options, &d),
    );
    try testing.expect(std.mem.indexOf(u8, d.message.?, "announced") != null);
    // The `oack` was never acknowledged, so no block was ever asked for.
    try testing.expectEqual(@as(usize, 0), server.acks().len);
}

test "a datagram from another peer is dropped and never answered" {
    // RFC 1350 invites a client to answer such a source with error code
    // 5. This does not: the source address is whatever the sender wrote,
    // so an answer would let anybody who can guess this port use zurl to
    // write a packet at a third machine.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "payload", .inject_foreign_data = true });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const body = try fetcher.open(try parseTftpUrl(text), quick, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    // The foreign block never reached the file.
    try testing.expectEqualStrings("payload", contents);
    try testing.expectEqual(@as(usize, 0), server.foreignAcks());
}

test "the first datagram on the wire does not make a peer" {
    // The open half of the transfer identifier rule. Until a datagram has
    // been accepted this transfer holds no peer, so nothing it holds says
    // who may answer. The address the url resolved to is what says it.
    //
    // The fixture writes an `oack` and a `data` block from 127.0.0.2
    // before it answers at all. That is a host on the same loopback
    // interface, which is what an attacker on the same broadcast domain
    // is. Its file reads "INTRUDER". A client that took it would netboot
    // an image the server never sent.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "payload", .inject_foreign_first = true });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    // A wait long enough that the fixture's own pause for an answer from
    // the client cannot look like a server that stopped.
    const patient: Options = .{
        .block_timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } },
        .max_retries = 2,
    };

    const body = try fetcher.open(try parseTftpUrl(text), patient, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);

    try testing.expectEqualStrings("payload", contents);
    // Nothing went back to the other address, so it never became the peer.
    try testing.expectEqual(@as(usize, 0), server.foreignAcks());
}

test "an opcode a download cannot use ends the transfer by name" {
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "", .send_opcode = 4 });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    var d: Diagnostics = .{};
    try testing.expectError(error.ReadError, fetcher.open(try parseTftpUrl(text), quick, &d));
    try testing.expect(std.mem.indexOf(u8, d.message.?, "opcode 4") != null);
}

test "a second open frees the file the first one held" {
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "first" });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    _ = try fetcher.open(try parseTftpUrl(text), quick, null);
    try testing.expect(fetcher.file != null);

    try testing.expectError(
        error.CouldNotConnect,
        fetcher.open(try parseTftpUrl("tftp://127.0.0.1:1/x"), quick, null),
    );
    try testing.expectEqual(@as(?[]u8, null), fetcher.file);
}

test "a failure with no diagnostics still reports the error" {
    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    try testing.expectError(
        error.InvalidUrl,
        fetcher.open(try parseTftpUrl("tftp://127.0.0.1:1/a%00b"), quick, null),
    );
    try testing.expectError(
        error.TftpIllegalOperation,
        fetcher.open(try parseTftpUrl("tftp://127.0.0.1:1/"), quick, null),
    );
}

test "the datagram ceiling is above what a whole transfer needs" {
    // Four datagrams for each block of a file at the bound, plus a
    // margin. A transfer of the largest allowed file therefore never
    // reaches the ceiling, and a server that repeats itself does.
    const blocks = default_max_response_bytes / packet.default_block_size;
    try testing.expect(blockCeiling(default_max_response_bytes, packet.default_block_size) > blocks);

    // And a small bound still leaves room for the `oack`, the blocks, and
    // a few dropped datagrams.
    try testing.expect(blockCeiling(1, packet.default_block_size) >= 64);

    // A smaller block needs more datagrams for the same file, so the
    // ceiling grows as the block shrinks. This is why `run` computes it
    // again every time the negotiation moves the block size: a ceiling
    // held at the requested size would stop a transfer the server moved
    // to a smaller block.
    const smallest = blockCeiling(default_max_response_bytes, packet.min_block_size);
    const largest = blockCeiling(default_max_response_bytes, packet.max_block_size);
    try testing.expect(smallest > blockCeiling(default_max_response_bytes, packet.default_block_size));
    try testing.expect(blockCeiling(default_max_response_bytes, packet.default_block_size) > largest);
    // Every size in the range leaves room for the whole file at that size.
    try testing.expect(largest > default_max_response_bytes / packet.max_block_size);
}

test "the size bound keeps the block number away from its wrap" {
    // A 16 bit block number at 512 bytes a block covers 32 MiB. The
    // default bound is under that, so nothing here has to read a wrapped
    // block number.
    const blocks = default_max_response_bytes / packet.default_block_size;
    try testing.expect(blocks < std.math.maxInt(u16));
}

test "protocol builds a dispatch entry that runs the whole download" {
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "dispatched" });
    defer server.stop();

    var url_buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&url_buffer, "tftp://127.0.0.1:{d}/f.txt", .{server.port()});

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();

    const entry = fetcher.protocol(StubFront);
    try testing.expectEqualStrings("tftp", entry.scheme);
    try testing.expectEqual(@as(?u16, 69), entry.default_port);

    var client: StubFront.Client = .{};
    const response = try entry.vtable.perform(
        entry.ptr,
        &client,
        try parseTftpUrl(text),
        .{ .connect_timeout = quick.block_timeout },
        null,
    );
    try testing.expectEqual(@as(u16, 0), response.status);
    try testing.expectEqual(@as(?u64, 10), response.content_length);

    const contents = try response.body.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("dispatched", contents);
}

test "--max-filesize narrows the package bound and never widens it" {
    const D = Dispatch(StubFront);
    try testing.expectEqual(
        default_max_response_bytes,
        D.translate(.{ .max_size = 0 }).max_response_bytes,
    );
    try testing.expectEqual(@as(u64, 100), D.translate(.{ .max_size = 100 }).max_response_bytes);
    try testing.expectEqual(
        default_max_response_bytes,
        D.translate(.{ .max_size = default_max_response_bytes * 4 }).max_response_bytes,
    );

    // A caller that named no connect timeout keeps the package default.
    try testing.expectEqual(default_block_timeout, D.translate(.{}).block_timeout);
}

test "--tftp-no-options and --tftp-blksize reach this package as they were written" {
    const D = Dispatch(StubFront);

    // With neither flag named the request is curl's own default request.
    try testing.expectEqual(true, D.translate(.{}).send_options);
    try testing.expectEqual(packet.default_block_size, D.translate(.{}).block_size);

    // `--tftp-no-options` takes the whole option block out.
    try testing.expectEqual(false, D.translate(.{ .tftp_send_options = false }).send_options);

    // `--tftp-blksize` goes through as it was written, and a number
    // outside the range goes through too: `open` refuses it by name
    // before any datagram, where a clamp here would run the transfer at a
    // size nobody asked for.
    try testing.expectEqual(@as(u16, 1428), D.translate(.{ .tftp_block_size = 1428 }).block_size);
    try testing.expectEqual(@as(u16, 7), D.translate(.{ .tftp_block_size = 7 }).block_size);
    try testing.expectEqual(
        @as(u16, 65464),
        D.translate(.{ .tftp_block_size = 65464 }).block_size,
    );

    // `--connect-to` and `--resolve` travel the same way. A translation
    // that dropped them would leave both flags working in a unit test and
    // doing nothing on the command line.
    const overrides: []const zurl_net.override.HostOverride = &.{.{
        .from_host = "a.test",
        .to_host = "127.0.0.1",
        .to_port = 9,
    }};
    try testing.expectEqual(@as(usize, 0), D.translate(.{}).connect_to.len);
    try testing.expectEqualStrings(
        "a.test",
        D.translate(.{ .connect_to = overrides }).connect_to[0].from_host,
    );
}

test "--connect-to moves where a tftp read request is sent" {
    // The defect this closes: this package read no `connect_to`, so a
    // user who named either flag sent the read request to the url's own
    // host and got no diagnostic. curl 8.21.0 applies both to `tftp`,
    // measured: the bare url exits 6 and the same url under either flag
    // reaches the address the flag named.
    //
    // **No test here touches a resolver.** The url names `127.0.0.2`,
    // which is an address and never a lookup.
    var server: test_server.Server = undefined;
    try server.start(.{ .file = "moved", .answer_options = false });
    defer server.stop();

    var fetcher: Fetcher = .init(testing.allocator, testing.io);
    defer fetcher.deinit();
    const url = try parseTftpUrl("tftp://127.0.0.2:1/f.txt");

    // Nothing serves `127.0.0.2:1`, so the bare url gets no datagram back
    // and reports the peer that never answered.
    var bare: Diagnostics = .{};
    try testing.expectError(error.CouldNotConnect, fetcher.open(url, quick, &bare));

    var moved = quick;
    moved.connect_to = &.{.{
        .from_host = "127.0.0.2",
        .from_port = 1,
        .to_host = "127.0.0.1",
        .to_port = server.port(),
    }};
    const body = try fetcher.open(url, moved, null);
    const contents = try body.reader.allocRemaining(testing.allocator, .unlimited);
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("moved", contents);
}
