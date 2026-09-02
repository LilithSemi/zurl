//! One SSH session channel, RFC 4254.
//!
//! This is the layer between `Transport`, which carries packets, and a
//! protocol that runs inside a channel: `sftp` over a `subsystem` request,
//! or the old rcp protocol over an `exec` one.
//!
//! **One channel at a time, on purpose.** RFC 4254 multiplexes as many
//! channels as either side wants, and a transfer tool needs one. A single
//! slot means the dispatch below has one number to compare against, and a
//! message for any other channel is a message that belongs to no channel
//! this build opened. It is refused rather than acted on.
//!
//! ## Flow control, which is the part that deadlocks when it is wrong
//!
//! RFC 4254 section 5.2 gives each direction a window. A sender may put
//! that many bytes on the channel and no more, and the receiver opens room
//! again with `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
//!
//! **A sender that only writes never reads the adjustment that would let
//! it carry on.** That is a deadlock, and it is the same one the HTTP/2
//! engine has: `zurl_http.h2.roomToSend` solves it by reading a frame
//! whenever it has no room, and `roomToSend` here does the same thing with
//! `step`. There is one loop and one answer, and this file did not invent
//! a second.
//!
//! The other half is the receive window. Every data byte that arrives
//! spends the peer's room, and a receiver that never gives it back stops
//! the transfer as surely as a sender that never reads. `credit` counts
//! what is owed and writes one `SSH_MSG_CHANNEL_WINDOW_ADJUST` when the
//! debt reaches half the window, which is `zurl_http.h2.creditReceive`'s
//! own rule.
//!
//! **Extended data spends the window too.** RFC 4254 section 5.2 says so.
//! A build that credited only `SSH_MSG_CHANNEL_DATA` would leak window on
//! every line a remote command wrote to standard error, and a chatty
//! command would stall the transfer.
//!
//! ## What `SSH_MSG_CHANNEL_EXTENDED_DATA` is, and what it is not
//!
//! It is the remote command's standard error. **It is not the body.** A
//! build that mixed it in would write a warning from the far side into the
//! file the user asked for, and the file would be wrong in a way no
//! checksum on this side could see. It goes to `Options.stderr` and
//! nowhere else, and the counters say how much of it there was.
//!
//! ## `exit-status`, which is why a failed command is not a good transfer
//!
//! RFC 4254 section 6.10 says the server reports a command's exit status
//! in a `SSH_MSG_CHANNEL_REQUEST` before it closes the channel. A remote
//! `scp` that could not open the file writes a diagnostic and exits
//! non-zero, and a client that read the empty body and stopped there would
//! report a successful transfer of nothing. `exitStatus` is that number,
//! and `zurl_scp` maps it onto an exit code.
//!
//! ## Every bound
//!
//! | what | bound | where |
//! | --- | --- | --- |
//! | the window this side advertises | `Options.window_bytes` | 256 KiB by default, and it is the buffer size too |
//! | one message the peer may send | `Options.max_packet_bytes` | 32768 by default |
//! | the peer's `initial window size` | 2^31-1 | `max_peer_window_bytes` |
//! | the peer's `maximum packet size` | 1 to `max_peer_packet_bytes` | a zero would let no byte through |
//! | a window adjustment that would pass the ceiling | refused | `error.WindowOverflow` |
//! | data past the window this side gave | refused | `error.PeerWindowExceeded` |
//! | packets that carry no progress | `max_idle_steps` | `error.PeerStalled` |
//! | the stderr this build keeps | `Options.stderr` decides | nothing is kept with no sink |
//! | a peer's channel request name | compared, never stored | `step` |
//! | a full window held across a rekey | `Transport.backlogCapacity` | `backlogBytesNeeded` |

const Channel = @This();

const std = @import("std");

const connection = @import("connection.zig");
const messages = @import("messages.zig");
const packet = @import("packet.zig");
const wire = @import("wire.zig");

const Transport = @import("Transport.zig");

/// How many bytes this side lets the peer send before it adjusts the
/// window.
///
/// 256 KiB, and **this one is a buffer**. A caller can ask for room while
/// data it has not read yet is still held, so the bytes have to wait
/// somewhere, and the honest place is a buffer of exactly the window this
/// side advertised. The window then bounds the memory as well as the wire:
/// a peer that writes past it is `error.PeerWindowExceeded` and never a
/// buffer that grows.
///
/// The HTTP/2 engine advertises 1 MiB and holds no buffer at all, because
/// its body reader hands every `DATA` payload straight to the caller. A
/// channel cannot: `roomToSend` and `close` both read packets while a
/// caller is in the middle of something else, and the data those reads
/// find belongs to a `read` that has not happened yet.
pub const default_window_bytes: u32 = 256 * 1024;

/// The largest message this side takes on a channel.
///
/// 32768, which is what OpenSSH offers and what every server this build
/// has met answers with. It is the size of `data_storage`, so it is a real
/// memory cost and not only a number on the wire.
pub const default_max_packet_bytes: u32 = 32768;

/// The largest `initial window size` this build takes from a peer.
///
/// 2^31-1. RFC 4254 section 5.1 makes the field a `uint32` and says
/// nothing about a ceiling, so this build keeps the window in a `u32` and
/// refuses a value that could not be added to without wrapping.
pub const max_peer_window_bytes: u32 = (1 << 31) - 1;

/// The largest `maximum packet size` this build takes from a peer.
///
/// A message this build sends must fit one SSH packet, and
/// `zurl_ssh.packet.max_packet_bytes` is the bound on one of those. The
/// nine bytes are the message number, the channel number, and the length
/// of the data string.
pub const max_peer_packet_bytes: u32 = packet.max_packet_bytes - 9;

/// How many bytes a `SSH_MSG_CHANNEL_DATA` costs past the data it carries.
///
/// The message number, the recipient channel, and the length of the data
/// string.
pub const data_message_head: usize = 9;

/// How much transport backlog a full receive window in flight needs.
///
/// **This is the arithmetic that finding I3 got wrong.** A key exchange
/// this side starts must hold every payload the peer had already sent, and
/// the peer may have a whole receive window in flight. The window is data
/// bytes, so the message count is the window divided by the largest
/// message, rounded up, and each message costs its head and the backlog
/// entry head as well as its data.
///
/// With the defaults that is 8 messages of 32768 bytes, which is
/// 8 x (4 + 9 + 32768), or 262248 bytes. A backlog sized from one packet
/// holds 262148, and the eighth message would be
/// `error.RekeyBacklogFull`: any download that passed `rekey_bytes` with
/// the window full would die. The comptime check below is what stops the
/// two numbers drifting apart again, and `init` makes the same check for a
/// window a caller chose.
/// **A `max_packet_bytes` of zero is answered here and not by a divide.**
/// `init` refuses that value with `error.ChannelBoundInvalid`, but this
/// runs before any `Channel` is built: `Client.open` sizes the transport's
/// backlog from the raw options first. A divide by zero reaches
/// `catch unreachable`, which is undefined behaviour in a build with
/// safety off, so the value is checked instead. Zero needs no backlog,
/// because no message of that size can carry a byte, and the caller still
/// gets the named refusal one step later where it belongs.
pub fn backlogBytesNeeded(window_bytes: u32, max_packet_bytes: u32) usize {
    if (max_packet_bytes == 0) return 0;
    const messages_in_flight = std.math.divCeil(usize, window_bytes, max_packet_bytes) catch
        unreachable;
    return Transport.backlogBytesFor(messages_in_flight, data_message_head + max_packet_bytes);
}

comptime {
    // **The default window must fit the default backlog.** One file sets
    // the window and another sets the backlog, so the relationship is
    // checked here rather than left to a reader of both.
    if (backlogBytesNeeded(default_window_bytes, default_max_packet_bytes) >
        Transport.default_backlog_bytes)
    {
        @compileError("the default channel window does not fit the transport backlog");
    }
}

/// How many packets that carry no progress this build reads before it
/// gives up.
///
/// A peer can answer forever with `SSH_MSG_GLOBAL_REQUEST`, with a channel
/// request for a name this build drops, or with a window adjustment of
/// zero bytes on a channel it does not hold. Each one costs a read and
/// moves nothing.
///
/// **This is a total over the channel, and nothing sets it back to
/// zero.** `apply` holds the count, because every packet the channel
/// reads goes through it, so one line there catches every case.
///
/// A budget that started again would be no budget at all. It was a local
/// in `read`, and a peer that spent all of it and then let one byte
/// through had the whole of it again: 1024 packets bought one byte, for
/// ever, and each of those packets could carry 256 `SSH_MSG_IGNORE`
/// under `Transport.max_idle_run` as well. A budget that started again on
/// any progress has the same hole, because one byte is progress. Only a
/// total closes it. `zurl_ws.Fetcher.max_empty_frames` is the same bound
/// in the same shape, for the same reason.
///
/// 1024 is far past any honest server. A real session sends one
/// `hostkeys-00@openssh.com` and little else that moves nothing, and
/// every message that carries data, opens window, or ends the channel is
/// not counted here at all.
pub const max_idle_steps: usize = 1024;

/// The channel number this side uses.
///
/// Zero, because this build opens one channel. RFC 4254 section 5.1 lets
/// each side number its own channels however it likes.
pub const local_channel: u32 = 0;

/// Where the remote command's standard error goes.
///
/// **The text is the peer's and it is not filtered here.** A caller that
/// shows it to a person makes it safe first, the way
/// `zurl_ssh.userauth.sanitizeBanner` does for a banner.
pub const StderrSink = struct {
    ctx: ?*anyopaque = null,
    write: *const fn (ctx: ?*anyopaque, text: []const u8) void,
};

/// What one channel needs.
pub const Options = struct {
    /// How many bytes the peer may send before this side adjusts the
    /// window. See `default_window_bytes`.
    window_bytes: u32 = default_window_bytes,
    /// The largest message this side takes. See
    /// `default_max_packet_bytes`.
    max_packet_bytes: u32 = default_max_packet_bytes,
    /// Where standard error goes. Null drops it, and `counters` still
    /// shows how much arrived.
    stderr: ?StderrSink = null,
};

/// Why a channel could not start.
pub const InitError = error{
    /// The process has no room for the data buffer.
    OutOfMemory,
    /// `Options.window_bytes` or `Options.max_packet_bytes` is outside
    /// what this build frames, or a full window of messages would not fit
    /// the transport's rekey backlog. A caller's own bug.
    ChannelBoundInvalid,
};

/// Why a channel operation stopped.
pub const Error =
    Transport.SendError ||
    Transport.ReceiveError ||
    connection.ParseError ||
    connection.BuildError ||
    error{
        /// The server would not open the channel. `openFailure` says why.
        ChannelOpenRefused,
        /// The server confirmed a channel this side did not open.
        ChannelNumberMismatch,
        /// The server named a `maximum packet size` of zero, which would
        /// let no byte through, or one past `max_peer_packet_bytes`.
        ChannelPacketSizeInvalid,
        /// The server named an `initial window size` past
        /// `max_peer_window_bytes`.
        ChannelWindowInvalid,
        /// A `SSH_MSG_CHANNEL_WINDOW_ADJUST` would take the window past
        /// its ceiling. RFC 4254 section 5.2 leaves the overflow
        /// undefined, and this build refuses it.
        WindowOverflow,
        /// The peer sent more data than the window this side gave it.
        PeerWindowExceeded,
        /// The peer sent data, extended data, or an end of file after its
        /// own `SSH_MSG_CHANNEL_CLOSE`. RFC 4254 section 5.3 says a side
        /// that has sent a close sends no more. See `apply`.
        PeerDataAfterClose,
        /// A full receive window in flight would not fit the transport's
        /// rekey backlog, so the window is never advertised. See
        /// `backlogBytesNeeded`.
        ChannelWindowTooLarge,
        /// The peer sent one message larger than
        /// `Options.max_packet_bytes`, which is the size it agreed to.
        PeerPacketTooLong,
        /// A message arrived for a channel this build did not open.
        ChannelUnknown,
        /// The server refused the `exec` or `subsystem` request.
        ChannelRequestRefused,
        /// `max_idle_steps` packets came in a row that moved nothing.
        PeerStalled,
        /// The peer closed the channel while something was still needed
        /// from it.
        ChannelClosed,
        /// A caller asked for something out of order: a write after the
        /// end of file, a request before the open. A caller's own bug,
        /// and an error rather than an assert because a caller outside
        /// this package can reach it.
        ChannelStateInvalid,
    };

/// What the channel did that no caller asked for.
///
/// **Recovery is never silent.** A dropped request, a refused open from
/// the peer, and every byte of standard error are all counted here.
pub const Counters = struct {
    /// How many bytes of `SSH_MSG_CHANNEL_DATA` arrived.
    data_bytes: u64 = 0,
    /// How many bytes of `SSH_MSG_CHANNEL_EXTENDED_DATA` arrived, of
    /// every type.
    extended_bytes: u64 = 0,
    /// How many `SSH_MSG_CHANNEL_EXTENDED_DATA` messages named a type
    /// that is not `stderr`, and were dropped.
    extended_unknown: u64 = 0,
    /// How many `SSH_MSG_CHANNEL_REQUEST` messages this build dropped.
    requests_dropped: u64 = 0,
    /// How many `SSH_MSG_GLOBAL_REQUEST` messages this build refused.
    global_requests_refused: u64 = 0,
    /// How many `SSH_MSG_CHANNEL_OPEN` messages from the peer this build
    /// refused.
    peer_opens_refused: u64 = 0,
    /// How many `SSH_MSG_CHANNEL_WINDOW_ADJUST` messages arrived.
    window_adjusts: u64 = 0,
    /// How many this side sent.
    window_credits: u64 = 0,
    /// How many packets arrived that belong to no channel this build
    /// holds, and were answered with `SSH_MSG_UNIMPLEMENTED`.
    unimplemented_sent: u64 = 0,
    /// How many packets arrived that moved nothing a caller asked for.
    /// See `max_idle_steps`.
    idle_steps: u64 = 0,
};

/// What a peer said when it would not open the channel.
pub const OpenFailure = struct {
    reason: connection.OpenFailureReason,
    /// **Untrusted text**, cut to fit.
    description: []const u8,
};

/// How many bytes of a peer's open failure description this keeps.
pub const max_open_failure_bytes = 256;

/// How many bytes of an `exit-signal` name this keeps.
pub const max_signal_name_bytes = 32;

/// What a command's `exit-signal` said, RFC 4254 section 6.10.
pub const ExitSignal = struct {
    /// The signal name with no `SIG` in front of it. **Untrusted text**,
    /// cut to fit.
    name: []const u8,
    core_dumped: bool,
};

transport: *Transport,
options: Options,

/// The number the peer wants in every message this side sends.
remote_channel: u32,

/// How many bytes this side may still send. RFC 4254 section 5.2.
send_window: u32,
/// The largest data payload the peer takes in one message.
peer_max_packet: u32,

/// How many bytes the peer may still send.
local_window: u32,
/// How many bytes have arrived whose room has not gone back yet.
recv_owed: u32,

/// The channel data that has arrived and that no `read` has taken yet,
/// copied out of the transport's own buffer so that the next `step` may
/// reuse it. Owned, and `Options.window_bytes` long.
///
/// **The window is what keeps this bounded.** A peer may have
/// `window_bytes` in flight and no more, and the room only goes back when
/// a `read` takes the bytes, so what is held here is never more than one
/// window.
data_storage: []u8,
/// How many bytes of `data_storage` hold data.
data_len: usize,
/// Where the next `read` starts inside it.
data_at: usize,

/// Holds one outgoing `SSH_MSG_CHANNEL_DATA` as it is built. Owned.
///
/// Separate from `data_storage` because a `write` reads packets while it
/// waits for window, and the data those reads find would otherwise
/// overwrite the message being built.
send_storage: []u8,

opened: bool,
/// Whether this side has sent `SSH_MSG_CHANNEL_EOF`.
eof_sent: bool,
/// Whether the peer has sent one.
eof_received: bool,
/// Whether this side has sent `SSH_MSG_CHANNEL_CLOSE`.
close_sent: bool,
/// Whether the peer has sent one.
close_received: bool,

exit_status: ?u32,
exit_signal_name_storage: [max_signal_name_bytes]u8,
exit_signal_name_len: usize,
exit_signal_core_dumped: bool,
has_exit_signal: bool,

open_failure_reason: ?connection.OpenFailureReason,
open_failure_storage: [max_open_failure_bytes]u8,
open_failure_len: usize,

counters: Counters,

/// How many packets in a row have moved nothing a caller asked for. See
/// `max_idle_steps`.
idle_steps: usize,

/// Holds one control message as it is built.
control_storage: [connection.max_control_bytes]u8,

/// Starts a channel over `transport`.
///
/// Initializes `c` in place, and not as a returned value, because the
/// buffers a caller reads point into this value.
///
/// This writes nothing to the peer. `open` does that.
pub fn init(
    c: *Channel,
    gpa: std.mem.Allocator,
    transport: *Transport,
    options: Options,
) InitError!void {
    // A window under one message is a window that could never carry one,
    // and a message this build cannot frame is a caller's own bug. A
    // silently clamped bound would hide either one.
    if (options.max_packet_bytes == 0 or options.max_packet_bytes > max_peer_packet_bytes) {
        return error.ChannelBoundInvalid;
    }
    if (options.window_bytes < options.max_packet_bytes) return error.ChannelBoundInvalid;
    if (options.window_bytes > max_peer_window_bytes) return error.ChannelBoundInvalid;

    const data_storage = gpa.alloc(u8, options.window_bytes) catch return error.OutOfMemory;
    errdefer gpa.free(data_storage);
    const send_storage = gpa.alloc(u8, 9 + @as(usize, options.max_packet_bytes)) catch
        return error.OutOfMemory;

    c.* = .{
        .transport = transport,
        .options = options,
        .remote_channel = 0,
        .send_window = 0,
        .peer_max_packet = 0,
        .local_window = options.window_bytes,
        .recv_owed = 0,
        .data_storage = data_storage,
        .data_len = 0,
        .data_at = 0,
        .send_storage = send_storage,
        .opened = false,
        .eof_sent = false,
        .eof_received = false,
        .close_sent = false,
        .close_received = false,
        .exit_status = null,
        .exit_signal_name_storage = undefined,
        .exit_signal_name_len = 0,
        .exit_signal_core_dumped = false,
        .has_exit_signal = false,
        .open_failure_reason = null,
        .open_failure_storage = undefined,
        .open_failure_len = 0,
        .counters = .{},
        .idle_steps = 0,
        .control_storage = undefined,
    };
}

/// Frees the two buffers.
pub fn deinit(c: *Channel, gpa: std.mem.Allocator) void {
    gpa.free(c.data_storage);
    gpa.free(c.send_storage);
    c.* = undefined;
}

/// Why the server would not open the channel, or null.
pub fn openFailure(c: *const Channel) ?OpenFailure {
    const reason = c.open_failure_reason orelse return null;
    return .{
        .reason = reason,
        .description = c.open_failure_storage[0..c.open_failure_len],
    };
}

/// The exit status of the remote command, or null when the server sent
/// none.
///
/// **A null here is not a success.** A server that closed the channel with
/// no `exit-status` said nothing about how the command ended, and a caller
/// that read it as zero would report a transfer that may have failed.
pub fn exitStatus(c: *const Channel) ?u32 {
    return c.exit_status;
}

/// The signal that killed the remote command, or null.
pub fn exitSignal(c: *const Channel) ?ExitSignal {
    if (!c.has_exit_signal) return null;
    return .{
        .name = c.exit_signal_name_storage[0..c.exit_signal_name_len],
        .core_dumped = c.exit_signal_core_dumped,
    };
}

/// Whether the peer has said it will send no more data.
pub fn atEnd(c: *const Channel) bool {
    return c.data_at == c.data_len and (c.eof_received or c.close_received);
}

/// Opens a `session` channel and waits for the answer.
pub fn open(c: *Channel) Error!void {
    if (c.opened) return error.ChannelStateInvalid;
    // **The window is checked against the transport before it is
    // advertised.** A peer may put a whole window in flight, and a key
    // exchange that this side starts has to hold all of it. A window the
    // backlog cannot hold is `error.RekeyBacklogFull` at the first rekey,
    // which is in the middle of a transfer that has been running for a
    // gigabyte. It is refused here instead, before the peer is told it may
    // send that much. See `backlogBytesNeeded`.
    if (backlogBytesNeeded(c.options.window_bytes, c.options.max_packet_bytes) >
        c.transport.backlogCapacity())
    {
        return error.ChannelWindowTooLarge;
    }

    const request = try connection.writeOpenSession(
        &c.control_storage,
        local_channel,
        c.options.window_bytes,
        c.options.max_packet_bytes,
    );
    try c.transport.send(request);

    // The wait has no count of its own. Every packet that is not the
    // answer goes to `handleOther`, which is `apply`, and that is where
    // `max_idle_steps` is kept for the whole channel.
    while (true) {
        const payload = try c.transport.receive();
        const id = messages.idOf(payload) orelse return error.WrongMessage;
        switch (@as(connection.Id, @enumFromInt(@intFromEnum(id)))) {
            .channel_open_confirmation => {
                const confirmed = try connection.parseOpenConfirmation(payload);
                if (confirmed.recipient_channel != local_channel) {
                    return error.ChannelNumberMismatch;
                }
                // **Both of the peer's numbers are checked before either
                // one is used.** A `maximum packet size` of zero would let
                // no byte through and a sender that trusted it would loop
                // forever, and an `initial window size` at the top of the
                // range would wrap the first time it grew.
                if (confirmed.max_packet == 0 or confirmed.max_packet > max_peer_packet_bytes) {
                    return error.ChannelPacketSizeInvalid;
                }
                if (confirmed.initial_window > max_peer_window_bytes) {
                    return error.ChannelWindowInvalid;
                }
                c.remote_channel = confirmed.sender_channel;
                c.send_window = confirmed.initial_window;
                c.peer_max_packet = confirmed.max_packet;
                c.opened = true;
                return;
            },
            .channel_open_failure => {
                const failed = try connection.parseOpenFailure(payload);
                if (failed.recipient_channel != local_channel) {
                    return error.ChannelNumberMismatch;
                }
                c.open_failure_reason = failed.reason;
                const cut = @min(failed.description.len, max_open_failure_bytes);
                @memcpy(c.open_failure_storage[0..cut], failed.description[0..cut]);
                c.open_failure_len = cut;
                return error.ChannelOpenRefused;
            },
            else => try c.handleOther(payload),
        }
    }
}

/// Sends a `subsystem` request and waits for the answer.
///
/// The name goes to the server's own subsystem table. Nothing in it
/// reaches a shell.
pub fn requestSubsystem(c: *Channel, name: []const u8) Error!void {
    if (!c.opened) return error.ChannelStateInvalid;
    const request = try connection.writeSubsystem(
        &c.control_storage,
        c.remote_channel,
        name,
        true,
    );
    try c.transport.send(request);
    return c.awaitRequestReply();
}

/// Sends an `exec` request and waits for the answer.
///
/// **`command` reaches a shell on the far side**, so whoever built it owns
/// the quoting. See `zurl_scp.command`, which is the one builder in this
/// repository, and see RFC 4254 section 6.5.
///
/// `buffer` holds the request while it is built. It must be at least
/// `command.len + connection.max_control_bytes`, because the command can
/// be longer than a control message and this value's own buffer is not.
pub fn requestExec(c: *Channel, buffer: []u8, command: []const u8) Error!void {
    if (!c.opened) return error.ChannelStateInvalid;
    const request = try connection.writeExec(buffer, c.remote_channel, command, true);
    try c.transport.send(request);
    return c.awaitRequestReply();
}

fn awaitRequestReply(c: *Channel) Error!void {
    // See `open`: the count for a packet that is not the answer lives in
    // `apply`, so this wait keeps none of its own.
    while (true) {
        const payload = try c.transport.receive();
        const id = messages.idOf(payload) orelse return error.WrongMessage;
        switch (@as(connection.Id, @enumFromInt(@intFromEnum(id)))) {
            .channel_success => {
                if (try connection.recipientChannelOf(payload) != local_channel) {
                    return error.ChannelUnknown;
                }
                return;
            },
            .channel_failure => {
                if (try connection.recipientChannelOf(payload) != local_channel) {
                    return error.ChannelUnknown;
                }
                return error.ChannelRequestRefused;
            },
            else => try c.handleOther(payload),
        }
    }
}

/// Fills `out` with channel data and returns how many bytes it wrote.
///
/// Zero says the peer will send no more: it sent `SSH_MSG_CHANNEL_EOF` or
/// `SSH_MSG_CHANNEL_CLOSE`, and nothing is left in the buffer.
///
/// **Standard error never lands here.** It goes to `Options.stderr`.
pub fn read(c: *Channel, out: []u8) Error!usize {
    if (!c.opened) return error.ChannelStateInvalid;

    while (true) {
        if (c.data_at < c.data_len) {
            const take = @min(out.len, c.data_len - c.data_at);
            @memcpy(out[0..take], c.data_storage[c.data_at..][0..take]);
            c.data_at += take;
            // The room goes back as the bytes leave, which is the same
            // moment the caller takes them. Nothing here holds a window.
            try c.credit(@intCast(take));
            return take;
        }
        if (c.eof_received or c.close_received) return 0;
        // **The no-progress budget is not kept here.** It was, and a
        // budget a `read` started again was a budget the peer got back
        // for every byte it let through. `apply` keeps one total for the
        // whole channel now. See `max_idle_steps`.
        try c.step();
    }
}

/// Sends `data`, waiting for window whenever there is none.
///
/// **This is where a transfer larger than the peer's window would
/// deadlock, and where it does not.** See `roomToSend`.
pub fn write(c: *Channel, data: []const u8) Error!void {
    if (!c.opened) return error.ChannelStateInvalid;
    if (c.eof_sent or c.close_sent) return error.ChannelStateInvalid;

    var at: usize = 0;
    while (at < data.len) {
        const room = try c.roomToSend();
        const take = @min(data.len - at, room);
        const built = try connection.writeData(
            c.send_storage,
            c.remote_channel,
            data[at..][0..take],
        );
        try c.transport.send(built);
        c.send_window -= @intCast(take);
        at += take;
    }
}

/// How many bytes the next `SSH_MSG_CHANNEL_DATA` may carry, reading the
/// connection until there is room.
///
/// **The peer opens room with a `SSH_MSG_CHANNEL_WINDOW_ADJUST`, and a
/// sender that only wrote would never read one.** So this reads a packet
/// whenever the window is empty, through `step`, which applies every
/// adjustment and answers everything else on the way. It is the same shape
/// as `zurl_http.h2.roomToSend`, and it is that shape because that is the
/// one answer this repository has to this problem.
fn roomToSend(c: *Channel) Error!usize {
    while (true) {
        if (c.close_received) return error.ChannelClosed;
        if (c.send_window > 0) {
            // Three ceilings, and the smallest wins: the peer's window,
            // the peer's own message size, and the buffer this side
            // builds the message in.
            const room: usize = @min(
                @as(usize, c.send_window),
                @as(usize, c.peer_max_packet),
            );
            return @min(room, c.send_storage.len - 9);
        }
        // See `read`: the budget for a packet that opens no room is kept
        // in `apply`, over the whole channel.
        try c.step();
    }
}

/// Says this side will send no more data, RFC 4254 section 5.3.
///
/// The channel stays open and the peer keeps sending. A remote `scp -t`
/// waits for this before it reports its exit status.
pub fn sendEof(c: *Channel) Error!void {
    if (!c.opened or c.close_sent) return error.ChannelStateInvalid;
    if (c.eof_sent) return;
    const built = try connection.writeEof(&c.control_storage, c.remote_channel);
    try c.transport.send(built);
    c.eof_sent = true;
}

/// Closes the channel and waits for the peer's own close.
///
/// RFC 4254 section 5.3 says each side sends `SSH_MSG_CHANNEL_CLOSE` and
/// neither may reuse the number until both have. **The wait is what
/// collects `exit-status`**: OpenSSH sends it between the last data and
/// its close, so a client that stopped at its own close would never see
/// whether the command worked.
pub fn close(c: *Channel) Error!void {
    if (!c.opened) return error.ChannelStateInvalid;
    if (!c.close_sent) {
        const built = try connection.writeClose(&c.control_storage, c.remote_channel);
        try c.transport.send(built);
        c.close_sent = true;
    }

    // See `read`: the budget lives in `apply`, over the whole channel.
    while (!c.close_received) {
        c.step() catch |err| switch (err) {
            // The peer dropped the connection rather than answering the
            // close. The channel is over either way, and a caller that
            // has decided to close has nothing left to do about it.
            error.PeerDisconnected, error.EndOfStream => return,
            else => |rest| return rest,
        };
    }
}

/// Reads one packet and applies it.
fn step(c: *Channel) Error!void {
    const payload = try c.transport.receive();
    return c.apply(payload);
}

fn apply(c: *Channel, payload: []const u8) Error!void {
    const id = messages.idOf(payload) orelse return error.WrongMessage;
    const channel_id: connection.Id = @enumFromInt(@intFromEnum(id));

    // **A packet that moves nothing a caller asked for is counted, and
    // the count never goes back down.** See `max_idle_steps`. The arms
    // below are the only place that says a packet moved something, and
    // the count is taken after them, so an arm added later that says
    // nothing is counted, which is the safe answer.
    var progress = false;

    // **RFC 4254 section 5.3: a side that has sent `SSH_MSG_CHANNEL_CLOSE`
    // sends nothing more on the channel.** The three messages that carry
    // bytes or move the end of the stream are refused after one, above
    // the arms, so that no arm has to remember the rule. A window
    // adjustment is left alone: it moves no data and a peer that sends
    // one late costs this side nothing.
    //
    // **The rule reads the peer's close and never this side's.** RFC 4254
    // lets the peer's own data cross this side's close, because the peer
    // had not seen it yet, and a build that refused that would refuse an
    // ordinary end of transfer.
    //
    // One route reaches this: a payload the transport held across a key
    // exchange, handed back after the close that followed it. Every read
    // loop above stops at the peer's close, so a late message on the wire
    // is ordinarily never read at all.
    if (c.close_received) switch (channel_id) {
        .channel_data, .channel_extended_data, .channel_eof => {
            return error.PeerDataAfterClose;
        },
        else => {},
    };

    switch (channel_id) {
        .channel_data => {
            const got = try connection.parseData(payload);
            if (got.recipient_channel != local_channel) return error.ChannelUnknown;
            try c.takeData(got.bytes);
            progress = got.bytes.len != 0;
        },
        .channel_extended_data => {
            const got = try connection.parseExtendedData(payload);
            if (got.recipient_channel != local_channel) return error.ChannelUnknown;
            try c.takeExtended(got);
            progress = got.bytes.len != 0;
        },
        .channel_window_adjust => {
            const got = try connection.parseWindowAdjust(payload);
            if (got.recipient_channel != local_channel) return error.ChannelUnknown;
            c.counters.window_adjusts += 1;
            // The sum is computed at 64 bits, so the check runs before
            // any wrap can happen.
            const sum = @as(u64, c.send_window) + @as(u64, got.add);
            if (sum > max_peer_window_bytes) return error.WindowOverflow;
            c.send_window = @intCast(sum);
            // Room to send is progress for a `write`. An adjustment of
            // zero bytes opens none, and it is the message the budget is
            // there to bound.
            progress = got.add != 0;
        },
        .channel_eof => {
            if (try connection.recipientChannelOf(payload) != local_channel) {
                return error.ChannelUnknown;
            }
            c.eof_received = true;
            progress = true;
        },
        .channel_close => {
            if (try connection.recipientChannelOf(payload) != local_channel) {
                return error.ChannelUnknown;
            }
            c.close_received = true;
            progress = true;
            // RFC 4254 section 5.3: a side that gets a close and has not
            // sent one must send one. A build that did not would leave
            // the peer holding the channel number.
            if (!c.close_sent) {
                const built = try connection.writeClose(&c.control_storage, c.remote_channel);
                try c.transport.send(built);
                c.close_sent = true;
            }
        },
        .channel_request => {
            const before = c.exit_status != null or c.has_exit_signal;
            try c.takeRequest(payload);
            // How the remote command ended is what a caller asked for. A
            // request for any other name is counted and dropped, and that
            // one carries no progress.
            progress = !before and (c.exit_status != null or c.has_exit_signal);
        },
        .global_request => {
            const head = try connection.parseGlobalRequestHead(payload);
            c.counters.global_requests_refused += 1;
            // **This build grants no global request.** OpenSSH sends
            // `hostkeys-00@openssh.com` after authentication, and a
            // server that asked for a reply and never heard one would
            // wait. A refusal is an answer.
            if (head.want_reply) {
                const built = try connection.writeGlobalFailure(&c.control_storage);
                try c.transport.send(built);
            }
        },
        .channel_open => {
            const head = try connection.parsePeerOpenHead(payload);
            c.counters.peer_opens_refused += 1;
            // This build asked for no forwarding and no X11, so it takes
            // no channel. The refusal names the number the peer chose.
            const built = try connection.writeOpenFailure(
                &c.control_storage,
                head.sender_channel,
                .administratively_prohibited,
                "zurl opens channels and takes none",
            );
            try c.transport.send(built);
        },
        // A reply to a request nobody is waiting for. `open` and
        // `awaitRequestReply` read these where they belong, so one here
        // belongs to no request this build sent.
        .channel_success, .channel_failure => return error.ChannelStateInvalid,
        .channel_open_confirmation, .channel_open_failure => return error.ChannelStateInvalid,
        .request_success, .request_failure => {
            // This build sends no global request, so an answer to one
            // answers nothing. It is counted and dropped rather than
            // taken for a channel message.
            c.counters.requests_dropped += 1;
        },
        // RFC 4253 section 11.4: a message number this build does not
        // know is answered and the connection carries on. The number is
        // the one before the next, because `receiveSequence` names the
        // packet that has not arrived yet.
        _ => {
            const sequence = c.transport.receiveSequence() -% 1;
            try c.transport.sendUnimplemented(sequence);
            c.counters.unimplemented_sent += 1;
        },
    }

    // One line, and every arm above passes through it. See
    // `max_idle_steps` for why the count is never set back to zero.
    if (progress) return;
    c.idle_steps += 1;
    c.counters.idle_steps = c.idle_steps;
    if (c.idle_steps > max_idle_steps) return error.PeerStalled;
}

fn takeData(c: *Channel, bytes: []const u8) Error!void {
    if (bytes.len > c.options.max_packet_bytes) return error.PeerPacketTooLong;
    // **The window this side gave is the window this side holds the peer
    // to.** A peer past it is not a peer whose message this build grows a
    // buffer for.
    if (bytes.len > c.local_window) return error.PeerWindowExceeded;
    c.local_window -= @intCast(bytes.len);
    c.counters.data_bytes += bytes.len;

    // **Bytes a caller has not read are never overwritten.** `roomToSend`
    // and `close` both read packets while a `read` is not running, so
    // data can arrive with data already waiting. The buffer is one window
    // long and the window bounds what may be in flight, so the two
    // together say this always fits: what is held is the bytes that
    // arrived and were not read, and the room for those only goes back
    // when a `read` takes them.
    if (c.data_at != 0) {
        std.mem.copyForwards(u8, c.data_storage[0..], c.data_storage[c.data_at..c.data_len]);
        c.data_len -= c.data_at;
        c.data_at = 0;
    }
    if (bytes.len > c.data_storage.len - c.data_len) return error.PeerWindowExceeded;
    @memcpy(c.data_storage[c.data_len..][0..bytes.len], bytes);
    c.data_len += bytes.len;
}

fn takeExtended(c: *Channel, got: connection.ExtendedData) Error!void {
    if (got.bytes.len > c.options.max_packet_bytes) return error.PeerPacketTooLong;
    // RFC 4254 section 5.2: extended data spends the window as data does.
    // A build that credited only `SSH_MSG_CHANNEL_DATA` would leak window
    // on every line a remote command wrote to standard error.
    if (got.bytes.len > c.local_window) return error.PeerWindowExceeded;
    c.local_window -= @intCast(got.bytes.len);
    c.counters.extended_bytes += got.bytes.len;

    if (got.kind != .stderr) {
        c.counters.extended_unknown += 1;
    } else if (c.options.stderr) |sink| {
        sink.write(sink.ctx, got.bytes);
    }
    // The room goes back whether a sink took the bytes or not. A window
    // that only opened for text somebody read would stall a transfer with
    // no `stderr` wired.
    try c.credit(@intCast(got.bytes.len));
}

/// Gives the peer back the room `taken` bytes spent.
///
/// One `SSH_MSG_CHANNEL_WINDOW_ADJUST` when the debt reaches half the
/// window. A smaller number spends more packets on adjustments, and a
/// larger one lets the peer run out of room before the adjustment reaches
/// it. `zurl_http.h2.creditReceive` uses the same half.
fn credit(c: *Channel, taken: u32) Error!void {
    c.recv_owed += taken;
    if (c.recv_owed < c.options.window_bytes / 2) return;
    // A closed channel takes no more data, so an adjustment on one would
    // be a message about a window nobody can spend.
    if (c.close_sent or c.close_received) {
        c.recv_owed = 0;
        return;
    }
    const built = try connection.writeWindowAdjust(
        &c.control_storage,
        c.remote_channel,
        c.recv_owed,
    );
    try c.transport.send(built);
    c.local_window += c.recv_owed;
    c.recv_owed = 0;
    c.counters.window_credits += 1;
}

fn takeRequest(c: *Channel, payload: []const u8) Error!void {
    const head = try connection.parseRequestHead(payload);
    if (head.recipient_channel != local_channel) return error.ChannelUnknown;

    if (std.mem.eql(u8, head.request, connection.exit_status_request)) {
        c.exit_status = try connection.parseExitStatus(head.rest);
    } else if (std.mem.eql(u8, head.request, connection.exit_signal_request)) {
        const signal = try connection.parseExitSignal(head.rest);
        const cut = @min(signal.name.len, max_signal_name_bytes);
        @memcpy(c.exit_signal_name_storage[0..cut], signal.name[0..cut]);
        c.exit_signal_name_len = cut;
        c.exit_signal_core_dumped = signal.core_dumped;
        c.has_exit_signal = true;
    } else {
        c.counters.requests_dropped += 1;
    }

    // RFC 4254 section 5.4 says the server must not ask for a reply on
    // `exit-status`, and OpenSSH does not. One that asks anyway gets a
    // failure: this build runs no request a server can send it.
    if (head.want_reply) {
        const built = try connection.writeChannelFailure(&c.control_storage, local_channel);
        try c.transport.send(built);
    }
}

/// Applies a packet that is not the reply `open` or `awaitRequestReply`
/// was waiting for.
fn handleOther(c: *Channel, payload: []const u8) Error!void {
    const id = messages.idOf(payload) orelse return error.WrongMessage;
    // A channel message before the channel is open belongs to no channel,
    // and `apply` would take it for one this side holds. Only the
    // connection layer's own housekeeping is answered here.
    if (!c.opened and connection.isConnectionMessage(@intFromEnum(id))) {
        switch (@as(connection.Id, @enumFromInt(@intFromEnum(id)))) {
            .global_request, .channel_open => return c.apply(payload),
            else => return error.ChannelStateInvalid,
        }
    }
    return c.apply(payload);
}

const testing = std.testing;

test "a channel refuses a bound it could not frame" {
    var transport: Transport = undefined;
    var c: Channel = undefined;
    try testing.expectError(error.ChannelBoundInvalid, c.init(
        testing.allocator,
        &transport,
        .{ .max_packet_bytes = 0 },
    ));
    try testing.expectError(error.ChannelBoundInvalid, c.init(
        testing.allocator,
        &transport,
        .{ .max_packet_bytes = max_peer_packet_bytes + 1 },
    ));
    // A window smaller than one message could never carry one.
    try testing.expectError(error.ChannelBoundInvalid, c.init(
        testing.allocator,
        &transport,
        .{ .window_bytes = 16, .max_packet_bytes = 1024 },
    ));
    try testing.expectError(error.ChannelBoundInvalid, c.init(
        testing.allocator,
        &transport,
        .{ .window_bytes = max_peer_window_bytes + 1 },
    ));
}

test "the backlog sizing answers a message size of zero rather than dividing by it" {
    // **`Client.open` sizes the transport's backlog from the raw options,
    // before any `Channel` exists to refuse them.** So a caller that
    // passed `.max_packet_bytes = 0` reached a `catch unreachable` here,
    // which is undefined behaviour in a build with safety off and a panic
    // in one with safety on. It is answered instead, and `init` above
    // still gives the caller the named refusal one step later.
    try testing.expectEqual(@as(usize, 0), backlogBytesNeeded(default_window_bytes, 0));
    try testing.expectEqual(@as(usize, 0), backlogBytesNeeded(0, 0));

    // An ordinary pair still gives the arithmetic the comptime check
    // below `data_message_head` relies on.
    try testing.expectEqual(
        Transport.backlogBytesFor(8, data_message_head + 32768),
        backlogBytesNeeded(8 * 32768, 32768),
    );
}

test "the peer's maximum packet size bounds a message this build sends" {
    // The three ceilings of `roomToSend`, checked with no socket: the
    // peer's window, the peer's message size, and this build's own
    // buffer.
    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{ .max_packet_bytes = 4096 });
    defer c.deinit(testing.allocator);

    c.opened = true;
    c.send_window = 100;
    c.peer_max_packet = 32768;
    try testing.expectEqual(@as(usize, 100), try c.roomToSend());

    c.send_window = 1 << 20;
    c.peer_max_packet = 200;
    try testing.expectEqual(@as(usize, 200), try c.roomToSend());

    c.peer_max_packet = 32768;
    try testing.expectEqual(@as(usize, 4096), try c.roomToSend());
}

test "a window adjustment that would wrap is refused and the window does not move" {
    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{});
    defer c.deinit(testing.allocator);

    c.opened = true;
    c.send_window = max_peer_window_bytes - 1;

    var storage: [16]u8 = undefined;
    const good = try connection.writeWindowAdjust(&storage, local_channel, 1);
    try c.apply(good);
    try testing.expectEqual(max_peer_window_bytes, c.send_window);

    const overflowing = try connection.writeWindowAdjust(&storage, local_channel, 1);
    try testing.expectError(error.WindowOverflow, c.apply(overflowing));
    try testing.expectEqual(max_peer_window_bytes, c.send_window);
}

test "data past the window this side gave is refused" {
    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{
        .window_bytes = 4096,
        .max_packet_bytes = 4096,
    });
    defer c.deinit(testing.allocator);

    c.opened = true;
    c.local_window = 4;
    try testing.expectError(error.PeerWindowExceeded, c.takeData("hello"));
    try testing.expectEqual(@as(u32, 4), c.local_window);

    // And a message larger than the size this side offered is refused
    // before the window is even read.
    c.local_window = 4096;
    var big: [5000]u8 = @splat('x');
    try testing.expectError(error.PeerPacketTooLong, c.takeData(&big));
}

test "a message for a channel this build did not open is refused" {
    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{});
    defer c.deinit(testing.allocator);
    c.opened = true;

    var storage: [64]u8 = undefined;
    const stray = try connection.writeData(&storage, 7, "hi");
    try testing.expectError(error.ChannelUnknown, c.apply(stray));

    const stray_eof = try connection.writeEof(&storage, 7);
    try testing.expectError(error.ChannelUnknown, c.apply(stray_eof));
}

const StderrCollector = struct {
    text: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    fn sink(collector: *StderrCollector) StderrSink {
        return .{ .ctx = collector, .write = show };
    }

    fn show(ctx: ?*anyopaque, text: []const u8) void {
        const collector: *StderrCollector = @ptrCast(@alignCast(ctx.?));
        collector.text.appendSlice(collector.gpa, text) catch {};
    }
};

test "extended data goes to the stderr sink and never to the body" {
    var collector: StderrCollector = .{ .gpa = testing.allocator };
    defer collector.text.deinit(testing.allocator);

    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{ .stderr = collector.sink() });
    defer c.deinit(testing.allocator);
    c.opened = true;

    var storage: [64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(connection.Id.channel_extended_data));
    try w.uint32(local_channel);
    try w.uint32(@intFromEnum(connection.ExtendedDataType.stderr));
    try w.string("scp: no such file");
    try c.apply(w.written());

    try testing.expectEqualStrings("scp: no such file", collector.text.items);
    // Nothing reached the body buffer.
    try testing.expectEqual(@as(usize, 0), c.data_len);
    try testing.expectEqual(@as(u64, 17), c.counters.extended_bytes);
    try testing.expectEqual(@as(u64, 0), c.counters.data_bytes);
}

test "an extended data type this build does not know is counted and dropped" {
    var collector: StderrCollector = .{ .gpa = testing.allocator };
    defer collector.text.deinit(testing.allocator);

    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{ .stderr = collector.sink() });
    defer c.deinit(testing.allocator);
    c.opened = true;

    var storage: [64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(connection.Id.channel_extended_data));
    try w.uint32(local_channel);
    try w.uint32(9);
    try w.string("who knows");
    try c.apply(w.written());

    try testing.expectEqualStrings("", collector.text.items);
    try testing.expectEqual(@as(u64, 1), c.counters.extended_unknown);
    // The window still moved, because the peer still spent it.
    try testing.expectEqual(@as(u64, 9), c.counters.extended_bytes);
}

test "an exit status is kept, and a channel with none says so" {
    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{});
    defer c.deinit(testing.allocator);
    c.opened = true;

    try testing.expectEqual(@as(?u32, null), c.exitStatus());

    var storage: [64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(connection.Id.channel_request));
    try w.uint32(local_channel);
    try w.string("exit-status");
    try w.boolean(false);
    try w.uint32(1);
    try c.apply(w.written());

    try testing.expectEqual(@as(?u32, 1), c.exitStatus());
}

test "an exit signal is kept beside the status and does not become one" {
    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{});
    defer c.deinit(testing.allocator);
    c.opened = true;

    var storage: [128]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(connection.Id.channel_request));
    try w.uint32(local_channel);
    try w.string("exit-signal");
    try w.boolean(false);
    try w.string("KILL");
    try w.boolean(true);
    try w.string("killed");
    try w.string("");
    try c.apply(w.written());

    const signal = c.exitSignal() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("KILL", signal.name);
    try testing.expect(signal.core_dumped);
    // **A signal is not a status.** A caller that read a null status as
    // zero would report a killed command as a good transfer.
    try testing.expectEqual(@as(?u32, null), c.exitStatus());
}

test "a channel request this build does not act on is counted and dropped" {
    var transport: Transport = undefined;
    var c: Channel = undefined;
    try c.init(testing.allocator, &transport, .{});
    defer c.deinit(testing.allocator);
    c.opened = true;

    var storage: [64]u8 = undefined;
    var w: wire.Writer = .init(&storage);
    try w.byte(@intFromEnum(connection.Id.channel_request));
    try w.uint32(local_channel);
    try w.string("keepalive@openssh.com");
    try w.boolean(false);
    try c.apply(w.written());

    try testing.expectEqual(@as(u64, 1), c.counters.requests_dropped);
    try testing.expectEqual(@as(?u32, null), c.exitStatus());
}

test "the credit rule gives room back at half the window and not before" {
    var transport: Transport = undefined;
    var c: Channel = undefined;
    // A close is set so that `credit` writes nothing to a transport this
    // test does not have. The counters still show the decision.
    try c.init(testing.allocator, &transport, .{
        .window_bytes = 1024,
        .max_packet_bytes = 256,
    });
    defer c.deinit(testing.allocator);
    c.opened = true;
    c.close_sent = true;

    try c.credit(511);
    try testing.expectEqual(@as(u32, 511), c.recv_owed);
    try c.credit(1);
    // At half the window the debt is cleared. With the channel closed no
    // message goes out, which is the arm this test can reach with no
    // socket.
    try testing.expectEqual(@as(u32, 0), c.recv_owed);
    try testing.expectEqual(@as(u64, 0), c.counters.window_credits);
}
