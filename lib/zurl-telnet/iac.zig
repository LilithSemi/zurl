//! The telnet command stream, RFC 854. Pure bytes, and testable with a
//! table.
//!
//! **Telnet has one escape and everything turns on it.** The octet 255 is
//! `IAC`, "interpret as command", and every command starts with it. So a
//! data octet that happens to be 255 has to be written twice, `IAC IAC`,
//! or the peer reads the byte after it as a command:
//!
//! - **A 255 in outgoing data that is not doubled forges a command.** A
//!   file, a password, or a binary payload holding `FF FD 18` would reach
//!   the peer as `IAC DO TERMINAL-TYPE`, and one holding `FF F4` would
//!   reach it as an interrupt. `escape` is the one writer, and it doubles
//!   every 255 before anything reaches a socket. This is the same class of
//!   fault as SMTP dot-stuffing: unescaped data becomes commands.
//! - **A command in incoming data must not reach the output.** curl
//!   8.21.0 writes the data octets alone: measured against a loopback
//!   server that sent `data<FF><FF>with-iac<CRLF>` and then
//!   `IAC WILL ECHO` and `tail<CRLF>`, curl's standard output held
//!   `data<FF>with-iac<CRLF>tail<CRLF>`, with the doubled 255 halved and
//!   the command gone. `Decoder` does the same.
//!
//! **The negotiation this speaks is curl's, measured.** curl sends nothing
//! at all until the peer negotiates first: with a server that opened with
//! plain data, curl wrote only the standard input it was given. When the
//! peer does negotiate, curl answers that negotiation and then offers four
//! of its own, once:
//!
//! ```
//! server  IAC DO TERMINAL-TYPE
//! curl    IAC WONT TERMINAL-TYPE      the answer, and it refuses
//! curl    IAC WILL BINARY             then the four offers, once
//! curl    IAC DO BINARY
//! curl    IAC WILL SUPPRESS-GO-AHEAD
//! curl    IAC DO SUPPRESS-GO-AHEAD
//! ```
//!
//! zurl writes the same six lines for the same input. It has no
//! `-t`/`--telnet-option`, so it refuses `TERMINAL-TYPE`, `XDISPLOC`, and
//! `NEW-ENVIRON` where curl with a `-t` would accept one.
//!
//! **An answer is written only when the state changes**, which is the rule
//! RFC 1143 gives for keeping two endpoints out of a negotiation loop. A
//! second `DO BINARY` after this end has already said `WILL BINARY` is
//! answered with nothing.
//!
//! **The answers are bounded.** A peer that writes negotiation forever
//! would otherwise make this end write forever with it. `max_answers` is
//! the count over one session, and passing it is
//! `error.TooManyNegotiations`, which ends the transfer rather than answer
//! quietly for as long as a peer likes.
//!
//! **The commands that draw no answer are bounded too.** A subnegotiation
//! that never ends, and an `IAC NOP` written again and again, produce no
//! data octet and no answer, so neither the answer bound nor the caller's
//! response bound sees them. `max_discarded` is the count of such octets
//! over one session, and passing it is `error.TooManyCommandOctets`.
//!
//! **The answer buffer is checked by the writer.** `answersBound` says how
//! large a buffer a chunk needs, and `Decoder.write` still checks the room
//! before every answer it writes. A formula one part computes and another
//! part trusts is not a bound. See `answersBound`.
//!
//! This module opens nothing. It reads a caller's slice and writes a
//! caller's slice.

const std = @import("std");

/// Interpret as command, RFC 854. Every command starts with this octet,
/// and a data octet of this value is written twice.
pub const iac: u8 = 255;

/// The commands RFC 854 names, in the values it gives them.
pub const command = struct {
    /// The end of a subnegotiation.
    pub const se: u8 = 240;
    pub const nop: u8 = 241;
    /// Data mark.
    pub const dm: u8 = 242;
    pub const brk: u8 = 243;
    /// Interrupt process.
    pub const ip: u8 = 244;
    /// Abort output.
    pub const ao: u8 = 245;
    /// Are you there.
    pub const ayt: u8 = 246;
    /// Erase character.
    pub const ec: u8 = 247;
    /// Erase line.
    pub const el: u8 = 248;
    /// Go ahead.
    pub const ga: u8 = 249;
    /// The start of a subnegotiation.
    pub const sb: u8 = 250;
    pub const will: u8 = 251;
    pub const wont: u8 = 252;
    pub const do: u8 = 253;
    pub const dont: u8 = 254;
};

/// The options this end has an opinion about.
pub const option = struct {
    /// Transmit binary, RFC 856.
    pub const binary: u8 = 0;
    /// Echo, RFC 857.
    pub const echo: u8 = 1;
    /// Suppress go ahead, RFC 858.
    pub const suppress_go_ahead: u8 = 3;
    /// Terminal type, RFC 1091. zurl has no `-t`, so it refuses this.
    pub const terminal_type: u8 = 24;
};

/// The offer this end makes once, when the peer negotiates first.
///
/// The same four lines curl 8.21.0 writes, measured. Binary keeps an
/// eight bit path in both directions, and suppress-go-ahead turns off the
/// half duplex turn taking that a modern peer does not use.
pub const offer = [_]u8{
    iac, command.will, option.binary,
    iac, command.do,   option.binary,
    iac, command.will, option.suppress_go_ahead,
    iac, command.do,   option.suppress_go_ahead,
};

/// How many negotiation answers one session writes.
///
/// A real dialogue settles in a handful. This is far past that, and it is
/// a bound because a peer that negotiates forever would otherwise hold
/// this process writing for as long as it likes. See the module comment.
pub const max_answers: usize = 4096;

/// How many octets one session reads that produce no data and no answer.
///
/// **A peer can write for ever and produce nothing.** A subnegotiation
/// that never ends, or `IAC NOP` again and again, reads and discards with
/// no output at all, so `Options.max_response_bytes` never fires and
/// `max_answers` never fires either. This is the bound on that work.
/// Passing it is `error.TooManyCommandOctets`.
///
/// A real dialogue discards a few dozen octets. This is far past that, and
/// it is far past the octets `max_answers` negotiations take as well.
pub const max_discarded: usize = 1 << 16;

/// How many octets `escape` writes for `data`.
///
/// Every octet is itself, and an octet of 255 is written twice.
pub fn escapedLen(data: []const u8) usize {
    var total: usize = data.len;
    for (data) |byte| {
        if (byte == iac) total += 1;
    }
    return total;
}

/// Writes `data` into `out` with every 255 doubled, and returns the part
/// of `out` that holds it.
///
/// **This is the one writer of outgoing telnet data.** See the module
/// comment for what an undoubled 255 does.
///
/// `error.NoSpaceLeft` when `out` is smaller than `escapedLen(data)`.
/// Nothing is written in that case, so a refused write leaves no half
/// escaped run on the wire.
pub fn escape(out: []u8, data: []const u8) error{NoSpaceLeft}![]u8 {
    if (escapedLen(data) > out.len) return error.NoSpaceLeft;
    var at: usize = 0;
    for (data) |byte| {
        out[at] = byte;
        at += 1;
        if (byte == iac) {
            out[at] = iac;
            at += 1;
        }
    }
    return out[0..at];
}

/// What `Decoder.feed` produced.
pub const Feed = struct {
    /// The data octets, with every doubled 255 halved and every command
    /// taken out. Points into the caller's `data_out`.
    data: []u8,
    /// The negotiation to write back, or an empty slice when this chunk
    /// asked for none. Points into the caller's `answers_out`.
    answers: []u8,
};

/// Why a chunk could not be decoded.
pub const FeedError = error{
    /// The peer negotiated more times than `max_answers` allows in one
    /// session. See the module comment.
    TooManyNegotiations,
    /// The peer wrote more command octets than `max_discarded` allows in
    /// one session. See `max_discarded`.
    TooManyCommandOctets,
    /// `answers_out` is smaller than this chunk's answers need. A caller
    /// sizes it with `answersBound`.
    AnswerBufferTooSmall,
    /// `data_out` is smaller than the chunk the caller passed. The data a
    /// chunk holds can only shrink, so a buffer as large as the chunk is
    /// always enough. See `Decoder.feed`.
    DataBufferTooSmall,
};

/// How large an `answers_out` a chunk of `input_len` octets may need.
///
/// **A `Decoder` carries its state between chunks**, so the first octet of
/// a chunk is not always the first octet of a command. Three shapes, and
/// the largest of the three is the bound:
///
/// - A chunk that starts in state `.data` buys three answer octets for
///   every three input octets, so `input_len` answer octets.
/// - A chunk that starts in state `.iac` answers its first **two** octets
///   with three, and then one for one, so `input_len + 1`.
/// - A chunk that starts in state `.negotiate` answers its **first** octet
///   with three, and then one for one, so `input_len + 2`.
///
/// The one time offer is `offer.len` octets more.
///
/// **This is a sizing hint and not the safety property.** `Decoder.write`
/// and the offer copy each check `answers_out` themselves, so a bound that
/// a later change makes wrong is a named refusal and never an overrun. It
/// was wrong once: it modelled the `.data` case alone, and a peer that
/// split `IAC DO opt` across a read wrote two octets past the caller's
/// buffer, and chose the second of them.
pub fn answersBound(input_len: usize) usize {
    return input_len + 2 + offer.len;
}

/// The telnet command stream, read one chunk at a time.
///
/// **A `Decoder` holds the state between chunks**, because a command can
/// be cut in half by the end of a read: a chunk that ends with `IAC` and a
/// chunk that starts with `DO` are one command. A decoder that started
/// fresh on each chunk would write the second half of a command to the
/// output as data.
pub const Decoder = struct {
    state: State = .data,
    /// The command octet of a negotiation whose option has not arrived
    /// yet.
    pending: u8 = 0,
    /// Which options this end has agreed to perform.
    us: [256]bool = @splat(false),
    /// Which options this end has agreed to let the peer perform.
    him: [256]bool = @splat(false),
    /// Whether the one time offer has gone out.
    offered: bool = false,
    /// How many answers this session has written.
    answers: usize = 0,
    /// How many octets this session has read that produced no data octet.
    /// See `max_discarded`.
    discarded: usize = 0,

    const State = enum {
        /// Reading data octets.
        data,
        /// The last octet was `IAC`.
        iac,
        /// The last two octets were `IAC` and a negotiation command, so
        /// the next octet is the option.
        negotiate,
        /// Inside a subnegotiation, reading until `IAC SE`.
        subnegotiation,
        /// Inside a subnegotiation, and the last octet was `IAC`.
        subnegotiation_iac,
    };

    /// Reads `input`, writing its data octets into `data_out` and any
    /// negotiation answer into `answers_out`.
    ///
    /// `data_out` must be at least `input.len` octets: the data can only
    /// shrink, because a doubled 255 becomes one octet and a command
    /// becomes none. A shorter one is `error.DataBufferTooSmall`.
    ///
    /// **A shorter `data_out` is a named fault and not an assertion.** The
    /// loop below writes one octet of `data_out` for each octet of
    /// `input`, and `input` came off the wire, so the length a peer chose
    /// is the bound on those writes. An assertion is compiled out of a
    /// ReleaseFast or a ReleaseSmall build, which is the build that ships,
    /// and the writes are then unbounded. This package lost two octets
    /// past `answer_storage` to that exact shape once. The comparison
    /// costs one branch per chunk and it bounds every write in the loop,
    /// because `data_at` moves at most once for each octet of `input`.
    ///
    /// `answers_out` should be at least `answersBound(input.len)` octets. A
    /// shorter one is `error.AnswerBufferTooSmall`, which is a bound the
    /// caller keeps and not a fault on the wire. The refusal comes from the
    /// writer and not from the formula, so a wrong formula cannot become an
    /// overrun. See `answersBound`.
    ///
    /// A command octet that produces no data and no answer is charged
    /// against `max_discarded`. Passing it is `error.TooManyCommandOctets`.
    pub fn feed(
        d: *Decoder,
        input: []const u8,
        data_out: []u8,
        answers_out: []u8,
    ) FeedError!Feed {
        if (data_out.len < input.len) return error.DataBufferTooSmall;

        var data_at: usize = 0;
        var answer_at: usize = 0;

        for (input) |byte| switch (d.state) {
            .data => {
                if (byte == iac) {
                    try d.discard();
                    d.state = .iac;
                    continue;
                }
                data_out[data_at] = byte;
                data_at += 1;
            },
            .iac => switch (byte) {
                // **`IAC IAC` is one data octet of 255.** RFC 854.
                iac => {
                    data_out[data_at] = iac;
                    data_at += 1;
                    d.state = .data;
                },
                command.will, command.wont, command.do, command.dont => {
                    try d.discard();
                    d.pending = byte;
                    d.state = .negotiate;
                },
                command.sb => {
                    try d.discard();
                    d.state = .subnegotiation;
                },
                // Every other command is two octets and this end does
                // nothing with any of them. RFC 854 gives no answer to a
                // `NOP`, a `GA`, or an `AYT` that a client must make, and
                // curl writes none either.
                else => {
                    try d.discard();
                    d.state = .data;
                },
            },
            .negotiate => {
                try d.discard();
                try d.answer(d.pending, byte, answers_out, &answer_at);
                d.state = .data;
            },
            .subnegotiation => {
                try d.discard();
                if (byte == iac) d.state = .subnegotiation_iac;
            },
            .subnegotiation_iac => {
                try d.discard();
                switch (byte) {
                    // A doubled 255 inside a subnegotiation is a parameter
                    // octet, so the subnegotiation carries on.
                    iac => d.state = .subnegotiation,
                    command.se => d.state = .data,
                    // Any other command ends the subnegotiation too. RFC 854
                    // lets a command interrupt one, and a decoder that stayed
                    // inside would read the rest of the session as parameters.
                    else => d.state = .data,
                }
            },
        };

        return .{ .data = data_out[0..data_at], .answers = answers_out[0..answer_at] };
    }

    /// Writes the answer to one `WILL`, `WONT`, `DO`, or `DONT`.
    ///
    /// **An answer goes out only when the state changes**, which is the
    /// rule RFC 1143 gives for keeping two endpoints out of a negotiation
    /// loop.
    ///
    /// The one time offer follows the first answer, which is the order
    /// curl writes them in, measured.
    fn answer(
        d: *Decoder,
        verb: u8,
        opt: u8,
        out: []u8,
        at: *usize,
    ) FeedError!void {
        switch (verb) {
            command.do => {
                if (d.wants(opt)) {
                    if (!d.us[opt]) {
                        d.us[opt] = true;
                        try d.write(out, at, command.will, opt);
                    }
                } else {
                    // Refused. RFC 1143 keeps the state at NO and answers
                    // anyway, so a peer that asks again is told again.
                    // `max_answers` is what bounds that.
                    d.us[opt] = false;
                    try d.write(out, at, command.wont, opt);
                }
            },
            command.dont => {
                if (d.us[opt]) {
                    d.us[opt] = false;
                    try d.write(out, at, command.wont, opt);
                }
            },
            command.will => {
                if (d.wants(opt)) {
                    if (!d.him[opt]) {
                        d.him[opt] = true;
                        try d.write(out, at, command.do, opt);
                    }
                } else {
                    d.him[opt] = false;
                    try d.write(out, at, command.dont, opt);
                }
            },
            command.wont => {
                if (d.him[opt]) {
                    d.him[opt] = false;
                    try d.write(out, at, command.dont, opt);
                }
            },
            else => unreachable, // `feed` reaches this with those four alone.
        }

        if (!d.offered) {
            d.offered = true;
            for (0..offer.len / 3) |i| {
                const line = offer[i * 3 ..][0..3];
                d.us[line[2]] = d.us[line[2]] or line[1] == command.will;
                d.him[line[2]] = d.him[line[2]] or line[1] == command.do;
            }
            if (d.answers + offer.len / 3 > max_answers) return error.TooManyNegotiations;
            // **The copy checks the room it needs.** See `answersBound`.
            if (offer.len > out.len - at.*) return error.AnswerBufferTooSmall;
            d.answers += offer.len / 3;
            @memcpy(out[at.*..][0..offer.len], &offer);
            at.* += offer.len;
        }
    }

    /// Whether this end agrees to `opt`.
    ///
    /// Binary and suppress-go-ahead, and nothing else. `TERMINAL-TYPE`,
    /// `XDISPLOC`, and `NEW-ENVIRON` each need a value this build has no
    /// flag for, so agreeing to one would promise a subnegotiation answer
    /// that never comes.
    fn wants(d: *const Decoder, opt: u8) bool {
        _ = d;
        return opt == option.binary or opt == option.suppress_go_ahead;
    }

    /// Writes one three octet answer into `out`.
    ///
    /// **The room is checked here, by the writer.** A caller sizes `out`
    /// with `answersBound`, and a bound that only the caller keeps is a
    /// bound that a later change can make wrong. This check is what turns a
    /// wrong bound into `error.AnswerBufferTooSmall` instead of two octets
    /// written past the end of a peer's buffer, one of which the peer
    /// chose. See `answersBound`.
    fn write(d: *Decoder, out: []u8, at: *usize, verb: u8, opt: u8) FeedError!void {
        if (d.answers == max_answers) return error.TooManyNegotiations;
        if (3 > out.len - at.*) return error.AnswerBufferTooSmall;
        d.answers += 1;
        out[at.*] = iac;
        out[at.* + 1] = verb;
        out[at.* + 2] = opt;
        at.* += 3;
    }

    /// Charges one octet that produced no data octet.
    ///
    /// See `max_discarded` for why the work a peer can ask for this way
    /// needs a bound of its own.
    fn discard(d: *Decoder) FeedError!void {
        if (d.discarded == max_discarded) return error.TooManyCommandOctets;
        d.discarded += 1;
    }
};

const testing = std.testing;

test "escaping doubles every 255 and touches nothing else" {
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        "he\xff\xffllo\r\n",
        try escape(&out, "he\xffllo\r\n"),
    );
    // Measured against curl 8.21.0: standard input of
    // `he<FF>llo<CRLF>bye<CRLF>` reached a loopback server as
    // `he<FF><FF>llo<CRLF>bye<CRLF>`.
    try testing.expectEqualSlices(
        u8,
        "he\xff\xffllo\r\nbye\r\n",
        try escape(&out, "he\xffllo\r\nbye\r\n"),
    );
    try testing.expectEqualSlices(u8, "plain", try escape(&out, "plain"));
    try testing.expectEqualSlices(u8, "", try escape(&out, ""));
    // A run of 255s is doubled one for one.
    try testing.expectEqualSlices(
        u8,
        "\xff\xff\xff\xff\xff\xff",
        try escape(&out, "\xff\xff\xff"),
    );
}

test "an unescaped 255 in data would have written a command" {
    // The whole reason `escape` exists. These three octets are
    // `IAC DO TERMINAL-TYPE`, and a writer that passed them through would
    // send a negotiation the user never asked for.
    var out: [64]u8 = undefined;
    const forged = "\xff\xfd\x18";
    const written = try escape(&out, forged);
    try testing.expectEqualSlices(u8, "\xff\xff\xfd\x18", written);

    // And a decoder on the other end reads it back as data, not as a
    // command.
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [128]u8 = undefined;
    const fed = try decoder.feed(written, &data, &answers);
    try testing.expectEqualSlices(u8, forged, fed.data);
    try testing.expectEqual(@as(usize, 0), fed.answers.len);
}

test "escaping refuses a buffer it does not fit, and writes nothing" {
    var out: [3]u8 = .{ 0xaa, 0xaa, 0xaa };
    try testing.expectError(error.NoSpaceLeft, escape(&out, "a\xffb"));
    try testing.expectEqual(@as(u8, 0xaa), out[0]);
    try testing.expectEqual(@as(usize, 4), escapedLen("a\xffb"));
}

fn decodeAll(decoder: *Decoder, input: []const u8, data_out: []u8, answers_out: []u8) !Feed {
    return decoder.feed(input, data_out, answers_out);
}

test "a doubled 255 comes back as one octet and a command reaches no output" {
    // Measured against curl 8.21.0. A server that wrote
    // `data<FF><FF>with-iac<CRLF>`, then `IAC WILL ECHO`, then
    // `tail<CRLF>` gave curl's standard output
    // `data<FF>with-iac<CRLF>tail<CRLF>`.
    var decoder: Decoder = .{};
    var data: [128]u8 = undefined;
    var answers: [256]u8 = undefined;
    const fed = try decodeAll(
        &decoder,
        "data\xff\xffwith-iac\r\n\xff\xfb\x01tail\r\n",
        &data,
        &answers,
    );
    try testing.expectEqualSlices(u8, "data\xffwith-iac\r\ntail\r\n", fed.data);
    // `WILL ECHO` is refused, and the one time offer follows it.
    try testing.expectEqualSlices(
        u8,
        "\xff\xfe\x01" ++ "\xff\xfb\x00\xff\xfd\x00\xff\xfb\x03\xff\xfd\x03",
        fed.answers,
    );
}

test "a command split across two chunks is still one command" {
    // A decoder that started fresh on each chunk would write `\xfd\x18`
    // to the output as data.
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [256]u8 = undefined;

    const first = try decoder.feed("abc\xff", &data, &answers);
    try testing.expectEqualSlices(u8, "abc", first.data);
    try testing.expectEqual(@as(usize, 0), first.answers.len);

    var second_data: [64]u8 = undefined;
    var second_answers: [256]u8 = undefined;
    const second = try decoder.feed("\xfd\x18def", &second_data, &second_answers);
    try testing.expectEqualSlices(u8, "def", second.data);
    try testing.expectEqualSlices(
        u8,
        "\xff\xfc\x18" ++ "\xff\xfb\x00\xff\xfd\x00\xff\xfb\x03\xff\xfd\x03",
        second.answers,
    );
}

test "the answer to a DO TERMINAL-TYPE is the six lines curl writes" {
    // Measured: a server that opened with `IAC DO TERMINAL-TYPE` and then
    // `login: ` read back
    // `IAC WONT TTYPE`, `IAC WILL BINARY`, `IAC DO BINARY`,
    // `IAC WILL SGA`, `IAC DO SGA` from curl 8.21.0.
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [256]u8 = undefined;
    const fed = try decoder.feed("\xff\xfd\x18login: ", &data, &answers);
    try testing.expectEqualSlices(u8, "login: ", fed.data);
    try testing.expectEqualSlices(
        u8,
        "\xff\xfc\x18" ++ "\xff\xfb\x00" ++ "\xff\xfd\x00" ++
            "\xff\xfb\x03" ++ "\xff\xfd\x03",
        fed.answers,
    );
}

test "the offer goes out once, and never again" {
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [256]u8 = undefined;

    _ = try decoder.feed("\xff\xfd\x18", &data, &answers);
    // A second negotiation gets its own answer and no second offer.
    const second = try decoder.feed("\xff\xfd\x01", &data, &answers);
    try testing.expectEqualSlices(u8, "\xff\xfc\x01", second.answers);
}

test "an answer that would change nothing is not written" {
    // The rule RFC 1143 gives for keeping two endpoints out of a loop. The
    // offer said `WILL BINARY`, so a `DO BINARY` from the peer is the
    // answer to it and needs no reply.
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [256]u8 = undefined;

    _ = try decoder.feed("\xff\xfb\x00", &data, &answers); // WILL BINARY
    const settled = try decoder.feed("\xff\xfd\x00\xff\xfb\x03", &data, &answers);
    try testing.expectEqual(@as(usize, 0), settled.answers.len);
}

test "a subnegotiation reaches no output and does not swallow the session" {
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [256]u8 = undefined;
    // `IAC SB TTYPE SEND IAC SE`, then plain data.
    const fed = try decoder.feed("a\xff\xfa\x18\x01\xff\xf0b", &data, &answers);
    try testing.expectEqualSlices(u8, "ab", fed.data);
    try testing.expectEqual(@as(usize, 0), fed.answers.len);
}

test "a doubled 255 inside a subnegotiation does not end it" {
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [256]u8 = undefined;
    const fed = try decoder.feed("\xff\xfa\x18\xff\xff\x01\xff\xf0tail", &data, &answers);
    try testing.expectEqualSlices(u8, "tail", fed.data);
}

test "a two octet command reaches no output" {
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [256]u8 = undefined;
    // `IAC NOP`, `IAC GA`, and `IAC AYT` around some data.
    const fed = try decoder.feed("a\xff\xf1b\xff\xf9c\xff\xf6d", &data, &answers);
    try testing.expectEqualSlices(u8, "abcd", fed.data);
    try testing.expectEqual(@as(usize, 0), fed.answers.len);
}

test "a peer that negotiates forever is refused instead of answered forever" {
    var decoder: Decoder = .{};
    var data: [4096]u8 = undefined;
    var answers: [answersBound(4096)]u8 = undefined;

    // Each `IAC DO ECHO` is refused with `IAC WONT ECHO`, which is one
    // answer, and the first chunk carries the four offers too.
    var chunk: [3 * 1000]u8 = undefined;
    var at: usize = 0;
    while (at < chunk.len) : (at += 3) {
        chunk[at] = iac;
        chunk[at + 1] = command.do;
        chunk[at + 2] = option.echo;
    }

    var rounds: usize = 0;
    while (rounds < 10) : (rounds += 1) {
        _ = decoder.feed(&chunk, &data, &answers) catch |err| {
            try testing.expectEqual(error.TooManyNegotiations, err);
            try testing.expect(decoder.answers <= max_answers);
            return;
        };
    }
    return error.TestExpectedEqual;
}

test "an answers buffer that is too small is refused and not overrun" {
    var decoder: Decoder = .{};
    var data: [16]u8 = undefined;
    // Poison behind the buffer, so a build that removed the bounds check
    // fails this test instead of writing past the end and passing. See
    // `lib/zurl-net/line.zig` for the same idiom.
    var storage: [32]u8 = undefined;
    @memset(&storage, 0xaa);
    try testing.expectError(
        error.AnswerBufferTooSmall,
        decoder.feed("\xff\xfd\x18", &data, storage[0..4]),
    );
    for (storage[4..]) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);
}

test "a data buffer that is too small is refused and not overrun" {
    var decoder: Decoder = .{};
    var answers: [64]u8 = undefined;
    // The same poison idiom as the test above. Before the check this wrote
    // the fifth and later octets of the input past the end of the four the
    // caller gave, because the assertion that stood here is compiled out
    // of the builds that ship.
    var storage: [32]u8 = undefined;
    @memset(&storage, 0xaa);
    try testing.expectError(
        error.DataBufferTooSmall,
        decoder.feed("abcdefgh", storage[0..4], &answers),
    );
    for (storage) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);
}

test "a data buffer exactly as large as the chunk is enough" {
    var decoder: Decoder = .{};
    var answers: [64]u8 = undefined;
    var data: [8]u8 = undefined;
    const fed = try decoder.feed("abcdefgh", &data, &answers);
    try testing.expectEqualStrings("abcdefgh", fed.data);
}

/// The worst input of `len` octets for a decoder that already read `prefix`.
///
/// Every whole `IAC DO TERMINAL-TYPE` draws an answer, because this end
/// refuses that option and RFC 1143 answers a refusal every time. So the
/// input is as many of those as fit, and `prefix` decides where the first
/// one is cut.
fn worstNegotiation(out: []u8) void {
    var at: usize = 0;
    while (at < out.len) : (at += 1) {
        out[at] = switch (at % 3) {
            0 => iac,
            1 => command.do,
            else => option.terminal_type,
        };
    }
}

test "a chunk that starts inside a negotiation fits the bound this file names" {
    // **The two octet out-of-bounds write this bound used to allow.** A
    // peer wrote `IAC DO`, stopped so the read ended there, and then wrote
    // a whole chunk. The old `answersBound` modelled a chunk that starts in
    // state `.data`, where three input octets buy three answer octets. A
    // chunk that starts in state `.negotiate` answers its **first** octet
    // with three, so the true need is two octets more. `Decoder.write` then
    // wrote three octets with no check at all, and the second of the two
    // octets past the end was the option, which the peer chose.
    const chunk = 4096;
    var decoder: Decoder = .{};
    var data: [chunk]u8 = undefined;
    var opening: [answersBound(2)]u8 = undefined;

    // `IAC DO`, with the option octet held back. This leaves the decoder in
    // state `.negotiate`.
    const opened = try decoder.feed(&.{ iac, command.do }, &data, &opening);
    try testing.expectEqual(@as(usize, 0), opened.data.len);
    try testing.expectEqual(@as(usize, 0), opened.answers.len);

    // The option octet the last read held back, and then whole
    // negotiations for the rest of the chunk.
    var input: [chunk]u8 = undefined;
    input[0] = option.terminal_type;
    worstNegotiation(input[1..]);

    // Poison past the end of the answer buffer. A build with no bounds
    // check writes there and returns rather than panic, so this is what
    // proves the overrun is gone in ReleaseFast as well as in Debug.
    var storage: [answersBound(chunk) + 16]u8 = undefined;
    @memset(&storage, 0xaa);
    const answers = storage[0..answersBound(chunk)];

    const fed = try decoder.feed(&input, &data, answers);
    try testing.expectEqual(@as(usize, 0), fed.data.len);
    // Every octet of the bound is used, and not one past it.
    try testing.expectEqual(answersBound(chunk), fed.answers.len);
    for (storage[answersBound(chunk)..]) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);
    // The first answer is the refusal for the command the read split.
    try testing.expectEqualSlices(
        u8,
        &.{ iac, command.wont, option.terminal_type },
        fed.answers[0..3],
    );
}

test "a chunk that starts on a held IAC fits the bound too" {
    // The sibling of the case above, and the reason the bound adds two and
    // not three: a chunk that starts in state `.iac` answers its first two
    // octets with three.
    const chunk = 1025;
    var decoder: Decoder = .{};
    var data: [chunk]u8 = undefined;
    var opening: [answersBound(1)]u8 = undefined;
    _ = try decoder.feed(&.{iac}, &data, &opening);

    var input: [chunk]u8 = undefined;
    input[0] = command.do;
    input[1] = option.terminal_type;
    worstNegotiation(input[2..]);

    var storage: [answersBound(chunk) + 16]u8 = undefined;
    @memset(&storage, 0xaa);
    const answers = storage[0..answersBound(chunk)];

    const fed = try decoder.feed(&input, &data, answers);
    try testing.expect(fed.answers.len <= answersBound(chunk));
    // And past the old formula, which was `input.len + offer.len`.
    try testing.expect(fed.answers.len > chunk + offer.len);
    for (storage[answersBound(chunk)..]) |byte| try testing.expectEqual(@as(u8, 0xaa), byte);
}

test "command octets that draw no answer are bounded" {
    // A subnegotiation that never ends produces no data octet and no
    // answer, so neither the caller's response bound nor `max_answers`
    // counts one of its octets. Without `max_discarded` a peer holds this
    // end reading for as long as it likes, at five octets a second.
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [answersBound(64)]u8 = undefined;

    const opener = [_]u8{ iac, command.sb };
    _ = try decoder.feed(&opener, &data, &answers);

    // Parameter octets, none of which ends the subnegotiation.
    const parameters: [64]u8 = @splat(0);
    const blocks = (max_discarded - opener.len) / parameters.len;
    for (0..blocks) |_| {
        const fed = try decoder.feed(&parameters, &data, &answers);
        try testing.expectEqual(@as(usize, 0), fed.data.len);
        try testing.expectEqual(@as(usize, 0), fed.answers.len);
    }
    const rest = max_discarded - opener.len - blocks * parameters.len;
    _ = try decoder.feed(parameters[0..rest], &data, &answers);
    try testing.expectEqual(max_discarded, decoder.discarded);

    try testing.expectError(
        error.TooManyCommandOctets,
        decoder.feed(parameters[0..1], &data, &answers),
    );
}

test "a two octet command written forever is bounded too" {
    // `IAC NOP` draws no answer either, and it leaves the decoder back in
    // state `.data` every time, so no state machine ever stops it.
    var decoder: Decoder = .{};
    var data: [64]u8 = undefined;
    var answers: [answersBound(64)]u8 = undefined;

    var chunk: [64]u8 = undefined;
    var at: usize = 0;
    while (at < chunk.len) : (at += 2) {
        chunk[at] = iac;
        chunk[at + 1] = command.nop;
    }

    var rounds: usize = 0;
    while (rounds < max_discarded) : (rounds += 1) {
        _ = decoder.feed(&chunk, &data, &answers) catch |err| {
            try testing.expectEqual(error.TooManyCommandOctets, err);
            try testing.expect(decoder.discarded <= max_discarded);
            return;
        };
    }
    return error.TestExpectedEqual;
}
