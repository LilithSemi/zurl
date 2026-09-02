//! The live key state of one QUIC connection: the key set at each
//! encryption level, the packet number that each one is used with, and the
//! key update of RFC 9001 section 6.
//!
//! **This file exists to stop a nonce repeating.** RFC 9001 section 5.3
//! makes the AEAD nonce the packet protection IV exclusive-ored with the
//! packet number. The IV is fixed for a key, so two packets sent under one
//! key with one packet number would share a nonce, and a shared nonce
//! under AES-GCM or ChaCha20-Poly1305 gives away the authentication key.
//! Nothing else about QUIC matters as much.
//!
//! ## The bound, in one place
//!
//! A packet number comes from `nextPacketNumber` and from nowhere else. It
//! is issued once, it never goes back, and it stops for three reasons:
//!
//! 1. **The space is used up.** RFC 9000 section 12.3 gives a packet
//!    number space 2^62 - 1 numbers and requires the connection to close
//!    rather than reuse one. That is `error.PacketNumberExhausted`.
//! 2. **The AEAD confidentiality limit.** RFC 9001 section 6.6 bounds how
//!    many packets one key may protect: 2^23 for the AES-GCM suites and
//!    2^62 for ChaCha20-Poly1305. Reaching it at the application level is
//!    `error.KeyUpdateRequired`, and the caller runs `update`. At the
//!    Initial and Handshake levels there is no key update, so the same
//!    count is `error.AeadLimitReached` and the connection must close.
//! 3. **The AEAD integrity limit.** Section 6.6 also bounds how many
//!    packets may fail to open under one key: 2^52 for AES-GCM and 2^36
//!    for ChaCha20-Poly1305. `failedOpen` counts them and reports
//!    `error.AeadLimitReached` at the bound.
//!
//! Each level has its own space, and at the application level each key
//! phase starts a fresh count. A key update therefore gives a new key, a
//! new IV, and a count that starts again, and the packet number keeps
//! climbing across the update. So the pair (key, packet number) is never
//! repeated: within one phase the number is new, and across two phases the
//! key is new.
//!
//! ## What this file does not do
//!
//! It sends nothing and it reads nothing. There is no loss recovery, no
//! congestion control, and no timer here. The caller drives it.

const std = @import("std");

const quic = @import("zurl-quic");
const protection = quic.protection;
const schedule = @import("schedule.zig");

const Session = @This();

/// The largest packet number QUIC version 1 allows. RFC 9000 section 12.3.
pub const max_packet_number: u64 = (1 << 62) - 1;

/// Why a key could not be used.
pub const Error = error{
    /// The packet number space is used up. RFC 9000 section 12.3 requires
    /// the connection to close rather than reuse a number.
    PacketNumberExhausted,
    /// The AEAD limit of RFC 9001 section 6.6 is reached at a level with
    /// no key update, so the connection must close.
    AeadLimitReached,
    /// The application keys have protected as many packets as RFC 9001
    /// section 6.6 allows. The caller runs `update` and sends again.
    KeyUpdateRequired,
    /// A key update was asked for before the handshake was confirmed, or
    /// while the last one is still unacknowledged. RFC 9001 section 6.
    KeyUpdateNotAllowed,
    /// The level has no keys yet.
    KeysNotReady,
};

/// How many packets one key may protect. RFC 9001 section 6.6.
pub fn confidentialityLimit(suite: protection.Suite) u64 {
    return switch (suite) {
        // "the confidentiality limit is 2^23 encrypted packets".
        .aes_128_gcm, .aes_256_gcm => 1 << 23,
        // "the confidentiality limit is greater than 2^62", so the packet
        // number space runs out first.
        .chacha20_poly1305 => max_packet_number,
    };
}

/// How many packets may fail to open under one key. RFC 9001 section 6.6.
pub fn integrityLimit(suite: protection.Suite) u64 {
    return switch (suite) {
        .aes_128_gcm, .aes_256_gcm => 1 << 52,
        .chacha20_poly1305 => 1 << 36,
    };
}

/// One packet number space. RFC 9000 section 12.3.
///
/// Initial, Handshake, and application data each have one, and a number
/// means nothing outside the space it was issued in.
pub const Space = struct {
    /// The number the next packet gets.
    next: u64 = 0,
    /// The largest number the peer has acknowledged, which decides how
    /// few bytes the packet number needs on the wire.
    largest_acked: ?u64 = null,

    /// Issues the next packet number.
    ///
    /// **This is the only way a packet number is produced.** It hands out
    /// each number once and it never hands out the same one twice, which
    /// is what keeps one nonce from covering two packets.
    pub fn take(self: *Space) Error!u64 {
        if (self.next > max_packet_number) return error.PacketNumberExhausted;
        const number = self.next;
        self.next += 1;
        return number;
    }

    /// Records a packet number the peer acknowledged.
    pub fn acknowledge(self: *Space, number: u64) void {
        if (self.largest_acked == null or number > self.largest_acked.?) {
            self.largest_acked = number;
        }
    }
};

/// A key set for each direction at one level.
pub const Pair = struct {
    /// Protects packets this endpoint sends.
    write: protection.Keys,
    /// Opens packets the peer sends.
    read: protection.Keys,
};

/// The application level, which is the one level with a key update.
pub const Application = struct {
    /// The Key Phase bit of the short header, RFC 9001 section 6. It
    /// starts at zero and flips at each update.
    phase: u1,
    /// The traffic secret behind `keys.write`.
    write_secret: schedule.Secret,
    /// The traffic secret behind `keys.read`.
    read_secret: schedule.Secret,
    keys: Pair,
    /// The key set for the next phase in the read direction, kept so a
    /// packet the peer sent after its own update can be opened without
    /// deriving under a timer. RFC 9001 section 6.3.
    next_read_secret: schedule.Secret,
    next_read_keys: protection.Keys,
    /// The read key set of the phase before this one, or null before the
    /// first update.
    ///
    /// **RFC 9001 section 6.3 requires this.** A packet the peer sent
    /// before the update can arrive after it, because the path reorders,
    /// and it opens only under the generation it was sealed with. The RFC
    /// asks for about three PTO, and `discardPreviousReadKeys` is what
    /// ends that.
    previous_read_keys: ?protection.Keys,
    /// The lowest packet number that has opened in this phase, or null
    /// before one has.
    ///
    /// RFC 9001 section 6.3 uses it to tell a reordered packet of the
    /// previous phase from the peer starting a new update: both carry a
    /// Key Phase bit that is not the current one, and only the packet
    /// number separates them.
    first_in_phase: ?u64,
    /// How many packets this phase's write key has protected.
    sent_in_phase: u64,
    /// Whether an update this endpoint started is still unacknowledged.
    /// RFC 9001 section 6.1 bars a second update until then.
    update_pending: bool,
};

suite: protection.Suite,
/// The Initial keys, which RFC 9001 section 5.2 derives with no handshake.
initial: ?Pair,
/// The Handshake keys, from the TLS handshake traffic secrets.
handshake: ?Pair,
/// The 1-RTT keys, from the TLS application traffic secrets.
application: ?Application,
/// One space for each level that has one. Index by `spaceIndex`.
spaces: [3]Space,
/// Whether the server has sent HANDSHAKE_DONE. RFC 9001 section 4.1.2
/// makes that the point the handshake is confirmed for a client, and RFC
/// 9001 section 6 bars a key update before it.
handshake_confirmed: bool,
/// How many packets failed to open under the current keys, over the whole
/// connection. RFC 9001 section 6.6 bounds this.
failed_opens: u64,

/// A session with the Initial keys and nothing else.
///
/// `dcid` is the Destination Connection ID of the client's first Initial
/// packet. RFC 9001 section 5.2 derives both Initial keys from it.
pub fn init(dcid: []const u8) Session {
    return initFrom(dcid, @splat(0));
}

/// The same session, with each packet number space carrying on from
/// `next_packet_numbers` instead of starting at zero.
///
/// **A Retry needs this.** The model for a Retry is to build a second
/// `Handshake`, and therefore a second `Session`. RFC 9000 section
/// 17.2.5.3 says a client MUST NOT reset its packet numbers when it sends
/// its Initial packets again, so the numbers the first attempt reached are
/// handed over here. The index is the one `space` uses.
pub fn initFrom(dcid: []const u8, next_packet_numbers: [3]u64) Session {
    const secrets = quic.initial.secrets(dcid);
    var spaces: [3]Space = @splat(.{});
    for (&spaces, next_packet_numbers) |*slot, number| slot.next = number;
    return .{
        // The Initial keys always use this suite, whatever TLS goes on to
        // negotiate. RFC 9001 section 5.2.
        .suite = quic.initial.suite,
        .initial = .{
            .write = .fromSecret(quic.initial.suite, &secrets.client),
            .read = .fromSecret(quic.initial.suite, &secrets.server),
        },
        .handshake = null,
        .application = null,
        .spaces = spaces,
        .handshake_confirmed = false,
        .failed_opens = 0,
    };
}

/// Which space a level uses. RFC 9000 section 12.3 gives 0-RTT and 1-RTT
/// one space between them.
fn spaceIndex(level: protection.Level) usize {
    return switch (level) {
        .initial => 0,
        .handshake => 1,
        .zero_rtt, .application => 2,
    };
}

/// The packet number space of one level.
pub fn space(self: *Session, level: protection.Level) *Space {
    return &self.spaces[spaceIndex(level)];
}

/// Installs the Handshake keys from the TLS handshake traffic secrets.
///
/// `suite` is what TLS negotiated, and it replaces the Initial suite for
/// every level above Initial.
pub fn setHandshakeKeys(
    self: *Session,
    suite: protection.Suite,
    traffic: *const schedule.Pair,
) void {
    self.suite = suite;
    self.handshake = .{
        .write = schedule.keys(suite, &traffic.client),
        .read = schedule.keys(suite, &traffic.server),
    };
}

/// Installs the 1-RTT keys from the TLS application traffic secrets.
pub fn setApplicationKeys(
    self: *Session,
    suite: protection.Suite,
    traffic: *const schedule.Pair,
) void {
    self.suite = suite;
    const next_read = schedule.nextSecret(suite, &traffic.server);
    const read_keys = schedule.keys(suite, &traffic.server);
    self.application = .{
        .phase = 0,
        .write_secret = traffic.client,
        .read_secret = traffic.server,
        .keys = .{
            .write = schedule.keys(suite, &traffic.client),
            .read = read_keys,
        },
        .next_read_secret = next_read,
        // The header protection key of the next generation is this
        // generation's. RFC 9001 section 5.4.
        .next_read_keys = schedule.updatedKeys(suite, &read_keys, &next_read),
        .previous_read_keys = null,
        .first_in_phase = null,
        .sent_in_phase = 0,
        .update_pending = false,
    };
}

/// Writes zeroes over the key material of one key set.
///
/// `protection.Keys` has no `clear` of its own, and setting an optional to
/// null leaves the payload where it was. Only the three key fields are
/// written over: `suite` is not a secret, and zeroing it would leave an
/// enum holding the name of another suite.
fn clearKeys(keys: *protection.Keys) void {
    std.crypto.secureZero(u8, &keys.key);
    std.crypto.secureZero(u8, &keys.iv);
    std.crypto.secureZero(u8, &keys.hp);
}

/// Writes zeroes over both key sets of a level and drops them.
fn clearPair(pair: *?Pair) void {
    if (pair.*) |*keys| {
        clearKeys(&keys.write);
        clearKeys(&keys.read);
    }
    pair.* = null;
}

/// Drops the Initial keys. RFC 9001 section 4.9.1 says a client does this
/// as soon as it sends a Handshake packet.
///
/// The keys are written over first. Assigning null to an optional leaves
/// the payload in memory verbatim, and an AEAD key that is still there is
/// an AEAD key somebody can read.
pub fn dropInitialKeys(self: *Session) void {
    clearPair(&self.initial);
}

/// Drops the Handshake keys. RFC 9001 section 4.9.2 says an endpoint does
/// this when the handshake is confirmed.
pub fn dropHandshakeKeys(self: *Session) void {
    clearPair(&self.handshake);
}

/// Records the HANDSHAKE_DONE frame, RFC 9000 section 19.20.
///
/// **Only a server sends it**, and it is what confirms the handshake for a
/// client. RFC 9001 section 4.1.2. Until then no key update may run, and
/// the Handshake keys stay.
pub fn handshakeDone(self: *Session) void {
    self.handshake_confirmed = true;
    self.dropHandshakeKeys();
}

/// The key set that protects a packet this endpoint sends at `level`, or
/// null when that level has no keys.
pub fn writeKeys(self: *const Session, level: protection.Level) ?protection.Keys {
    return switch (level) {
        .initial => if (self.initial) |pair| pair.write else null,
        .handshake => if (self.handshake) |pair| pair.write else null,
        .application => if (self.application) |app| app.keys.write else null,
        // Nothing here offers 0-RTT. RFC 9001 section 4.6 makes it
        // optional, and a client with no session ticket has nothing to
        // send under it.
        .zero_rtt => null,
    };
}

/// The key set that opens a packet the peer sent at `level`, or null when
/// that level has no keys.
pub fn readKeys(self: *const Session, level: protection.Level) ?protection.Keys {
    return switch (level) {
        .initial => if (self.initial) |pair| pair.read else null,
        .handshake => if (self.handshake) |pair| pair.read else null,
        .application => if (self.application) |app| app.keys.read else null,
        .zero_rtt => null,
    };
}

/// The Key Phase bit to write into a short header, or null before the
/// application keys exist.
pub fn keyPhase(self: *const Session) ?u1 {
    const app = self.application orelse return null;
    return app.phase;
}

/// Issues the packet number for the next packet at `level`, and counts it
/// against the AEAD limit of the key that will protect it.
///
/// **Every packet this build sends takes its number from here.** The
/// counting and the bound are in the same call as the number, so there is
/// no way to get a number without meeting the limit that goes with it.
pub fn nextPacketNumber(self: *Session, level: protection.Level) Error!u64 {
    // The limit belongs to the key that will protect the packet, so the
    // suite comes from that key set and not from the connection. The
    // Initial level always runs AES-128-GCM whatever TLS went on to
    // negotiate, which is why the two can differ.
    const keys = self.writeKeys(level) orelse return error.KeysNotReady;
    const limit = confidentialityLimit(keys.suite);

    switch (level) {
        .initial, .handshake, .zero_rtt => {
            // There is no key update below the application level, so the
            // AEAD limit is the end of the road for these keys. RFC 9001
            // section 6.6 has the connection close.
            if (self.spaces[spaceIndex(level)].next >= limit) return error.AeadLimitReached;
        },
        .application => {
            const app = &self.application.?;
            if (app.sent_in_phase >= limit) return error.KeyUpdateRequired;
            app.sent_in_phase += 1;
        },
    }

    return self.spaces[spaceIndex(level)].take();
}

/// Counts one packet that did not open, and reports the AEAD integrity
/// limit of RFC 9001 section 6.6.
///
/// A packet that fails to open is discarded and is not a connection error
/// on its own, because anyone can write bytes to a socket. Enough of them
/// under one key is a connection error, because that is what a forgery
/// attempt looks like.
///
/// **The count is for the whole connection and not for one key.** Section
/// 6.6 bounds it per key, so counting every level together reaches the
/// bound sooner than the RFC requires. That is the safe direction.
pub fn failedOpen(self: *Session) Error!void {
    self.failed_opens += 1;
    if (self.failed_opens >= integrityLimit(self.suite)) return error.AeadLimitReached;
}

/// Runs a key update. RFC 9001 section 6.
///
/// Both directions move together, the Key Phase bit flips, and the count
/// against the confidentiality limit starts again. The next generation of
/// the read keys is derived at the same time, so a packet the peer sends
/// under its own new keys can be opened at once.
///
/// **Two rules stop an update.** RFC 9001 section 6 bars one before the
/// handshake is confirmed, and section 6.1 bars a second one until a
/// packet in the new phase has been acknowledged. Both are
/// `error.KeyUpdateNotAllowed`.
pub fn update(self: *Session) Error!void {
    if (!self.handshake_confirmed) return error.KeyUpdateNotAllowed;
    const app = &(self.application orelse return error.KeysNotReady);
    if (app.update_pending) return error.KeyUpdateNotAllowed;

    self.rotate(app);
    app.update_pending = true;
}

/// Moves both directions on by one generation. RFC 9001 section 6.
///
/// **The header protection keys stay.** RFC 9001 section 5.4 runs one
/// header protection key for the whole connection, so `schedule.updatedKeys`
/// puts the old one back over the derivation.
/// **The generation this replaces is kept.** RFC 9001 section 6.3 has an
/// endpoint keep the old read keys for about three PTO, so a packet the
/// peer sent before the update still opens when the path delivers it
/// late. `discardPreviousReadKeys` is what ends that hold.
fn rotate(self: *Session, app: *Application) void {
    const next_write = schedule.nextSecret(self.suite, &app.write_secret);
    app.write_secret.clear();
    app.write_secret = next_write;
    app.keys.write = schedule.updatedKeys(self.suite, &app.keys.write, &next_write);

    if (app.previous_read_keys) |*old| clearKeys(old);
    app.previous_read_keys = app.keys.read;

    app.read_secret.clear();
    app.read_secret = app.next_read_secret;
    app.keys.read = app.next_read_keys;
    app.next_read_secret = schedule.nextSecret(self.suite, &app.read_secret);
    app.next_read_keys = schedule.updatedKeys(self.suite, &app.keys.read, &app.next_read_secret);

    app.phase = ~app.phase;
    app.sent_in_phase = 0;
    app.first_in_phase = null;
}

/// Records that a packet sent in the current phase was acknowledged, which
/// is what lets the next update run. RFC 9001 section 6.1.
pub fn confirmUpdate(self: *Session) void {
    const app = &(self.application orelse return);
    app.update_pending = false;
}

/// Whether an update this side ran is still waiting for an acknowledgment
/// in the new phase. RFC 9001 section 6.1 bars a second update until then.
pub fn updatePending(self: *const Session) bool {
    const app = self.application orelse return false;
    return app.update_pending;
}

/// Records a packet that opened under the current phase's read keys.
///
/// RFC 9001 section 6.3 tells a reordered packet of the previous phase
/// from the start of a new update by the packet number, and this is what
/// gives `readKeysForPacket` the number to compare against. A caller that
/// never calls this loses the reordering tolerance and nothing else.
pub fn recordOpened(self: *Session, phase: u1, number: u64) void {
    const app = &(self.application orelse return);
    if (phase != app.phase) return;
    if (app.first_in_phase == null or number < app.first_in_phase.?) {
        app.first_in_phase = number;
    }
}

/// Writes zeroes over the read keys of the generation before this one and
/// drops them.
///
/// RFC 9001 section 6.3 has an endpoint hold them for about three PTO
/// after an update, so the caller runs this when that time is up. Holding
/// them for longer is not a leak of key material to the peer, but it is
/// key material in memory with no use left.
pub fn discardPreviousReadKeys(self: *Session) void {
    const app = &(self.application orelse return);
    if (app.previous_read_keys) |*old| clearKeys(old);
    app.previous_read_keys = null;
}

/// The key set that opens a short header packet with Key Phase `phase`,
/// or null when the application keys are not there.
///
/// A phase that is not the current one is the peer starting an update, and
/// RFC 9001 section 6.3 has the receiver open the packet under the next
/// generation before it moves its own keys. So this hands back the next
/// generation and leaves the session alone: a packet that does not open
/// under it is a forgery, and moving the keys for one would let anybody
/// force an update.
///
/// **This answers only half of RFC 9001 section 6.3.** A packet in the
/// other phase may instead be one the peer sent before this side's last
/// update, which the path delivered late. Only the packet number tells the
/// two apart, so a caller that has one uses `readKeysForPacket`.
pub fn readKeysForPhase(self: *const Session, phase: u1) ?protection.Keys {
    const app = self.application orelse return null;
    if (phase == app.phase) return app.keys.read;
    return app.next_read_keys;
}

/// Which generation of the read keys opens a short header packet.
pub const ReadGeneration = enum {
    /// The keys of the current phase.
    current,
    /// The generation before the current one, for a packet the peer sent
    /// before this side's last update and the path delivered late. RFC
    /// 9001 section 6.3. Accepting one is **not** a key update.
    previous,
    /// The generation after the current one, which is the peer starting an
    /// update. A packet that opens under it is what `acceptPeerUpdate`
    /// waits for.
    next,
};

/// Which generation a short header packet with Key Phase `phase` and
/// packet number `number` belongs to, or null before the application keys
/// exist.
///
/// A Key Phase bit that is not the current one means one of two things,
/// and the packet number is what separates them. Below the lowest number
/// this side has opened in the current phase, the packet was sent before
/// the last update. At or above it, the peer is starting an update.
/// `recordOpened` is what supplies that number, and with none recorded the
/// answer is `.next`, which is the state a connection is in before its
/// first update.
///
/// **A caller needs this and not only the keys.** Only a packet that
/// opened under `.next` may be answered with `acceptPeerUpdate`, and the
/// key set alone does not say which one it was.
pub fn readGeneration(self: *const Session, phase: u1, number: u64) ?ReadGeneration {
    const app = self.application orelse return null;
    if (phase == app.phase) return .current;
    if (app.first_in_phase) |lowest| {
        if (number < lowest) return .previous;
    }
    return .next;
}

/// The key set that opens a short header packet with Key Phase `phase` and
/// packet number `number`. RFC 9001 section 6.3, whole.
///
/// Null means nothing this session holds can open it, which for
/// `.previous` is a generation already dropped.
pub fn readKeysForPacket(self: *const Session, phase: u1, number: u64) ?protection.Keys {
    const app = self.application orelse return null;
    return switch (self.readGeneration(phase, number).?) {
        .current => app.keys.read,
        .previous => app.previous_read_keys,
        .next => app.next_read_keys,
    };
}

/// Moves the session onto the phase the peer started, after a packet has
/// opened under `readKeysForPacket`. RFC 9001 section 6.2.
///
/// `phase` is the Key Phase bit of the packet that opened. **It is checked
/// against the current phase**, so a second packet in the phase the peer
/// already moved to is not a second update. Without that check two packets
/// in one new phase rotate twice and leave the read keys a generation past
/// the peer's write keys, and every packet after that fails to open and
/// counts toward the integrity limit.
///
/// This is the same rotation as `update`, and it runs when the peer went
/// first. It runs before this side's own update is acknowledged, because
/// the peer chose the moment. It sets `update_pending` all the same:
/// `rotate` moves the write keys too, and RFC 9001 section 6.1 bars
/// another update until a packet in the new phase is acknowledged.
pub fn acceptPeerUpdate(self: *Session, phase: u1) Error!void {
    if (!self.handshake_confirmed) return error.KeyUpdateNotAllowed;
    const app = &(self.application orelse return error.KeysNotReady);
    if (phase == app.phase) return;
    self.rotate(app);
    app.update_pending = true;
}

/// Writes zeroes over every secret the session holds.
///
/// Assigning null to an optional does not touch the payload, so every key
/// set is written over before it is dropped. Otherwise the AEAD keys, the
/// IVs, and the header protection keys of every level stay in memory
/// verbatim after this call says they are gone.
pub fn clear(self: *Session) void {
    clearPair(&self.initial);
    clearPair(&self.handshake);
    if (self.application) |*app| {
        app.write_secret.clear();
        app.read_secret.clear();
        app.next_read_secret.clear();
        clearKeys(&app.keys.write);
        clearKeys(&app.keys.read);
        clearKeys(&app.next_read_keys);
        if (app.previous_read_keys) |*old| clearKeys(old);
    }
    self.application = null;
}

const testing = std.testing;

test "a fresh session holds the Initial keys of RFC 9001 appendix A" {
    // The connection id of appendix A.1, so the keys below are the ones
    // `rfc9001_test.zig` already checks byte for byte.
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var session: Session = .init(&dcid);

    const write = session.writeKeys(.initial).?;
    const read = session.readKeys(.initial).?;
    try testing.expectEqual(protection.Suite.aes_128_gcm, write.suite);
    try testing.expectEqualSlices(u8, quic.initial.clientKeys(&dcid).keySlice(), write.keySlice());
    try testing.expectEqualSlices(u8, quic.initial.serverKeys(&dcid).keySlice(), read.keySlice());

    // Nothing above Initial is there yet.
    try testing.expect(session.writeKeys(.handshake) == null);
    try testing.expect(session.readKeys(.handshake) == null);
    try testing.expect(session.writeKeys(.application) == null);
    try testing.expect(session.keyPhase() == null);
    // And this build never offers 0-RTT.
    try testing.expect(session.writeKeys(.zero_rtt) == null);
}

test "each level has its own packet number space and each number is issued once" {
    var session: Session = .init(&[_]u8{0x01} ** 8);
    session.setHandshakeKeys(.aes_128_gcm, &.{
        .client = .from(&[_]u8{0x11} ** 32),
        .server = .from(&[_]u8{0x22} ** 32),
    });

    try testing.expectEqual(@as(u64, 0), try session.nextPacketNumber(.initial));
    try testing.expectEqual(@as(u64, 1), try session.nextPacketNumber(.initial));
    // The Handshake space starts at zero of its own.
    try testing.expectEqual(@as(u64, 0), try session.nextPacketNumber(.handshake));
    try testing.expectEqual(@as(u64, 2), try session.nextPacketNumber(.initial));
    try testing.expectEqual(@as(u64, 1), try session.nextPacketNumber(.handshake));

    // A level with no keys has no numbers.
    try testing.expectError(error.KeysNotReady, session.nextPacketNumber(.application));
}

test "a level with no key update stops at the AEAD confidentiality limit" {
    var session: Session = .init(&[_]u8{0x02} ** 8);
    // Step the space to one below the limit, which a test cannot reach by
    // sending 2^23 packets.
    session.spaces[0].next = confidentialityLimit(.aes_128_gcm) - 1;
    try testing.expectEqual(confidentialityLimit(.aes_128_gcm) - 1, try session.nextPacketNumber(.initial));
    // The next one would pass the limit, and Initial has no key update.
    try testing.expectError(error.AeadLimitReached, session.nextPacketNumber(.initial));
}

test "the AEAD limit of a level comes from that level's own suite" {
    // RFC 9001 section 5.2 makes every Initial packet AES-128-GCM,
    // whatever TLS goes on to negotiate. So a connection that settled on
    // ChaCha20-Poly1305 still holds the Initial level to the 2^23 bound
    // of AES-GCM and not to the far larger ChaCha20 one.
    var session: Session = .init(&[_]u8{0x09} ** 8);
    session.setHandshakeKeys(.chacha20_poly1305, &.{
        .client = .from(&[_]u8{0xdd} ** 32),
        .server = .from(&[_]u8{0xee} ** 32),
    });
    try testing.expectEqual(protection.Suite.chacha20_poly1305, session.suite);
    try testing.expectEqual(protection.Suite.aes_128_gcm, session.writeKeys(.initial).?.suite);

    session.spaces[0].next = confidentialityLimit(.aes_128_gcm);
    try testing.expectError(error.AeadLimitReached, session.nextPacketNumber(.initial));

    // And the Handshake level, which really is ChaCha20, keeps going at
    // the same count.
    session.spaces[1].next = confidentialityLimit(.aes_128_gcm);
    _ = try session.nextPacketNumber(.handshake);
}

test "the application level asks for a key update at the same limit" {
    var session: Session = .init(&[_]u8{0x03} ** 8);
    session.setApplicationKeys(.aes_128_gcm, &.{
        .client = .from(&[_]u8{0x33} ** 32),
        .server = .from(&[_]u8{0x44} ** 32),
    });
    session.handshake_confirmed = true;

    session.application.?.sent_in_phase = confidentialityLimit(.aes_128_gcm) - 1;
    _ = try session.nextPacketNumber(.application);
    try testing.expectError(error.KeyUpdateRequired, session.nextPacketNumber(.application));

    // And after the update the count starts again, while the packet
    // number keeps climbing. So the pair of key and number is new twice
    // over.
    const before = session.spaces[2].next;
    try session.update();
    const number = try session.nextPacketNumber(.application);
    try testing.expectEqual(before, number);
    try testing.expectEqual(@as(u64, 1), session.application.?.sent_in_phase);
}

test "the packet number space itself runs out rather than wrap" {
    var last: Space = .{ .next = max_packet_number };
    try testing.expectEqual(max_packet_number, try last.take());
    try testing.expectError(error.PacketNumberExhausted, last.take());
    try testing.expectError(error.PacketNumberExhausted, last.take());
}

test "ChaCha20-Poly1305 has a confidentiality limit the space reaches first" {
    // RFC 9001 section 6.6 puts the ChaCha20 limit above the packet
    // number space, so the space is what stops that suite.
    try testing.expectEqual(max_packet_number, confidentialityLimit(.chacha20_poly1305));
    try testing.expectEqual(@as(u64, 1 << 23), confidentialityLimit(.aes_128_gcm));
    try testing.expectEqual(@as(u64, 1 << 23), confidentialityLimit(.aes_256_gcm));

    // And the integrity limits are the other way round.
    try testing.expectEqual(@as(u64, 1 << 52), integrityLimit(.aes_128_gcm));
    try testing.expectEqual(@as(u64, 1 << 36), integrityLimit(.chacha20_poly1305));
}

test "enough packets that fail to open closes the connection" {
    var session: Session = .init(&[_]u8{0x04} ** 8);
    // One below the ChaCha20 limit, which is the low one.
    session.suite = .chacha20_poly1305;
    session.failed_opens = integrityLimit(.chacha20_poly1305) - 2;
    try session.failedOpen();
    try testing.expectError(error.AeadLimitReached, session.failedOpen());
}

test "a key update changes both keys and flips the phase" {
    var session: Session = .init(&[_]u8{0x05} ** 8);
    session.setApplicationKeys(.aes_128_gcm, &.{
        .client = .from(&[_]u8{0x55} ** 32),
        .server = .from(&[_]u8{0x66} ** 32),
    });

    // RFC 9001 section 6 bars an update before the handshake is
    // confirmed, which for a client is the HANDSHAKE_DONE frame.
    try testing.expectError(error.KeyUpdateNotAllowed, session.update());

    session.handshakeDone();
    try testing.expect(session.handshake_confirmed);
    // Confirming the handshake drops the Handshake keys. RFC 9001
    // section 4.9.2.
    try testing.expect(session.writeKeys(.handshake) == null);

    const before_write = session.writeKeys(.application).?;
    const before_read = session.readKeys(.application).?;
    try testing.expectEqual(@as(u1, 0), session.keyPhase().?);

    try session.update();
    try testing.expectEqual(@as(u1, 1), session.keyPhase().?);
    const after_write = session.writeKeys(.application).?;
    const after_read = session.readKeys(.application).?;
    try testing.expect(!std.mem.eql(u8, before_write.keySlice(), after_write.keySlice()));
    try testing.expect(!std.mem.eql(u8, before_read.keySlice(), after_read.keySlice()));
    // The header protection key does not change. RFC 9001 section 6.
    try testing.expectEqualSlices(u8, before_write.headerKeySlice(), after_write.headerKeySlice());

    // A second update must wait for the first to be acknowledged. RFC
    // 9001 section 6.1.
    try testing.expectError(error.KeyUpdateNotAllowed, session.update());
    session.confirmUpdate();
    try session.update();
    try testing.expectEqual(@as(u1, 0), session.keyPhase().?);
}

test "a packet in the phase the peer started opens under the next generation" {
    var session: Session = .init(&[_]u8{0x06} ** 8);
    session.setApplicationKeys(.aes_128_gcm, &.{
        .client = .from(&[_]u8{0x77} ** 32),
        .server = .from(&[_]u8{0x88} ** 32),
    });
    session.handshakeDone();

    const current = session.readKeysForPhase(0).?;
    const next = session.readKeysForPhase(1).?;
    try testing.expectEqualSlices(u8, session.readKeys(.application).?.keySlice(), current.keySlice());
    try testing.expect(!std.mem.eql(u8, current.keySlice(), next.keySlice()));

    // Reading with the next generation must not move the session on its
    // own, because anybody can send bytes with the other phase bit.
    try testing.expectEqual(@as(u1, 0), session.keyPhase().?);

    // The move happens only after a packet really opened.
    try session.acceptPeerUpdate(1);
    try testing.expectEqual(@as(u1, 1), session.keyPhase().?);
    try testing.expectEqualSlices(u8, next.keySlice(), session.readKeys(.application).?.keySlice());
}

test "the two directions never share a key at any level" {
    var session: Session = .init(&[_]u8{0x07} ** 8);
    try testing.expect(!std.mem.eql(
        u8,
        session.writeKeys(.initial).?.keySlice(),
        session.readKeys(.initial).?.keySlice(),
    ));

    session.setHandshakeKeys(.aes_256_gcm, &.{
        .client = .from(&[_]u8{0x99} ** 48),
        .server = .from(&[_]u8{0xaa} ** 48),
    });
    try testing.expect(!std.mem.eql(
        u8,
        session.writeKeys(.handshake).?.keySlice(),
        session.readKeys(.handshake).?.keySlice(),
    ));
    // And the negotiated suite replaced the Initial one.
    try testing.expectEqual(protection.Suite.aes_256_gcm, session.writeKeys(.handshake).?.suite);
}

test "dropping a level's keys leaves nothing behind" {
    var session: Session = .init(&[_]u8{0x08} ** 8);
    session.setHandshakeKeys(.aes_128_gcm, &.{
        .client = .from(&[_]u8{0xbb} ** 32),
        .server = .from(&[_]u8{0xcc} ** 32),
    });

    session.dropInitialKeys();
    try testing.expect(session.writeKeys(.initial) == null);
    try testing.expect(session.readKeys(.initial) == null);
    try testing.expectError(error.KeysNotReady, session.nextPacketNumber(.initial));

    session.dropHandshakeKeys();
    try testing.expect(session.writeKeys(.handshake) == null);

    session.clear();
    try testing.expect(session.application == null);
}
