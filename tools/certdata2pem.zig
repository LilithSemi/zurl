//! Generates a PEM certificate authority bundle from NSS's `certdata.txt`.
//!
//! NSS ships its root store as a PKCS#11 attribute dump. A `CKO_CERTIFICATE`
//! row carries a certificate's DER bytes, encoded as `MULTILINE_OCTAL`. A
//! `CKO_NSS_TRUST` row carries the trust posture for the same certificate,
//! matched to it by label and serial number, the way NSS itself links them.
//! This tool emits a certificate only when its trust row marks
//! `CKA_TRUST_SERVER_AUTH` as `CKT_NSS_TRUSTED_DELEGATOR`.
//!
//! **Two refusals guard the link between the rows.** A second row under one
//! label and serial is refused, because the pair is the whole join and a
//! duplicate means it no longer decides anything. And a trust row that
//! carries `CKA_CERT_SHA1_HASH` is checked against the SHA-1 of the
//! certificate it is about to vouch for, so a drifted or corrupted
//! `CKA_VALUE` cannot ride under a trust decision that was made about other
//! bytes.
//!
//! `certdata.txt` is input from a build dependency, so malformed content is
//! a runtime fault here, not a programmer error. Every read in this file
//! checks its bound first, so a truncated or hand-edited file cannot make
//! this tool panic or read out of bounds.
//!
//! Usage: `certdata2pem <certdata.txt> <out.pem>`

const std = @import("std");
const Io = std.Io;

/// The trust value that marks a certificate as trusted for server auth.
const trusted_delegator = "CKT_NSS_TRUSTED_DELEGATOR";

/// The largest `certdata.txt` this tool reads.
///
/// The NSS root store is about 1.4 MB today. 16 MiB leaves more than ten
/// times that room, and still refuses a build dependency that names
/// something else.
const max_input_bytes: usize = 16 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 3) {
        printLine(io, "usage: {s} <certdata.txt> <out.pem>\n", .{if (args.len > 0) args[0] else "certdata2pem"});
        return error.MissingArguments;
    }
    const in_path = args[1];
    const out_path = args[2];
    const cwd: Io.Dir = .cwd();

    const text = try cwd.readFileAlloc(io, in_path, arena, .limited(max_input_bytes));

    var out: std.ArrayList(u8) = .empty;
    const emitted = try generate(arena, text, &out);

    const out_file = try cwd.createFile(io, out_path, .{});
    defer out_file.close(io);
    try out_file.writeStreamingAll(io, out.items);

    printLine(io, "certdata2pem: emitted {d} trusted server-auth roots\n", .{emitted});
}

/// Prints one line to stdout, never to stderr.
///
/// The build runner surfaces anything a run step writes to stderr as
/// "failed command:" noise, even on success. Stdout stays quiet unless this
/// tool is run directly.
fn printLine(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    Io.File.stdout().writeStreamingAll(io, msg) catch {};
}

/// One PKCS#11 object being read: a certificate, a trust row, or something
/// this tool does not use.
const Object = struct {
    class: []const u8 = "",
    label: []const u8 = "",
    serial: []const u8 = "",
    value: []const u8 = "",
    sha1: []const u8 = "",
    trust_server_auth: []const u8 = "",
};

/// Every fault `generate` can report beyond the allocator's own.
pub const GenerateError = error{
    /// A second row under one label and serial. The pair is the whole join
    /// between a certificate and its trust decision, so a duplicate means
    /// the join no longer decides anything and the run stops.
    DuplicateRow,
    /// A trust row carries `CKA_CERT_SHA1_HASH` and the hash of the
    /// certificate it matched disagrees with it.
    TrustHashMismatch,
    OutOfMemory,
};

/// Parses `text` as `certdata.txt`, and appends one PEM block to `out` for
/// every certificate whose trust row marks `CKA_TRUST_SERVER_AUTH` as
/// `CKT_NSS_TRUSTED_DELEGATOR`. Returns how many certificates it appended.
///
/// `allocator` backs both the parse's own bookkeeping and every byte this
/// function appends to `out`. Pass an arena, or another allocator whose
/// memory the caller reclaims in one step: this function frees nothing on
/// its own.
pub fn generate(allocator: std.mem.Allocator, text: []const u8, out: *std.ArrayList(u8)) GenerateError!usize {
    // Keyed by label and serial number, the same pair NSS uses to link a
    // certificate to its trust row.
    var certs: std.StringHashMap([]const u8) = .init(allocator);
    var trusted_keys: std.StringHashMap([]const u8) = .init(allocator);

    var lines = std.mem.splitScalar(u8, text, '\n');
    var current: Object = .{};
    var have_object = false;
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, " \t\r");
        if (line.len == 0 or std.mem.startsWith(u8, line, "#")) continue;
        if (std.mem.eql(u8, line, "BEGINDATA")) continue;

        // A MULTILINE_OCTAL block spans several lines: the header checked
        // here, then the octal digits, then an `END` line. Every such block
        // must be consumed to keep the line iterator in step with the file,
        // even for a field this tool does not keep.
        if (std.mem.indexOf(u8, line, "MULTILINE_OCTAL") != null) {
            const field = firstToken(line);
            const bytes = try readMultilineOctal(allocator, &lines);
            if (std.mem.eql(u8, field, "CKA_VALUE")) {
                current.value = bytes;
            } else if (std.mem.eql(u8, field, "CKA_SERIAL_NUMBER")) {
                current.serial = bytes;
            } else if (std.mem.eql(u8, field, "CKA_CERT_SHA1_HASH")) {
                current.sha1 = bytes;
            }
            continue;
        }

        if (std.mem.startsWith(u8, line, "CKA_CLASS ")) {
            if (have_object) try commit(allocator, &certs, &trusted_keys, current);
            current = .{};
            have_object = true;
            current.class = thirdToken(line);
            continue;
        }
        if (std.mem.startsWith(u8, line, "CKA_LABEL UTF8 ")) {
            current.label = unquote(line["CKA_LABEL UTF8 ".len..]);
            continue;
        }
        if (std.mem.startsWith(u8, line, "CKA_TRUST_SERVER_AUTH CK_TRUST ")) {
            current.trust_server_auth = thirdToken(line);
            continue;
        }
    }
    if (have_object) try commit(allocator, &certs, &trusted_keys, current);

    var emitted: usize = 0;
    var it = certs.iterator();
    while (it.next()) |entry| {
        const hash = trusted_keys.get(entry.key_ptr.*) orelse continue;
        // The trust decision was made about one set of bytes, and the
        // certificate this run emits has to be those bytes. NSS carries the
        // SHA-1 of the certificate in its trust row for exactly this check.
        if (hash.len != 0) {
            var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
            std.crypto.hash.Sha1.hash(entry.value_ptr.*, &digest, .{});
            if (!std.mem.eql(u8, &digest, hash)) return error.TrustHashMismatch;
        }
        try writePem(allocator, out, entry.key_ptr.*, entry.value_ptr.*);
        emitted += 1;
    }
    return emitted;
}

/// Records `object` once its fields are complete: a certificate goes into
/// `certs`, and a trust row that marks server auth as
/// `CKT_NSS_TRUSTED_DELEGATOR` puts its key and its own `CKA_CERT_SHA1_HASH`
/// into `trusted_keys`. Every other object class is dropped, because this
/// tool has no use for it.
///
/// A second row under one key is a refusal and not an overwrite. The pair
/// is the whole join between a certificate and its trust decision, and a
/// duplicate means the file carries two different answers for one
/// certificate, which no run can pick between.
fn commit(
    allocator: std.mem.Allocator,
    certs: *std.StringHashMap([]const u8),
    trusted_keys: *std.StringHashMap([]const u8),
    object: Object,
) GenerateError!void {
    // A row with no label cannot be matched to anything, so it carries
    // nothing this tool can use.
    if (object.label.len == 0) return;
    const key = try std.fmt.allocPrint(allocator, "{s}\x00{x}", .{ object.label, object.serial });
    if (std.mem.eql(u8, object.class, "CKO_CERTIFICATE") and object.value.len > 0) {
        if (certs.contains(key)) return error.DuplicateRow;
        try certs.put(key, object.value);
    } else if (std.mem.eql(u8, object.class, "CKO_NSS_TRUST") and
        std.mem.eql(u8, object.trust_server_auth, trusted_delegator))
    {
        if (trusted_keys.contains(key)) return error.DuplicateRow;
        try trusted_keys.put(key, object.sha1);
    }
}

/// Returns the text of `line` up to the first space, or the whole line when
/// it holds none.
fn firstToken(line: []const u8) []const u8 {
    const space = std.mem.indexOfScalar(u8, line, ' ') orelse return line;
    return line[0..space];
}

/// Returns the third space-separated field of `line`, or an empty slice
/// when `line` holds fewer than three.
fn thirdToken(line: []const u8) []const u8 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next();
    _ = it.next();
    return it.next() orelse "";
}

/// Strips one leading and one trailing double quote from `s`, when both are
/// present.
fn unquote(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') return s[1 .. s.len - 1];
    return s;
}

/// Reads the body of a `MULTILINE_OCTAL` block: a run of `\nnn` escapes,
/// terminated by a line that reads exactly `END`. Returns the decoded
/// bytes.
///
/// A line that ends partway through an escape, or holds a digit outside
/// `0`-`7`, decodes that escape as zero instead of reading past the line.
/// `certdata.txt` is a build dependency, not a trusted local file, so this
/// stays a lenient decode rather than a rejected file: the worst a bad
/// escape can do is put a wrong byte into one certificate, which the
/// certificate parser downstream then rejects on its own.
fn readMultilineOctal(allocator: std.mem.Allocator, lines: *std.mem.SplitIterator(u8, .scalar)) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, " \t\r");
        if (std.mem.eql(u8, line, "END")) break;
        var i: usize = 0;
        while (i < line.len) {
            if (line[i] == '\\' and i + 3 < line.len) {
                const byte = (octalDigit(line[i + 1]) << 6) |
                    (octalDigit(line[i + 2]) << 3) |
                    octalDigit(line[i + 3]);
                try out.append(allocator, byte);
                i += 4;
            } else {
                i += 1;
            }
        }
    }
    return out.toOwnedSlice(allocator);
}

/// Returns the value of one octal digit, or zero for a byte outside
/// `0`-`7`.
fn octalDigit(c: u8) u8 {
    return if (c >= '0' and c <= '7') c - '0' else 0;
}

/// Appends one PEM block for `der` to `out`, labelled with a comment line
/// so the generated file stays readable.
fn writePem(allocator: std.mem.Allocator, out: *std.ArrayList(u8), label: []const u8, der: []const u8) !void {
    // `label` carries the `\x00` and hex serial that `commit` appended to
    // make it a unique map key. Only the text before that separator is the
    // certificate's own name.
    const name = if (std.mem.indexOfScalar(u8, label, 0)) |sep| label[0..sep] else label;
    try out.appendSlice(allocator, "# ");
    try out.appendSlice(allocator, name);
    try out.appendSlice(allocator, "\n-----BEGIN CERTIFICATE-----\n");

    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(der.len));
    _ = encoder.encode(encoded, der);

    var i: usize = 0;
    while (i < encoded.len) : (i += 64) {
        const end = @min(i + 64, encoded.len);
        try out.appendSlice(allocator, encoded[i..end]);
        try out.append(allocator, '\n');
    }
    try out.appendSlice(allocator, "-----END CERTIFICATE-----\n");
}

const testing = std.testing;

test "readMultilineOctal decodes three digit octal escapes, including high bytes" {
    var lines = std.mem.splitScalar(u8, "\\000\\001\\176\\377\nEND", '\n');
    const bytes = try readMultilineOctal(testing.allocator, &lines);
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x7e, 0xff }, bytes);
}

test "readMultilineOctal stops at the END line and leaves the iterator past it" {
    var lines = std.mem.splitScalar(u8, "\\101\nEND\nCKA_NEXT_FIELD", '\n');
    const bytes = try readMultilineOctal(testing.allocator, &lines);
    defer testing.allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{'A'}, bytes);
    try testing.expectEqualStrings("CKA_NEXT_FIELD", lines.next().?);
}

/// A `certdata.txt` fragment with three certificates:
///
/// - "Trusted CA": a trust row that marks it `CKT_NSS_TRUSTED_DELEGATOR`
///   for server auth. Its DER bytes are `ABC`.
/// - "Untrusted CA": a trust row for the same label and serial, but marked
///   `CKT_NSS_MUST_VERIFY_TRUST` instead. Its DER bytes are `DEF`.
/// - "Orphan CA": no trust row at all. Its DER bytes are `GHI`.
const test_certdata =
    \\CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
    \\CKA_LABEL UTF8 "Trusted CA"
    \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
    \\\001
    \\END
    \\CKA_VALUE MULTILINE_OCTAL
    \\\101\102\103
    \\END
    \\
    \\CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
    \\CKA_LABEL UTF8 "Trusted CA"
    \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
    \\\001
    \\END
    \\CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
    \\
    \\CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
    \\CKA_LABEL UTF8 "Untrusted CA"
    \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
    \\\002
    \\END
    \\CKA_VALUE MULTILINE_OCTAL
    \\\104\105\106
    \\END
    \\
    \\CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
    \\CKA_LABEL UTF8 "Untrusted CA"
    \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
    \\\002
    \\END
    \\CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_MUST_VERIFY_TRUST
    \\
    \\CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
    \\CKA_LABEL UTF8 "Orphan CA"
    \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
    \\\003
    \\END
    \\CKA_VALUE MULTILINE_OCTAL
    \\\107\110\111
    \\END
    \\
;

test "a certificate whose trust row is a delegator is emitted, and only it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var out: std.ArrayList(u8) = .empty;

    const emitted = try generate(arena_state.allocator(), test_certdata, &out);

    try testing.expectEqual(@as(usize, 1), emitted);
    try testing.expect(std.mem.indexOf(u8, out.items, "QUJD") != null); // base64("ABC")
}

test "a certificate whose trust row is not a delegator is left out" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var out: std.ArrayList(u8) = .empty;

    _ = try generate(arena_state.allocator(), test_certdata, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "REVG") == null); // base64("DEF")
}

test "a certificate with no matching trust row is left out" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var out: std.ArrayList(u8) = .empty;

    _ = try generate(arena_state.allocator(), test_certdata, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "R0hJ") == null); // base64("GHI")
}

test "the emitted PEM block is labelled and framed with markers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var out: std.ArrayList(u8) = .empty;

    _ = try generate(arena_state.allocator(), test_certdata, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "# Trusted CA") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "-----BEGIN CERTIFICATE-----") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "-----END CERTIFICATE-----") != null);
}

test "an empty input emits nothing and does not fail" {
    var out: std.ArrayList(u8) = .empty;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const emitted = try generate(arena_state.allocator(), "", &out);
    try testing.expectEqual(@as(usize, 0), emitted);
    try testing.expectEqual(@as(usize, 0), out.items.len);
}

/// Formats `bytes` as the body of a `MULTILINE_OCTAL` block, three octets
/// of text per octet of data, one source line per twelve bytes, the way
/// NSS writes one.
fn formatMultilineOctal(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (bytes, 0..) |byte, i| {
        if (i > 0 and i % 12 == 0) try out.append(allocator, '\n');
        var one: [4]u8 = undefined;
        const printed = try std.fmt.bufPrint(&one, "\\{o:0>3}", .{byte});
        try out.appendSlice(allocator, printed);
    }
    try out.append(allocator, '\n');
    return out.items;
}

/// One trusted certificate with a trust row that carries the SHA-1 hash
/// NSS writes beside its trust decision.
fn certdataWithHash(allocator: std.mem.Allocator, cert_der: []const u8, hash: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
        \\CKA_LABEL UTF8 "Hashed CA"
        \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
        \\{s}
        \\END
        \\CKA_VALUE MULTILINE_OCTAL
        \\{s}
        \\END
        \\
        \\CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
        \\CKA_LABEL UTF8 "Hashed CA"
        \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
        \\{s}
        \\END
        \\CKA_CERT_SHA1_HASH MULTILINE_OCTAL
        \\{s}
        \\END
        \\CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
        \\
    , .{
        try formatMultilineOctal(allocator, &.{1}),
        try formatMultilineOctal(allocator, cert_der),
        try formatMultilineOctal(allocator, &.{1}),
        try formatMultilineOctal(allocator, hash),
    });
}

test "a trust row whose hash matches the certificate emits it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const cert_der = "ABC";
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(cert_der, &digest, .{});
    const text = try certdataWithHash(allocator, cert_der, &digest);

    var out: std.ArrayList(u8) = .empty;
    const emitted = try generate(allocator, text, &out);
    try testing.expectEqual(@as(usize, 1), emitted);
}

test "a trust row whose hash disagrees with the certificate is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    // The trust decision was made about `ABC`, and the row the join picks
    // carries `DEF`.
    var wrong: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash("DEF", &wrong, .{});
    const text = try certdataWithHash(allocator, "ABC", &wrong);

    var out: std.ArrayList(u8) = .empty;
    try testing.expectError(error.TrustHashMismatch, generate(allocator, text, &out));
}

test "a second certificate row under one label and serial is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const text =
        \\CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
        \\CKA_LABEL UTF8 "Twice"
        \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
        \\\001
        \\END
        \\CKA_VALUE MULTILINE_OCTAL
        \\\101
        \\END
        \\
        \\CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
        \\CKA_LABEL UTF8 "Twice"
        \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
        \\\001
        \\END
        \\CKA_VALUE MULTILINE_OCTAL
        \\\102
        \\END
        \\
    ;

    var out: std.ArrayList(u8) = .empty;
    try testing.expectError(error.DuplicateRow, generate(allocator, text, &out));
}

test "a second trust row under one label and serial is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const text =
        \\CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
        \\CKA_LABEL UTF8 "Twice"
        \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
        \\\001
        \\END
        \\CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
        \\
        \\CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
        \\CKA_LABEL UTF8 "Twice"
        \\CKA_SERIAL_NUMBER MULTILINE_OCTAL
        \\\001
        \\END
        \\CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
        \\
    ;

    var out: std.ArrayList(u8) = .empty;
    try testing.expectError(error.DuplicateRow, generate(allocator, text, &out));
}
