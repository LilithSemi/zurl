//! RFC 4511, the LDAP protocol operations this package sends and reads.
//!
//! `ber.zig` owns the bytes and this file owns their meaning. A change to
//! RFC 4511 lands here and never there.
//!
//! **Four operations go out and four kinds of reply come back.**
//!
//! | out | in |
//! | --- | --- |
//! | `BindRequest`, `[APPLICATION 0]` | `BindResponse`, `[APPLICATION 1]` |
//! | `SearchRequest`, `[APPLICATION 3]` | `SearchResultEntry`, `[APPLICATION 4]` |
//! | `UnbindRequest`, `[APPLICATION 2]` | `SearchResultReference`, `[APPLICATION 19]` |
//! | `ExtendedRequest`, `[APPLICATION 23]` | `SearchResultDone`, `[APPLICATION 5]` |
//! | | `ExtendedResponse`, `[APPLICATION 24]` |
//!
//! Every request encoding below was read off curl 8.21.0 on the wire,
//! through a byte-logging relay to a real slapd 2.6.13. The tests carry
//! the measured bytes.
//!
//! **SASL is not here, and it is refused by name and not ignored.** RFC
//! 4511 section 4.2 gives `AuthenticationChoice` a `sasl [3]` arm, and
//! this build writes only the `simple [0]` arm. `Fetcher` is what refuses
//! a caller that asked for SASL, so a user who asked for a mechanism this
//! build does not have reads that rather than get a simple bind they did
//! not ask for. A credential sent by a weaker method than the user chose
//! is the same class of fault as running direct when the user asked for a
//! proxy.
//!
//! **No `Controls` are written and none are read.** RFC 4511 section 4.1.11
//! puts them in a `[0]` after the operation. A control this build wrote
//! would be one nobody asked for, and a control the server sends is
//! stepped over: `read` stops at the operation and never walks past it.
//!
//! This file allocates nothing and does no I/O.

const std = @import("std");

const ber = @import("ber.zig");
const filter = @import("filter.zig");
const target = @import("target.zig");

/// The LDAP version this speaks. RFC 4511 is version 3, and curl sends
/// `02 01 03`, measured.
pub const version: i64 = 3;

/// How many bytes one request may take.
///
/// The largest is a `SearchRequest`: a base DN of `target.max_dn_bytes`,
/// a filter whose BER is at most about half again its text, an attribute
/// list of `target.max_attribute_list_bytes`, and the headers around
/// them. 16 KiB is past that with room left.
pub const max_request_bytes: usize = 16 * 1024;

/// How many containers one request may open at once.
///
/// The deepest is a `SearchRequest` whose filter nests `filter.max_depth`
/// times and ends in a substring match: the message, the operation, the
/// filter arms, and the two a substring adds. 24 covers it, and it is
/// under `ber.max_depth`.
pub const writer_depth: usize = 24;

/// The writer every request in this package is built with.
pub const RequestWriter = ber.Writer(max_request_bytes, writer_depth);

/// The `[APPLICATION n]` tag numbers RFC 4511 section 4.1.1 gives the
/// operations this package knows.
pub const app_bind_request: u5 = 0;
pub const app_bind_response: u5 = 1;
pub const app_unbind_request: u5 = 2;
pub const app_search_request: u5 = 3;
pub const app_search_entry: u5 = 4;
pub const app_search_done: u5 = 5;
pub const app_search_reference: u5 = 19;
pub const app_extended_request: u5 = 23;
pub const app_extended_response: u5 = 24;

/// The `[0] simple` arm of `AuthenticationChoice`. RFC 4511 section 4.2.
pub const auth_simple: u5 = 0;

/// The `[0] requestName` and `[1] requestValue` of an `ExtendedRequest`.
pub const ext_request_name: u5 = 0;

/// The `[3] referral` a `LDAPResult` may carry. RFC 4511 section 4.1.9.
pub const result_referral: u5 = 3;

/// The object identifier of the StartTLS extended operation. RFC 4511
/// section 4.14.
pub const start_tls_oid = "1.3.6.1.4.1.1466.20037";

/// `derefAliases`, which this build always sends as `neverDerefAliases`.
///
/// Zero, which is what curl sends: every `SearchRequest` measured carried
/// `0a 01 00` in that field. Following an alias would send the search
/// somewhere the url did not name, and nothing above this asks for it.
pub const deref_never: i64 = 0;

/// The largest `messageID` RFC 4511 section 4.1.1.1 allows.
pub const max_message_id: i32 = 2147483647;

/// Every fault reading a message can report.
/// **The BER names come through unchanged**, so a short message reads
/// `error.Truncated` and one whose fields are in the wrong order reads
/// `error.UnexpectedTag`. A single name for both would send a reader of
/// the diagnostic to the wrong place.
pub const ReadError = ber.ReadError || error{
    /// The `protocolOp` carries a tag this build does not know.
    UnknownOperation,
    /// A `resultCode` is not a number RFC 4511 section 4.1.9 names.
    UnknownResultCode,
};

/// Which operation a reply carries.
pub const Kind = enum {
    bind_response,
    search_entry,
    search_reference,
    search_done,
    extended_response,
};

/// One `LDAPMessage` read off the wire.
pub const Message = struct {
    id: i32,
    /// The `protocolOp`, still as BER. `result`, `entry`, and
    /// `references` are what read it.
    op: ber.Element,
    kind: Kind,
};

/// The result codes RFC 4511 section 4.1.9 and Appendix A name.
///
/// **An exhaustive enum with a `parse` that returns null**, and never
/// `@enumFromInt` on a number a server chose. A code outside this set is
/// `error.UnknownResultCode`, which a caller reports with the number
/// itself, rather than a value with no name behind it.
pub const ResultCode = enum(i32) {
    success = 0,
    operations_error = 1,
    protocol_error = 2,
    time_limit_exceeded = 3,
    size_limit_exceeded = 4,
    compare_false = 5,
    compare_true = 6,
    auth_method_not_supported = 7,
    stronger_auth_required = 8,
    referral = 10,
    admin_limit_exceeded = 11,
    unavailable_critical_extension = 12,
    confidentiality_required = 13,
    sasl_bind_in_progress = 14,
    no_such_attribute = 16,
    undefined_attribute_type = 17,
    inappropriate_matching = 18,
    constraint_violation = 19,
    attribute_or_value_exists = 20,
    invalid_attribute_syntax = 21,
    no_such_object = 32,
    alias_problem = 33,
    invalid_dn_syntax = 34,
    alias_dereferencing_problem = 36,
    inappropriate_authentication = 48,
    invalid_credentials = 49,
    insufficient_access_rights = 50,
    busy = 51,
    unavailable = 52,
    unwilling_to_perform = 53,
    loop_detect = 54,
    naming_violation = 64,
    object_class_violation = 65,
    not_allowed_on_non_leaf = 66,
    not_allowed_on_rdn = 67,
    entry_already_exists = 68,
    object_class_mods_prohibited = 69,
    affects_multiple_dsas = 71,
    other = 80,

    /// The code `value` names, or null.
    ///
    /// `std.enums.fromInt`, which is what IronStyle asks for on an
    /// untrusted number.
    pub fn parse(value: i32) ?ResultCode {
        return std.enums.fromInt(ResultCode, value);
    }

    /// The sentence a user reads for this code.
    ///
    /// These are the words RFC 4511 Appendix A gives each name, and they
    /// are this build's own text and never the server's. The server's own
    /// `diagnosticMessage` reaches a user beside this, sanitised.
    pub fn describe(c: ResultCode) []const u8 {
        return switch (c) {
            .success => "success",
            .operations_error => "the server was in the wrong state for this operation",
            .protocol_error => "the server did not read this request as LDAP",
            .time_limit_exceeded => "the search passed the server's time limit",
            .size_limit_exceeded => "the search passed the server's size limit",
            .compare_false => "compare false",
            .compare_true => "compare true",
            .auth_method_not_supported => "the server does not offer this authentication method",
            .stronger_auth_required => "the server asks for stronger authentication",
            .referral => "the server holds no part of this subtree and named another server",
            .admin_limit_exceeded => "the search passed a limit the administrator set",
            .unavailable_critical_extension => "the server does not carry a control this request marked critical",
            .confidentiality_required => "the server asks for an encrypted connection",
            .sasl_bind_in_progress => "the server asked for another SASL step",
            .no_such_attribute => "the entry holds no such attribute",
            .undefined_attribute_type => "the schema names no such attribute",
            .inappropriate_matching => "the matching rule does not fit the attribute",
            .constraint_violation => "the value breaks a constraint the schema sets",
            .attribute_or_value_exists => "the attribute or the value is already there",
            .invalid_attribute_syntax => "the value does not fit the attribute's syntax",
            .no_such_object => "no such object",
            .alias_problem => "an alias does not name an object",
            .invalid_dn_syntax => "the distinguished name does not parse",
            .alias_dereferencing_problem => "the server could not follow an alias",
            .inappropriate_authentication => "this credential is the wrong kind for this entry",
            .invalid_credentials => "invalid credentials",
            .insufficient_access_rights => "this credential may not read that",
            .busy => "the server is too busy",
            .unavailable => "the server is shutting down or is not available",
            .unwilling_to_perform => "the server will not do this",
            .loop_detect => "the server found a loop while it followed a reference",
            .naming_violation => "the name breaks a naming rule",
            .object_class_violation => "the entry breaks an object class rule",
            .not_allowed_on_non_leaf => "this operation is only allowed on a leaf entry",
            .not_allowed_on_rdn => "this operation may not change the relative name",
            .entry_already_exists => "the entry is already there",
            .object_class_mods_prohibited => "the object class of an entry may not change",
            .affects_multiple_dsas => "the operation would reach more than one server",
            .other => "the server reported no more than a failure",
        };
    }
};

/// An `LDAPResult`, which a `BindResponse`, a `SearchResultDone`, and an
/// `ExtendedResponse` all start with. RFC 4511 section 4.1.9.
pub const Result = struct {
    code: ResultCode,
    /// The furthest name the server did recognise. Borrows the message.
    matched_dn: []const u8,
    /// The server's own words about the failure. Borrows the message, and
    /// it is text a server chose, so a caller sanitises it.
    diagnostic: []const u8,
};

/// One `SearchResultEntry`. RFC 4511 section 4.5.2.
pub const Entry = struct {
    /// The `objectName`. Borrows the message, and it is text a server
    /// chose.
    dn: []const u8,
    /// Walks the `PartialAttributeList`. Read it with `nextAttribute`.
    attributes: ber.Cursor,
};

/// One `PartialAttribute`. RFC 4511 section 4.1.7.
pub const Attribute = struct {
    /// The `AttributeDescription`. Borrows the message.
    description: []const u8,
    /// Walks the `SET OF value`. Read it with `nextValue`.
    values: ber.Cursor,
};

/// Reads one whole `LDAPMessage`.
///
/// `bytes` is the message from its `SEQUENCE` tag to its last octet, which
/// is what `Session` reads off the socket.
///
/// **The message id is read as an `i32` and not as an `i64`.** RFC 4511
/// section 4.1.1.1 bounds it at `maxInt`, which is 2147483647, so a
/// message id that does not fit is a message this build refuses rather
/// than truncates into one that would match a request it did not answer.
pub fn read(bytes: []const u8) ReadError!Message {
    var outer: ber.Cursor = .init(bytes);
    const envelope = try outer.expect(ber.sequence);
    var fields = try outer.enter(envelope);

    const id_element = try fields.expect(ber.integer);
    const id = try ber.integerValue(i32, id_element);

    const op = try fields.next();
    // Anything after the operation is a `Controls` this build does not
    // read. It is stepped over and never walked.

    if (op.tag.class != .application) return error.UnknownOperation;
    const kind: Kind = switch (op.tag.number) {
        app_bind_response => .bind_response,
        app_search_entry => .search_entry,
        app_search_done => .search_done,
        app_search_reference => .search_reference,
        app_extended_response => .extended_response,
        else => return error.UnknownOperation,
    };

    return .{ .id = id, .op = op, .kind = kind };
}

/// Reads the `LDAPResult` at the front of `op`.
///
/// A `BindResponse` and an `ExtendedResponse` carry more fields after it,
/// and this stops at the third. The extra fields are not read: a
/// `serverSaslCreds` belongs to a SASL bind this build does not do, and a
/// `responseValue` belongs to an extended operation whose only use here is
/// StartTLS, which carries none.
pub fn result(op: ber.Element) ReadError!Result {
    var fields = try intoOperation(op);

    const code_element = try fields.expect(ber.enumerated);
    const raw = try ber.integerValue(i32, code_element);
    const code = ResultCode.parse(raw) orelse return error.UnknownResultCode;

    const matched = try fields.expect(ber.octet_string);
    const diagnostic = try fields.expect(ber.octet_string);

    return .{
        .code = code,
        .matched_dn = matched.content,
        .diagnostic = diagnostic.content,
    };
}

/// The raw `resultCode` number of `op`, for a message whose code this
/// build has no name for.
///
/// A diagnostic that says "the server answered 91" is worth more than one
/// that says "a code with no name", so `Fetcher` reads this when `result`
/// reports `error.UnknownResultCode`.
pub fn resultCodeNumber(op: ber.Element) ReadError!i32 {
    var fields = try intoOperation(op);
    const code_element = try fields.expect(ber.enumerated);
    return ber.integerValue(i32, code_element);
}

/// A cursor over the fields of one protocol operation.
///
/// The operation sits inside the message envelope, so the cursor over the
/// envelope is at depth one and this is at depth two. Counting from zero
/// here would give a walk of a hostile message one free level, which is
/// exactly the kind of off-by-one a nesting bound must not have.
fn intoOperation(op: ber.Element) ReadError!ber.Cursor {
    const envelope: ber.Cursor = .{ .rest = "", .depth = 1 };
    return envelope.enter(op);
}

/// Reads a `SearchResultEntry`.
pub fn entry(op: ber.Element) ReadError!Entry {
    var fields = try intoOperation(op);

    const name = try fields.expect(ber.octet_string);
    const list = try fields.expect(ber.sequence);

    return .{ .dn = name.content, .attributes = try fields.enter(list) };
}

/// Reads the next `PartialAttribute`, or null when the list is spent.
pub fn nextAttribute(c: *ber.Cursor) ReadError!?Attribute {
    if (c.atEnd()) return null;
    const one = try c.expect(ber.sequence);
    var fields = try c.enter(one);

    const description = try fields.expect(ber.octet_string);
    const values = try fields.expect(ber.set);

    return .{ .description = description.content, .values = try fields.enter(values) };
}

/// Reads the next `AttributeValue`, or null when the set is spent.
pub fn nextValue(c: *ber.Cursor) ReadError!?[]const u8 {
    if (c.atEnd()) return null;
    const one = try c.expect(ber.octet_string);
    return one.content;
}

/// Reads the next uri of a `SearchResultReference`, or null when it is
/// spent. RFC 4511 section 4.5.3.
pub fn nextReference(c: *ber.Cursor) ReadError!?[]const u8 {
    if (c.atEnd()) return null;
    const one = try c.expect(ber.octet_string);
    return one.content;
}

/// A cursor over the uris of a `SearchResultReference`.
pub fn references(op: ber.Element) ReadError!ber.Cursor {
    return intoOperation(op);
}

/// Writes a `BindRequest` with simple authentication.
///
/// An empty `dn` and an empty `password` is the anonymous bind, and it is
/// what curl sends for a url with no credential, measured:
/// `30 0c 02 01 01 60 07 02 01 03 04 00 80 00`.
///
/// **The password goes on the wire as it is given.** BER counts the octets
/// in front of them, so no byte of a password can end the element early
/// and no escaping rule is needed. That is why a credential needs no gate
/// here and needs one in every line protocol in this repository.
pub fn writeBind(
    w: *RequestWriter,
    id: i32,
    dn: []const u8,
    password: []const u8,
) RequestWriter.Error!void {
    w.reset();
    try w.beginElement(ber.sequence);
    try w.writeInteger(ber.integer, id);
    try w.beginElement(.application(app_bind_request, true));
    try w.writeInteger(ber.integer, version);
    try w.writeElement(ber.octet_string, dn);
    try w.writeElement(.context(auth_simple, false), password);
    try w.endElement();
    try w.endElement();
}

/// Writes an `UnbindRequest`.
///
/// `[APPLICATION 2] NULL`, which is a primitive element of no content.
/// Measured: `30 05 02 01 03 42 00`.
pub fn writeUnbind(w: *RequestWriter, id: i32) RequestWriter.Error!void {
    w.reset();
    try w.beginElement(ber.sequence);
    try w.writeInteger(ber.integer, id);
    try w.writeElement(.application(app_unbind_request, false), "");
    try w.endElement();
}

/// Writes the StartTLS `ExtendedRequest`. RFC 4511 section 4.14.
pub fn writeStartTls(w: *RequestWriter, id: i32) RequestWriter.Error!void {
    w.reset();
    try w.beginElement(ber.sequence);
    try w.writeInteger(ber.integer, id);
    try w.beginElement(.application(app_extended_request, true));
    try w.writeElement(.context(ext_request_name, false), start_tls_oid);
    try w.endElement();
    try w.endElement();
}

/// Writes a `SearchRequest` for `t`.
///
/// The field order and every constant here was read off curl on the wire:
///
/// ```
/// 63 33 04 0f "dc=zurl,dc=test"   baseObject
///       0a 01 00                  scope
///       0a 01 00                  derefAliases, neverDerefAliases
///       02 01 00                  sizeLimit
///       02 01 00                  timeLimit
///       01 01 00                  typesOnly, false
///       87 0b "objectClass"       filter
///       30 04 04 02 "dc"          attributes
/// ```
///
/// `size_limit` and `time_limit` are zero for "the server's own limit",
/// which is what curl sends. This build passes them through so a caller
/// with a bound of its own can name one.
pub fn writeSearch(
    w: *RequestWriter,
    id: i32,
    t: *const target.Target,
    size_limit: i64,
    time_limit: i64,
) (filter.ParseError || RequestWriter.Error)!void {
    w.reset();
    try w.beginElement(ber.sequence);
    try w.writeInteger(ber.integer, id);
    try w.beginElement(.application(app_search_request, true));
    try w.writeElement(ber.octet_string, t.dn);
    try w.writeInteger(ber.enumerated, @intFromEnum(t.scope));
    try w.writeInteger(ber.enumerated, deref_never);
    try w.writeInteger(ber.integer, size_limit);
    try w.writeInteger(ber.integer, time_limit);
    // `typesOnly` is false: this build reads the values and not only the
    // names, which is what curl asks for.
    try w.writeBoolean(ber.boolean, false);
    try filter.write(w, t.filter_text);
    try w.beginElement(ber.sequence);
    for (t.attributeList()) |attribute| {
        try w.writeElement(ber.octet_string, attribute);
    }
    try w.endElement();
    try w.endElement();
    try w.endElement();
}

const testing = std.testing;

test "the anonymous BindRequest matches the bytes curl sent" {
    var w: RequestWriter = .init();
    try writeBind(&w, 1, "", "");
    try testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 },
        w.written(),
    );
}

test "the simple BindRequest matches the bytes curl sent for -u" {
    // Measured: `-u 'cn=admin,dc=zurl,dc=test:secret'` reached the wire
    // as `30 2a 02 01 01 60 25 02 01 03 04 18 <dn> 80 06 secret`.
    var w: RequestWriter = .init();
    try writeBind(&w, 1, "cn=admin,dc=zurl,dc=test", "secret");

    const want = [_]u8{ 0x30, 0x2a, 0x02, 0x01, 0x01, 0x60, 0x25, 0x02, 0x01, 0x03, 0x04, 0x18 } ++
        "cn=admin,dc=zurl,dc=test".* ++ [_]u8{ 0x80, 0x06 } ++ "secret".*;
    try testing.expectEqualSlices(u8, &want, w.written());
}

test "a password of any bytes at all reaches the wire whole" {
    // **The reason no credential gate is needed here.** BER counts the
    // octets in front of them, so a CR, an LF, and a NUL are data. Every
    // line protocol in this repository has to refuse those three; this one
    // does not, and this test is why.
    var w: RequestWriter = .init();
    var password: [256]u8 = undefined;
    for (&password, 0..) |*b, i| b.* = @truncate(i);
    try writeBind(&w, 1, "cn=a", &password);

    // `read` reads replies, so the request is walked with the BER cursor
    // itself.
    var outer: ber.Cursor = .init(w.written());
    const envelope = try outer.expect(ber.sequence);
    var top = try outer.enter(envelope);
    _ = try top.expect(ber.integer);
    const request = try top.expect(.application(app_bind_request, true));

    var fields = try top.enter(request);
    _ = try fields.expect(ber.integer);
    _ = try fields.expect(ber.octet_string);
    const simple = try fields.expect(.context(auth_simple, false));
    try testing.expectEqualSlices(u8, &password, simple.content);
}

test "the UnbindRequest matches the bytes curl sent" {
    var w: RequestWriter = .init();
    try writeUnbind(&w, 3);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00 },
        w.written(),
    );
}

test "the StartTLS ExtendedRequest names the OID RFC 4511 gives it" {
    var w: RequestWriter = .init();
    try writeStartTls(&w, 1);
    const want = [_]u8{ 0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16 } ++
        "1.3.6.1.4.1.1466.20037".*;
    try testing.expectEqualSlices(u8, &want, w.written());
}

test "the SearchRequest matches the bytes curl sent" {
    // Measured: `ldap://h/dc=zurl,dc=test?dc?base?(objectClass=*)` reached
    // the wire as the bytes below.
    var storage: target.Storage = undefined;
    var t: target.Target = .empty;
    @memcpy(storage.dn[0..15], "dc=zurl,dc=test");
    t.dn = storage.dn[0..15];
    @memcpy(storage.attributes[0..2], "dc");
    t.attributes[0] = storage.attributes[0..2];
    t.attribute_count = 1;
    t.filter_text = "(objectClass=*)";

    var w: RequestWriter = .init();
    try writeSearch(&w, 2, &t, 0, 0);

    const want = [_]u8{ 0x30, 0x38, 0x02, 0x01, 0x02, 0x63, 0x33, 0x04, 0x0f } ++
        "dc=zurl,dc=test".* ++
        [_]u8{ 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00 } ++
        [_]u8{ 0x87, 0x0b } ++ "objectClass".* ++
        [_]u8{ 0x30, 0x04, 0x04, 0x02, 'd', 'c' };
    try testing.expectEqualSlices(u8, &want, w.written());
}

test "a search with no attributes writes an empty SEQUENCE" {
    // Measured: `ldap://h/dc=zurl,dc=test` reached the wire ending in
    // `30 00`.
    var t: target.Target = .empty;
    t.dn = "dc=zurl,dc=test";
    var w: RequestWriter = .init();
    try writeSearch(&w, 2, &t, 0, 0);
    const out = w.written();
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x00 }, out[out.len - 2 ..]);
}

test "every scope reaches the number RFC 4511 gives it" {
    const Case = struct { scope: target.Scope, octet: u8 };
    const cases = [_]Case{
        .{ .scope = .base, .octet = 0 },
        .{ .scope = .one, .octet = 1 },
        .{ .scope = .sub, .octet = 2 },
    };
    for (cases) |case| {
        var t: target.Target = .empty;
        t.dn = "dc=a";
        t.scope = case.scope;
        var w: RequestWriter = .init();
        try writeSearch(&w, 2, &t, 0, 0);
        // `0a 01 <scope>` follows the base object.
        const at = std.mem.indexOf(u8, w.written(), &.{ 0x0a, 0x01, case.octet }).?;
        try testing.expect(at != 0);
    }
}

test "the BindResponse curl read comes back as success" {
    // Measured off slapd: `30 0c 02 01 01 61 07 0a 01 00 04 00 04 00`.
    const bytes = [_]u8{
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07,
        0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    };
    const m = try read(&bytes);
    try testing.expectEqual(@as(i32, 1), m.id);
    try testing.expectEqual(Kind.bind_response, m.kind);

    const r = try result(m.op);
    try testing.expectEqual(ResultCode.success, r.code);
    try testing.expectEqualStrings("", r.matched_dn);
    try testing.expectEqualStrings("", r.diagnostic);
}

test "the SearchResultEntry curl read comes back whole" {
    // Measured off slapd:
    //
    //     30 26 02 01 02 64 21 04 0f "dc=zurl,dc=test"
    //           30 0e 30 0c 04 02 "dc" 31 06 04 04 "zurl"
    const bytes = [_]u8{ 0x30, 0x26, 0x02, 0x01, 0x02, 0x64, 0x21, 0x04, 0x0f } ++
        "dc=zurl,dc=test".* ++
        [_]u8{ 0x30, 0x0e, 0x30, 0x0c, 0x04, 0x02, 'd', 'c', 0x31, 0x06, 0x04, 0x04 } ++ "zurl".*;

    const m = try read(&bytes);
    try testing.expectEqual(@as(i32, 2), m.id);
    try testing.expectEqual(Kind.search_entry, m.kind);

    var e = try entry(m.op);
    try testing.expectEqualStrings("dc=zurl,dc=test", e.dn);

    const a = (try nextAttribute(&e.attributes)).?;
    try testing.expectEqualStrings("dc", a.description);
    var values = a.values;
    try testing.expectEqualStrings("zurl", (try nextValue(&values)).?);
    try testing.expectEqual(@as(?[]const u8, null), try nextValue(&values));
    try testing.expectEqual(@as(?Attribute, null), try nextAttribute(&e.attributes));
}

test "an attribute of two values reads both, in the order the server sent" {
    // `30 2c 04 04 "mail" 31 24 04 0e "ross@zurl.test" 04 12 "ross.alt@zurl.test"`,
    // read off slapd.
    const attribute = [_]u8{ 0x30, 0x2c, 0x04, 0x04 } ++ "mail".* ++
        [_]u8{ 0x31, 0x24, 0x04, 0x0e } ++ "ross@zurl.test".* ++
        [_]u8{ 0x04, 0x12 } ++ "ross.alt@zurl.test".*;

    var c: ber.Cursor = .init(&attribute);
    const a = (try nextAttribute(&c)).?;
    try testing.expectEqualStrings("mail", a.description);
    var values = a.values;
    try testing.expectEqualStrings("ross@zurl.test", (try nextValue(&values)).?);
    try testing.expectEqualStrings("ross.alt@zurl.test", (try nextValue(&values)).?);
    try testing.expectEqual(@as(?[]const u8, null), try nextValue(&values));
}

test "the SearchResultReference slapd sent comes back as its uri" {
    // Measured: `30 41 02 01 02 73 3c 04 3a "ldap://other.example.com/..."`.
    const uri = "ldap://other.example.com/ou=elsewhere,dc=zurl,dc=test??sub";
    const bytes = [_]u8{ 0x30, 0x41, 0x02, 0x01, 0x02, 0x73, 0x3c, 0x04, 0x3a } ++ uri.*;

    const m = try read(&bytes);
    try testing.expectEqual(Kind.search_reference, m.kind);
    var c = try references(m.op);
    try testing.expectEqualStrings(uri, (try nextReference(&c)).?);
    try testing.expectEqual(@as(?[]const u8, null), try nextReference(&c));
}

test "the SearchResultDone slapd sent comes back as success" {
    const bytes = [_]u8{
        0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07,
        0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    };
    const m = try read(&bytes);
    try testing.expectEqual(Kind.search_done, m.kind);
    try testing.expectEqual(ResultCode.success, (try result(m.op)).code);
}

test "a failing result carries the server's own matched name and words" {
    // `noSuchObject` is 32, and slapd answers a missing base with it.
    const bytes = [_]u8{ 0x30, 0x1d, 0x02, 0x01, 0x02, 0x65, 0x18, 0x0a, 0x01, 0x20, 0x04, 0x0f } ++
        "dc=zurl,dc=test".* ++ [_]u8{ 0x04, 0x02, 'n', 'o' };
    const m = try read(&bytes);
    const r = try result(m.op);
    try testing.expectEqual(ResultCode.no_such_object, r.code);
    try testing.expectEqualStrings("dc=zurl,dc=test", r.matched_dn);
    try testing.expectEqualStrings("no", r.diagnostic);
}

test "a result code this build has no name for is refused and its number kept" {
    // 91 is in no RFC 4511 table. A build that read it with
    // `@enumFromInt` would carry a value with no name behind it, which is
    // undefined behaviour for an invalid tag.
    const bytes = [_]u8{
        0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07,
        0x0a, 0x01, 0x5b, 0x04, 0x00, 0x04, 0x00,
    };
    const m = try read(&bytes);
    try testing.expectError(error.UnknownResultCode, result(m.op));
    try testing.expectEqual(@as(i32, 91), try resultCodeNumber(m.op));
    try testing.expectEqual(@as(?ResultCode, null), ResultCode.parse(91));
    try testing.expectEqual(@as(?ResultCode, null), ResultCode.parse(-1));
    try testing.expectEqual(ResultCode.invalid_credentials, ResultCode.parse(49).?);
}

test "an operation this build does not know is refused by name" {
    // `[APPLICATION 7]` is a ModifyResponse, which nothing here sends and
    // so nothing here should read.
    const bytes = [_]u8{ 0x30, 0x05, 0x02, 0x01, 0x01, 0x67, 0x00 };
    try testing.expectError(error.UnknownOperation, read(&bytes));
    // A universal tag where an operation belongs is refused too.
    try testing.expectError(
        error.UnknownOperation,
        read(&.{ 0x30, 0x05, 0x02, 0x01, 0x01, 0x04, 0x00 }),
    );
}

test "a message that is not a SEQUENCE of an id and an operation is refused" {
    // **The BER name comes through**, so a reader of the diagnostic knows
    // whether the peer sent too few bytes or the wrong shape.
    try testing.expectError(error.UnexpectedTag, read(&.{ 0x04, 0x02, 'a', 'b' }));
    try testing.expectError(error.Truncated, read(&.{ 0x30, 0x00 }));
    try testing.expectError(error.Truncated, read(&.{ 0x30, 0x03, 0x02, 0x01, 0x01 }));
    // An id that is not an integer.
    try testing.expectError(
        error.UnexpectedTag,
        read(&.{ 0x30, 0x05, 0x04, 0x01, 0x01, 0x42, 0x00 }),
    );
}

test "a message id that does not fit RFC 4511's bound is refused" {
    // Nine octets of real value. Truncating it would make the id match a
    // request this build never sent.
    const bytes = [_]u8{
        0x30, 0x0d, 0x02, 0x09, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x42, 0x00,
    };
    try testing.expectError(error.ValueOutOfRange, read(&bytes));
}

test "a truncated entry is refused rather than read as a short one" {
    // The `SEQUENCE` says it holds 0x21 bytes and the buffer holds fewer.
    const bytes = [_]u8{ 0x30, 0x26, 0x02, 0x01, 0x02, 0x64, 0x21, 0x04, 0x0f, 'd', 'c' };
    try testing.expectError(error.Truncated, read(&bytes));
}

test "an entry whose attribute list is not a SEQUENCE is refused" {
    const bytes = [_]u8{ 0x30, 0x0a, 0x02, 0x01, 0x02, 0x64, 0x05, 0x04, 0x01, 'a', 0x04, 0x00 };
    const m = try read(&bytes);
    try testing.expectError(error.UnexpectedTag, entry(m.op));
}

test "every result code has a sentence and none of them is empty" {
    inline for (@typeInfo(ResultCode).@"enum".fields) |field| {
        const code: ResultCode = @field(ResultCode, field.name);
        try testing.expect(code.describe().len != 0);
    }
}

test "a request past the writer's capacity is refused and never cut short" {
    var t: target.Target = .empty;
    // A base DN of the whole bound, plus a filter, plus the headers, is
    // still inside `max_request_bytes`. The refusal is the writer's own.
    var dn: [target.max_dn_bytes]u8 = undefined;
    @memset(&dn, 'a');
    t.dn = &dn;
    var w: RequestWriter = .init();
    try writeSearch(&w, 1, &t, 0, 0);
    try testing.expect(w.balanced());
    try testing.expect(w.written().len < max_request_bytes);
}

test "a filter that does not parse stops the request before any byte goes out" {
    var t: target.Target = .empty;
    t.dn = "dc=a";
    t.filter_text = "(cn=a";
    var w: RequestWriter = .init();
    try testing.expectError(error.Truncated, writeSearch(&w, 1, &t, 0, 0));
}
