//! RFC 4516, the `ldap://` url, read into the four things a search needs.
//!
//! ```
//! ldap://host:port/dn?attributes?scope?filter?extensions
//! ```
//!
//! Every part after the host is optional, and each one that is left out
//! takes a default. The defaults below were read off curl 8.21.0 on the
//! wire, through a byte-logging relay to a real slapd 2.6.13, and not out
//! of the RFC alone:
//!
//! | part | left out |
//! | --- | --- |
//! | dn | the empty DN, which is the root DSE |
//! | attributes | none named, so the server sends every user attribute |
//! | scope | `base` |
//! | filter | `(objectclass=*)`, in lower case |
//!
//! **The lower case of the default filter is measured and not a
//! guess.** curl sends `87 0b "objectclass"` for a url that names no
//! filter and `87 0b "objectClass"` for one that spells it that way, so
//! the default is libldap's own text and the url's text is passed
//! through.
//!
//! **Every part is percent-decoded, and the decode happens before
//! anything is judged.** RFC 4516 section 2 says a `?` inside a part must
//! be written `%3F`, so the split on `?` runs on the raw text and the
//! decode runs on each piece after it. A build that decoded first would
//! read a `%3F` in a filter as a separator and cut the url somewhere the
//! user did not.
//!
//! This file allocates nothing and does no I/O. It writes into storage the
//! caller owns.

const std = @import("std");
const zurl_core = @import("zurl-core");

const filter = @import("filter.zig");

/// How many bytes of base DN this reads.
///
/// 4096, the bound `zurl-scp` puts on a remote path and for the same
/// reason: it is far past any name a directory holds, and the text comes
/// out of a url so it needs a number.
pub const max_dn_bytes: usize = 4096;

/// How many attributes one url may name.
pub const max_attributes: usize = 64;

/// How many bytes the whole attribute list may hold once decoded.
pub const max_attribute_list_bytes: usize = 1024;

/// How deep the search goes. RFC 4511 section 4.5.1.2.
///
/// The numbers are the ones the `ENUMERATED` carries on the wire, measured
/// off curl: `0a 01 00` for `base`, `0a 01 01` for `one`, and `0a 01 02`
/// for `sub`.
pub const Scope = enum(i32) {
    base = 0,
    one = 1,
    sub = 2,

    /// The scope `text` names, or null.
    ///
    /// RFC 4516 section 2 names three: `base`, `one`, and `sub`. libldap
    /// also answers to `onelevel` and `subtree`, and curl 8.21.0 accepts
    /// both, measured. Both are here for that reason.
    ///
    /// **`children` is not here.** libldap answers to it with
    /// `LDAP_SCOPE_SUBORDINATE`, which is a draft extension and not a
    /// scope RFC 4511 names. A url that asks for it is refused by name
    /// rather than given `sub`, which would search a different set of
    /// entries than the url asked for.
    pub fn parse(text: []const u8) ?Scope {
        const rows = [_]struct { name: []const u8, scope: Scope }{
            .{ .name = "base", .scope = .base },
            .{ .name = "one", .scope = .one },
            .{ .name = "onelevel", .scope = .one },
            .{ .name = "sub", .scope = .sub },
            .{ .name = "subtree", .scope = .sub },
        };
        for (rows) |row| {
            if (std.ascii.eqlIgnoreCase(row.name, text)) return row.scope;
        }
        return null;
    }
};

/// The filter a url that names none carries. See the module doc comment.
pub const default_filter = "(objectclass=*)";

/// Every fault reading a url can report.
pub const ParseError = error{
    /// A part holds a percent escape that is not an escape.
    InvalidEscape,
    /// The base DN is longer than `max_dn_bytes`.
    DnTooLong,
    /// The base DN holds a control byte. See `Target.dn`.
    DnHasControlByte,
    /// The url names more than `max_attributes` attributes, or the list is
    /// longer than `max_attribute_list_bytes`.
    TooManyAttributes,
    /// One attribute description holds a byte RFC 4512 section 2.5 gives
    /// no attribute description, or it is empty.
    BadAttribute,
    /// The scope is not one of the names `Scope.parse` answers to.
    BadScope,
    /// The filter is longer than `filter.max_filter_bytes`.
    FilterTooLong,
    /// The filter holds a control byte.
    FilterHasControlByte,
    /// The url carries more than the five parts RFC 4516 section 2 names.
    TooManyParts,
    /// The url carries an extension. See `parse`.
    ExtensionUnsupported,
};

/// Where a parsed url's decoded text lives.
///
/// A caller keeps one of these for as long as it keeps the `Target` that
/// points into it. `Fetcher` holds it as a field, so the bounds above are
/// named numbers and never frame sizes.
pub const Storage = struct {
    dn: [max_dn_bytes]u8,
    attributes: [max_attribute_list_bytes]u8,
    filter: [filter.max_filter_bytes]u8,
};

/// What one `ldap://` url asks for.
///
/// Every slice points into the `Storage` the parse wrote into.
pub const Target = struct {
    /// The base object of the search, decoded. Empty is the root DSE,
    /// which is what `ldap://host/` names and what curl sends `04 00`
    /// for, measured.
    ///
    /// Holds no C0 control byte and no DEL. `zurl_core.url` already
    /// refuses those in a path, and `parse` refuses them again after the
    /// percent decode, which is where a `%0A` would otherwise arrive.
    dn: []const u8,
    /// The attribute descriptions the url named, decoded. Empty when it
    /// named none, which asks the server for every user attribute.
    attributes: [max_attributes][]const u8,
    /// How many of `attributes` are filled.
    attribute_count: usize,
    scope: Scope,
    /// The filter text, decoded, still in its RFC 4515 string form.
    /// `filter.write` is what turns it into BER.
    filter_text: []const u8,

    /// A target that names nothing. `parse` fills one in.
    pub const empty: Target = .{
        .dn = "",
        .attributes = @splat(""),
        .attribute_count = 0,
        .scope = .base,
        .filter_text = default_filter,
    };

    /// The attributes this url named.
    pub fn attributeList(t: *const Target) []const []const u8 {
        return t.attributes[0..t.attribute_count];
    }
};

/// Reads `url` into `storage` and returns what it asks for.
///
/// **The dn comes from the path and the other three from the query.**
/// `zurl_core.url` splits a url at the first `?`, so the path is the dn
/// with one leading `/` in front of it and the query is the remaining
/// three parts joined by `?`.
///
/// **An extension is refused and never dropped.** RFC 4516 section 2 ends
/// a url with an optional `?extensions` part, and an extension whose name
/// starts with `!` is critical: a client that does not implement it "must
/// not process the URL". This build implements none, so any extension at
/// all is `error.ExtensionUnsupported`. Dropping one would answer a
/// different question than the url asked, which is the same fault as
/// running direct when the user asked for a proxy.
pub fn parse(storage: *Storage, url: zurl_core.Url) ParseError!Target {
    var t: Target = .empty;

    // The path always starts with `/`, because `zurl_core.url` gives a url
    // with no path the path `/`.
    const raw_dn = if (url.path.len > 0 and url.path[0] == '/') url.path[1..] else url.path;
    if (raw_dn.len > storage.dn.len) return error.DnTooLong;
    t.dn = zurl_core.url.percentDecode(&storage.dn, raw_dn) catch |err| switch (err) {
        error.InvalidEscape => return error.InvalidEscape,
        error.NoSpaceLeft => return error.DnTooLong,
    };
    // **The decode is where a control byte can arrive.** `zurl_core.url`
    // refuses a raw CR or LF in a path, and `%0A` passes that check and
    // becomes one here. A DN reaches the output of this transfer, so a
    // newline in one would draw a line that reads like another entry.
    if (filter.hasControlByte(t.dn)) return error.DnHasControlByte;

    const query = url.query orelse return t;

    var parts = std.mem.splitScalar(u8, query, '?');
    const raw_attributes = parts.first();
    const raw_scope = parts.next() orelse "";
    const raw_filter = parts.next() orelse "";
    const raw_extensions = parts.next() orelse "";
    if (parts.next() != null) return error.TooManyParts;
    if (raw_extensions.len != 0) return error.ExtensionUnsupported;

    try parseAttributes(storage, &t, raw_attributes);

    if (raw_scope.len != 0) {
        t.scope = Scope.parse(raw_scope) orelse return error.BadScope;
    }

    if (raw_filter.len != 0) {
        if (raw_filter.len > storage.filter.len) return error.FilterTooLong;
        t.filter_text = zurl_core.url.percentDecode(&storage.filter, raw_filter) catch |err|
            switch (err) {
                error.InvalidEscape => return error.InvalidEscape,
                error.NoSpaceLeft => return error.FilterTooLong,
            };
        if (filter.hasControlByte(t.filter_text)) return error.FilterHasControlByte;
    }

    return t;
}

/// Reads the comma separated attribute list into `storage.attributes`.
///
/// **Each attribute is checked against RFC 4512 section 2.5**, the same
/// check `filter.checkAttribute` makes, for the same reason: libldap sends
/// whatever the url held, so without the check a url chooses the bytes of
/// an attribute description on the wire.
///
/// `1.1` is a real attribute name to this function and to the server. RFC
/// 4511 section 4.5.1.8 gives it the meaning "no attributes at all", and
/// curl sends it through as text, measured: `?1.1?` goes out as
/// `30 05 04 03 "1.1"`.
fn parseAttributes(storage: *Storage, t: *Target, raw: []const u8) ParseError!void {
    if (raw.len == 0) return;
    if (raw.len > storage.attributes.len) return error.TooManyAttributes;

    var written: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |piece| {
        if (t.attribute_count == max_attributes) return error.TooManyAttributes;
        const room = storage.attributes[written..];
        const decoded = zurl_core.url.percentDecode(room, piece) catch |err| switch (err) {
            error.InvalidEscape => return error.InvalidEscape,
            error.NoSpaceLeft => return error.TooManyAttributes,
        };
        if (decoded.len == 0) return error.BadAttribute;
        for (decoded) |b| {
            if (!filter.isAttributeByte(b)) return error.BadAttribute;
        }
        t.attributes[t.attribute_count] = decoded;
        t.attribute_count += 1;
        written += decoded.len;
    }
}

const testing = std.testing;

/// Parses `text` the way a registered `ldap` scheme does.
fn parseUrl(text: []const u8) !zurl_core.Url {
    var schemes: zurl_core.url.Schemes = .empty;
    try schemes.add(.{ .name = "ldap", .default_port = 389 });
    try schemes.add(.{ .name = "ldaps", .default_port = 636 });
    return zurl_core.url.parseWith(text, &schemes);
}

test "a url with every part names every part" {
    var storage: Storage = undefined;
    const url = try parseUrl("ldap://h/ou=people,dc=zurl,dc=test?cn,mail?one?(cn=Ross*)");
    const t = try parse(&storage, url);

    try testing.expectEqualStrings("ou=people,dc=zurl,dc=test", t.dn);
    try testing.expectEqual(@as(usize, 2), t.attribute_count);
    try testing.expectEqualStrings("cn", t.attributes[0]);
    try testing.expectEqualStrings("mail", t.attributes[1]);
    try testing.expectEqual(Scope.one, t.scope);
    try testing.expectEqualStrings("(cn=Ross*)", t.filter_text);
}

test "a url with only a dn takes the three defaults curl uses" {
    // Measured: `ldap://h/dc=zurl,dc=test` goes out with an empty
    // attribute SEQUENCE, `0a 01 00` for the scope, and
    // `87 0b "objectclass"` for the filter.
    var storage: Storage = undefined;
    const t = try parse(&storage, try parseUrl("ldap://h/dc=zurl,dc=test"));
    try testing.expectEqualStrings("dc=zurl,dc=test", t.dn);
    try testing.expectEqual(@as(usize, 0), t.attribute_count);
    try testing.expectEqual(Scope.base, t.scope);
    try testing.expectEqualStrings("(objectclass=*)", t.filter_text);
}

test "a url with no dn names the root DSE" {
    // Measured: `ldap://h/` goes out with `04 00` for the base object,
    // and slapd answers with the root DSE.
    var storage: Storage = undefined;
    const t = try parse(&storage, try parseUrl("ldap://h/"));
    try testing.expectEqualStrings("", t.dn);
    try testing.expectEqual(Scope.base, t.scope);
}

test "an empty part between two separators keeps its default" {
    var storage: Storage = undefined;
    const t = try parse(&storage, try parseUrl("ldap://h/dc=a??sub"));
    try testing.expectEqual(@as(usize, 0), t.attribute_count);
    try testing.expectEqual(Scope.sub, t.scope);
    try testing.expectEqualStrings("(objectclass=*)", t.filter_text);
}

test "every scope name curl accepts reaches the right number" {
    const Case = struct { text: []const u8, scope: Scope };
    const cases = [_]Case{
        .{ .text = "base", .scope = .base },
        .{ .text = "BASE", .scope = .base },
        .{ .text = "one", .scope = .one },
        .{ .text = "onelevel", .scope = .one },
        .{ .text = "sub", .scope = .sub },
        .{ .text = "subtree", .scope = .sub },
    };
    for (cases) |case| {
        try testing.expectEqual(case.scope, Scope.parse(case.text).?);
    }
    try testing.expectEqual(@as(i32, 0), @intFromEnum(Scope.base));
    try testing.expectEqual(@as(i32, 1), @intFromEnum(Scope.one));
    try testing.expectEqual(@as(i32, 2), @intFromEnum(Scope.sub));
}

test "a scope this build does not speak is refused by name" {
    var storage: Storage = undefined;
    // curl 8.21.0 answers a bad scope with exit 3, measured, and this is
    // the same answer.
    try testing.expectError(error.BadScope, parse(&storage, try parseUrl("ldap://h/dc=a?cn?nope")));
    // `children` is libldap's own extension and not a scope RFC 4511
    // names. Giving it `sub` would search a different set than the url
    // asked for.
    try testing.expectEqual(@as(?Scope, null), Scope.parse("children"));
}

test "every part is percent-decoded, and the split runs first" {
    var storage: Storage = undefined;
    // Measured: `dc%3Dzurl%2Cdc%3Dtest` reaches the wire as
    // `dc=zurl,dc=test`.
    const t = try parse(&storage, try parseUrl("ldap://h/dc%3Dzurl%2Cdc%3Dtest?cn?base?(cn=a%3Fb)"));
    try testing.expectEqualStrings("dc=zurl,dc=test", t.dn);
    // The `%3F` stayed inside the filter and did not cut the url.
    try testing.expectEqualStrings("(cn=a?b)", t.filter_text);
}

test "a percent escape that is not an escape is a runtime fault" {
    var storage: Storage = undefined;
    try testing.expectError(error.InvalidEscape, parse(&storage, try parseUrl("ldap://h/dc%zz")));
    try testing.expectError(
        error.InvalidEscape,
        parse(&storage, try parseUrl("ldap://h/dc=a?cn?base?(cn=%zz)")),
    );
}

test "a control byte hidden in a percent escape is refused" {
    // **This is the check `zurl_core.url` cannot make.** It refuses a raw
    // CR or LF in a path, and `%0A` passes that and becomes one here. A DN
    // reaches the output of this transfer.
    var storage: Storage = undefined;
    try testing.expectError(
        error.DnHasControlByte,
        parse(&storage, try parseUrl("ldap://h/cn=a%0ADN:%20cn=forged")),
    );
    try testing.expectError(
        error.DnHasControlByte,
        parse(&storage, try parseUrl("ldap://h/cn=a%00b")),
    );
    try testing.expectError(
        error.FilterHasControlByte,
        parse(&storage, try parseUrl("ldap://h/dc=a?cn?base?(cn=a%0Ab)")),
    );
}

test "an attribute holding a byte RFC 4512 does not name is refused" {
    var storage: Storage = undefined;
    try testing.expectError(
        error.BadAttribute,
        parse(&storage, try parseUrl("ldap://h/dc=a?c%20n")),
    );
    try testing.expectError(error.BadAttribute, parse(&storage, try parseUrl("ldap://h/dc=a?cn,")));
    try testing.expectError(error.BadAttribute, parse(&storage, try parseUrl("ldap://h/dc=a?,cn")));
    // `1.1` is a real name to the server: RFC 4511 section 4.5.1.8 gives
    // it the meaning "no attributes", and curl sends it as text.
    const t = try parse(&storage, try parseUrl("ldap://h/dc=a?1.1"));
    try testing.expectEqual(@as(usize, 1), t.attribute_count);
    try testing.expectEqualStrings("1.1", t.attributes[0]);
}

test "a url naming more attributes than the bound is refused" {
    var storage: Storage = undefined;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    try text.appendSlice(testing.allocator, "ldap://h/dc=a?");
    for (0..max_attributes + 1) |i| {
        if (i != 0) try text.append(testing.allocator, ',');
        try text.appendSlice(testing.allocator, "cn");
    }
    try testing.expectError(
        error.TooManyAttributes,
        parse(&storage, try parseUrl(text.items)),
    );
}

test "a dn longer than the bound is refused before it is decoded" {
    var storage: Storage = undefined;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    try text.appendSlice(testing.allocator, "ldap://h/");
    try text.appendNTimes(testing.allocator, 'a', max_dn_bytes + 1);
    try testing.expectError(error.DnTooLong, parse(&storage, try parseUrl(text.items)));
}

test "an extension is refused and never dropped" {
    // RFC 4516 section 2 makes an extension whose name starts with `!`
    // critical: a client that does not implement it must not process the
    // url. This build implements none, so every extension is refused.
    var storage: Storage = undefined;
    try testing.expectError(
        error.ExtensionUnsupported,
        parse(&storage, try parseUrl("ldap://h/dc=a?cn?base?(cn=x)?!bindname=cn=admin")),
    );
    try testing.expectError(
        error.ExtensionUnsupported,
        parse(&storage, try parseUrl("ldap://h/dc=a?cn?base?(cn=x)?e-bindname=cn=admin")),
    );
    // An empty extensions part names no extension, so it is not refused.
    const t = try parse(&storage, try parseUrl("ldap://h/dc=a?cn?base?(cn=x)?"));
    try testing.expectEqualStrings("(cn=x)", t.filter_text);
}

test "a url with more than five parts is refused" {
    var storage: Storage = undefined;
    try testing.expectError(
        error.TooManyParts,
        parse(&storage, try parseUrl("ldap://h/dc=a?cn?base?(cn=x)??more")),
    );
}
