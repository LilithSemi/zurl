//! The head and body handed back from one transfer.

const Response = @This();

const std = @import("std");
/// For `WireVersion` alone. The engine owns the set of versions a response
/// can have arrived in, and a second spelling of it here could name a
/// version no engine reports.
const zurl_http = @import("zurl-http");

status: u16,
/// How many bytes of body the peer announced, before any content
/// decoding.
///
/// `null` when the peer announced nothing, and also when
/// `transfer_encoding` is `.chunked`. A chunked transfer frames its own
/// length, so a `Content-Length` beside it says nothing about the body.
/// Passing that number through here would let a caller size a download,
/// or a progress bar, from a length the body does not match.
///
/// **A caller that leaves `Transfer.Options.accept_encoding` false reads
/// exactly this many octets off `body`.** Such a request decodes nothing:
/// a `Content-Encoding` the peer sends anyway is ignored and its octets go
/// to the caller as they arrived, which is what curl does with an
/// unsolicited coding. So the number and the octets describe the same
/// thing.
///
/// The only way this can describe octets a caller does not get is a caller
/// that set `accept_encoding`, and such a caller knows it did. `body` is
/// then decoded and this still counts the wire.
content_length: ?u64,
/// How the peer framed the body. Names why `content_length` reads `null`
/// for a chunked response.
transfer_encoding: std.http.TransferEncoding,
/// Streams the body, decoded if the peer used a content encoding.
/// Borrowed from the exchange that produced this response, and stays
/// valid only as long as that exchange stays open.
///
/// A read that fails returns `error.ReadFailed`, which says nothing about
/// the reason. Call `Client.resolveBodyError` right away, before any
/// other read, to get the named fault and record it in `Diagnostics`.
body: *std.Io.Reader,
// The four fields below carry a default, so a protocol written against an
// older `Response` still builds one. Each default is what a protocol that
// reports no response head says, and the built-in HTTP protocol writes
// every one of them itself.
/// Every response head this transfer received, in the order they arrived,
/// byte for byte as the peer wrote them.
///
/// Each block runs from the status line to the empty line that ends the
/// head, and keeps its CRLF line endings and that empty line. A transfer
/// that followed a redirect holds one block for each hop, one after the
/// other. That is what `curl -D file -L` writes, measured against curl
/// 8.21.0, so a `-D` implementation writes this text and nothing else.
///
/// `null` when the transfer kept no head block. See `headers_oversize` for
/// the two reasons, which a caller must tell apart before it writes a
/// file: the engine dropped the blocks at a bound, or the protocol that
/// ran this transfer reports no heads at all. A protocol registered with
/// `Client.registerProtocol` is the second case, and the built-in HTTP
/// protocol is never it.
///
/// Do not look a header up in this text. It holds more than one head once
/// a redirect was followed, and a name found in an earlier hop describes a
/// page the transfer moved away from. Use `header`, which reads
/// `final_headers`.
///
/// **Lifetime.** Valid until the next `perform` on the `Client` that
/// returned it, or until that `Client`'s `deinit`, whichever comes first.
/// The same rule `body` follows, and for the same reason: the memory
/// belongs to the `Client` and its engine, and the next transfer reuses
/// it. Copy the text to keep it longer.
///
/// **This holds no request header.** These are the bytes a server sent
/// back. `Authorization` and `Cookie` are headers zurl sends, they travel
/// to the engine by a separate channel, and no path leads from that
/// channel to here. A `Set-Cookie` is a response header and does appear,
/// because the peer wrote it.
headers: ?[]const u8 = null,
/// The head of the final response, alone. A subslice of `headers`, and
/// `null` whenever `headers` is.
///
/// This is what `header` reads. With no redirect it is all of `headers`.
final_headers: ?[]const u8 = null,
/// Whether the engine dropped the head blocks because they passed a bound
/// of its own.
///
/// `headers` is `null` for two different reasons, and a caller that writes
/// the blocks to a file must not treat them alike. This flag says the
/// blocks arrived and did not fit. The engine keeps every block or none,
/// so a file written from `headers` is never a part of a head that reads
/// like a whole one.
headers_oversize: bool = false,
/// The url the transfer finished on, after any redirect.
///
/// With no redirect this is the url text the caller gave `perform`, byte
/// for byte. With a redirect it is the engine's own text for the final
/// hop, which carries no userinfo.
///
/// Empty only for a protocol registered with `Client.registerProtocol`
/// that fills nothing here and reports a url of its own by another means.
/// `perform` fills the caller's url text in for such a protocol, so a
/// caller of `perform` never reads an empty one.
///
/// **Lifetime.** The same rule `headers` follows. With no redirect the
/// text is the caller's own and lives as long as the caller keeps it;
/// with a redirect it belongs to the transfer, so the shorter of the two
/// rules is the one to hold to.
effective_url: []const u8 = "",
/// Which version of HTTP framed the final response.
///
/// **This is what `-w %{http_version}` prints**, and it is the version the
/// peer answered in and never the version a flag asked for. A transfer
/// under `--http3` that fell back to the TCP hop reports the version that
/// hop used, which is what curl reports for the same command line.
///
/// `null` for a transfer that got no response head, and for a protocol
/// registered with `Client.registerProtocol`, which speaks no HTTP at all.
/// curl prints `0` for both.
http_version: ?zurl_http.engine.WireVersion = null,

/// The value of the response header `name`, from the final response's own
/// head, or `null` when that head carries no such header.
///
/// Matched without regard to case, because HTTP field names are
/// case-insensitive. The value comes back trimmed of the spaces and tabs
/// around it, and otherwise exactly as the peer wrote it.
///
/// Reads `final_headers` and never `headers`: a `Content-Type` in the head
/// of a redirect describes the redirect page, not the body this response
/// carries.
///
/// A peer may send the same header twice. This answers with the first,
/// which is what a caller asking for `Content-Type` wants; a caller that
/// needs every value of a repeated header, such as `Set-Cookie`, must walk
/// `final_headers` itself.
///
/// Parses the raw bytes here rather than through `std.http.HeaderIterator`,
/// which answers a block with no line ending by reaching past the end of
/// it. A head block is a peer's bytes, and a `Response` a caller built by
/// hand can hold any bytes at all, so this walks lines and stops at the
/// end of what it was given.
pub fn header(r: Response, name: []const u8) ?[]const u8 {
    return headerIn(r.final_headers orelse return null, name);
}

/// The value of `name` in one raw response head block, or `null` when the
/// block carries no such header.
///
/// `header` is this over a `Response`. It is `pub` so a caller that has a
/// head block and no `Response`, such as `Client.finalHeader` on the
/// `--fail` path, reads a header by the same rule and not by a second
/// copy of it.
pub fn headerIn(block: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, block, "\r\n");
    // The status line names no header.
    _ = lines.first();

    while (lines.next()) |line| {
        // The empty line ends the head.
        if (line.len == 0) return null;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

const testing = std.testing;

test "content_length stays null for a chunked transfer, matching engine.Head" {
    var body_source: std.Io.Reader = .fixed("");
    const r: Response = .{
        .status = 200,
        .content_length = null,
        .transfer_encoding = .chunked,
        .body = &body_source,
    };

    try testing.expectEqual(@as(?u64, null), r.content_length);
    try testing.expectEqual(std.http.TransferEncoding.chunked, r.transfer_encoding);
}

test "content_length carries the peer's announced length for a non-chunked transfer" {
    var body_source: std.Io.Reader = .fixed("payload");
    const r: Response = .{
        .status = 200,
        .content_length = 7,
        .transfer_encoding = .none,
        .body = &body_source,
    };

    try testing.expectEqual(@as(?u64, 7), r.content_length);
    try testing.expectEqual(std.http.TransferEncoding.none, r.transfer_encoding);
}

test "header finds a name without regard to case, and trims the value" {
    var body_source: std.Io.Reader = .fixed("");
    const block = "HTTP/1.1 200 OK\r\nContent-Type:\ttext/plain; charset=utf-8 \r\n" ++
        "Content-Length: 0\r\n\r\n";
    const r: Response = .{
        .status = 200,
        .content_length = 0,
        .transfer_encoding = .none,
        .body = &body_source,
        .headers = block,
        .final_headers = block,
        .headers_oversize = false,
        .effective_url = "http://example.com/",
    };

    try testing.expectEqualStrings("text/plain; charset=utf-8", r.header("Content-Type").?);
    try testing.expectEqualStrings("text/plain; charset=utf-8", r.header("content-type").?);
    try testing.expectEqualStrings("0", r.header("Content-Length").?);
    try testing.expectEqual(@as(?[]const u8, null), r.header("Set-Cookie"));
    // A name that is a prefix of a real one is not that header.
    try testing.expectEqual(@as(?[]const u8, null), r.header("Content"));
}

test "header reads the final response's head and never an earlier hop's" {
    // The whole log holds a redirect that carried a `Content-Type` of its
    // own. A lookup must answer with the final response's, because that is
    // the body the caller is about to read.
    const first = "HTTP/1.1 302 Found\r\nContent-Type: text/html\r\nLocation: /body\r\n\r\n";
    const second = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n";

    var body_source: std.Io.Reader = .fixed("ok");
    const r: Response = .{
        .status = 200,
        .content_length = 2,
        .transfer_encoding = .none,
        .body = &body_source,
        .headers = first ++ second,
        .final_headers = second,
        .headers_oversize = false,
        .effective_url = "http://example.com/body",
    };

    // The final response named no content type, so there is none, even
    // though the hop before it did.
    try testing.expectEqual(@as(?[]const u8, null), r.header("Content-Type"));
    try testing.expectEqualStrings("2", r.header("Content-Length").?);
}

test "header answers null for a response that kept no head, and for a malformed one" {
    var body_source: std.Io.Reader = .fixed("");
    var r: Response = .{
        .status = 200,
        .content_length = null,
        .transfer_encoding = .none,
        .body = &body_source,
    };

    // The defaults: a protocol that reports no head at all.
    try testing.expectEqual(@as(?[]const u8, null), r.header("Content-Type"));
    try testing.expectEqualStrings("", r.effective_url);

    // A block with no line ending, and one with no empty line, must
    // answer rather than read past their own end.
    r.final_headers = "HTTP/1.1 200 OK";
    try testing.expectEqual(@as(?[]const u8, null), r.header("Content-Type"));
    r.final_headers = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
    try testing.expectEqualStrings("text/plain", r.header("Content-Type").?);
    r.final_headers = "";
    try testing.expectEqual(@as(?[]const u8, null), r.header("Content-Type"));
}

test "header stops at the empty line, so a body cannot answer for a header" {
    // A caller may hand this a block that has a body behind it. A `X-Fake`
    // line in the body is not a header of the response.
    var body_source: std.Io.Reader = .fixed("");
    const r: Response = .{
        .status = 200,
        .content_length = null,
        .transfer_encoding = .none,
        .body = &body_source,
        .final_headers = "HTTP/1.1 200 OK\r\nA: 1\r\n\r\nX-Fake: yes\r\n",
    };

    try testing.expectEqualStrings("1", r.header("A").?);
    try testing.expectEqual(@as(?[]const u8, null), r.header("X-Fake"));
}
