//! zurl's `imap://` and `imaps://` protocols, RFC 3501 and RFC 2595.
//!
//! One protocol, one module. A build that does not want IMAP leaves this
//! module out and loses nothing else, and a program outside this
//! repository takes this module, `zurl-core`, and `zurl-net` and gets both
//! schemes with no other part of zurl.
//!
//! **One package owns both schemes**, the way `zurl-ftp` owns `ftp` and
//! `ftps`. RFC 3501 names the commands and the answers, and `imaps`
//! changes neither. The two carry different default ports, 143 and 993.
//!
//! **This package does not import `zurl`, and it never will**:
//! `Fetcher.protocol` takes the front package's namespace as a comptime
//! parameter instead.
//!
//! A caller wires it in four lines:
//!
//!     var fetcher: zurl_imap.Fetcher = .init(gpa, io);
//!     defer fetcher.deinit();
//!     try client.registerProtocol(fetcher.protocol(zurl));
//!     try client.registerProtocol(fetcher.secureProtocol(zurl));
//!
//! **IMAP is the one of the four mail and file protocols where an answer
//! names the command it answers.** Every command carries a tag, and the
//! server ends that command with a line starting with the same tag, with
//! any number of untagged lines in between. So the dialogue reads until it
//! sees its own tag and takes no untagged line as an end. `Control` holds
//! that rule.
//!
//! **The three rules that keep this safe**, each with its own section in
//! the file that holds it:
//!
//! - **No command can carry a forged line ending.** Every command goes out
//!   through `Control.send`, which calls the one gate every line-oriented
//!   package in this repository shares. The mailbox name, the message
//!   number, and the credential are each refused a second time, earlier,
//!   so the message names the url and not the command.
//! - **A mailbox name cannot close its own argument.** A name that is not
//!   an atom is written inside double quotes, and a `"` or a `\` inside it
//!   is escaped. Without that, the name `My" INBOX` would reach a server
//!   as two arguments. See `command.quote`.
//! - **A literal is read by its count and never as lines.** RFC 3501
//!   writes a string as `{n}` and then exactly `n` octets, and those
//!   octets may hold a `CRLF` and may look exactly like a tagged answer. A
//!   reader that took them as lines would end a command in the middle of a
//!   message. See `Control.collect`.
//!
//! **Every wait is bounded**: the dial, the `STARTTLS` step, and any
//! handshake by `--connect-timeout`, each line by `Control.max_line_bytes`,
//! each wait for a byte by `--speed-time` under a 300 second ceiling, the
//! lines of one command by `Control.max_untagged_lines`, and the answer by
//! `--max-filesize` under a 16 MiB ceiling. The last two count in every
//! `Control.Mode`, so no mode reads past them.

const std = @import("std");

/// Runs one IMAP transfer and builds the two dispatch entries that
/// register it.
pub const Fetcher = @import("zurl-imap/Fetcher.zig");

/// The RFC 3501 tagged command dialogue, over one reader and one writer.
/// It holds no socket, so a test can drive a whole session in memory.
pub const Control = @import("zurl-imap/Control.zig");

/// The RFC 3501 response grammar: the tagged line, the untagged line, the
/// continuation request, and the literal. Pure text.
pub const response = @import("zurl-imap/response.zig");

/// The commands, the tag each one carries, and the quoting a mailbox name
/// needs. Pure text.
pub const command = @import("zurl-imap/command.zig");

/// What a url path names: a mailbox, and the message inside it. Pure text.
pub const target = @import("zurl-imap/target.zig");

/// The loopback RFC 3501 server this package's tests use.
///
/// Exported for the same reason `zurl_ftp.test_server` is: the end to end
/// tests of the command line need an IMAP peer, and a second copy of this
/// fixture would drift from the one the package tests itself with. It is a
/// fixture and not a product, and nothing but a test may use it. It speaks
/// no TLS, so it serves `imap` and never `imaps`.
pub const test_server = @import("zurl-imap/test_server.zig");

/// The plain url scheme this package handles.
pub const scheme = Fetcher.scheme;

/// The encrypted url scheme this package handles.
pub const secure_scheme = Fetcher.secure_scheme;

/// The port an `imap://` url uses when it names none.
pub const default_port = Fetcher.default_port;

/// The port an `imaps://` url uses when it names none.
pub const secure_default_port = Fetcher.secure_default_port;

test {
    _ = Fetcher;
    _ = Control;
    _ = response;
    _ = command;
    _ = target;
}

test "the package names both schemes and the two ports they use" {
    try std.testing.expectEqualStrings("imap", scheme);
    try std.testing.expectEqualStrings("imaps", secure_scheme);
    try std.testing.expectEqual(@as(?u16, 143), default_port);
    try std.testing.expectEqual(@as(?u16, 993), secure_default_port);
}
