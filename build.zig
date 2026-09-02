const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_step = b.step("test", "Run all tests");

    const core = b.addModule("zurl-core", .{
        .root_source_file = b.path("lib/zurl-core.zig"),
        .target = target,
        .optimize = optimize,
    });
    // The public suffix list. `zurl-core/cookie.zig` is the one caller: a
    // `Set-Cookie` may not name a domain that every site under it would
    // read back. The list is always generated and always embedded, for the
    // reason the trust roots are: a build option here would let somebody
    // build a zurl whose cookie rule refuses nothing.
    core.addAnonymousImport("psl_data", .{ .root_source_file = addPublicSuffixList(b, test_step) });
    addModuleTests(b, test_step, core);

    const stream = b.addModule("zurl-stream", .{
        .root_source_file = b.path("lib/zurl-stream.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zurl-core", .module = core }},
    });
    addModuleTests(b, test_step, stream);

    // HPACK, the header compression of HTTP/2, RFC 7541. It imports
    // nothing else of ours, and that is on purpose: a codec with a
    // published specification and published test vectors needs no url
    // rule, no error taxonomy, and no trust root. The engine that sits
    // over it is what maps its faults onto `zurl_core.Error`, the way
    // `zurl-http/errors.zig` already does for HTTP/1.1.
    //
    // `zurl-http` is the one module that imports this, through
    // `zurl-http/h2.zig`.
    const hpack = b.addModule("zurl-hpack", .{
        .root_source_file = b.path("lib/zurl-hpack.zig"),
        .target = target,
        .optimize = optimize,
    });
    addModuleTests(b, test_step, hpack);

    // The frame layer of HTTP/2, RFC 9113. It is the second of the three
    // pieces HTTP/2 needs, after `zurl-hpack`.
    //
    // The architecture allows it `zurl-core` and `zurl-hpack`. Neither is
    // wired, because a frame carries a header block fragment as octets
    // and nothing in this layer decompresses one: only the engine above
    // knows when a block is whole. The imports go in when something in
    // the module needs them.
    //
    // This is framing alone. There is no connection engine here and no
    // stream state machine. `zurl-http/h2.zig` is that engine, and it is
    // the one file that imports this module and `zurl-hpack` together.
    const h2 = b.addModule("zurl-h2", .{
        .root_source_file = b.path("lib/zurl-h2.zig"),
        .target = target,
        .optimize = optimize,
    });
    addModuleTests(b, test_step, h2);

    // The packet and frame layer of QUIC, RFC 9000, and the keys RFC 9001
    // writes into its own text. It is the first of the pieces HTTP/3
    // needs, the way `zurl-hpack` was the first of the three HTTP/2
    // needed.
    //
    // The architecture allows it `zurl-core` and, once there is a socket
    // to open, `zurl-net`. Neither is wired, for the reason `zurl-hpack`
    // and `zurl-h2` wire neither: a codec with a published specification
    // and published test vectors needs no url rule, no error taxonomy,
    // and no trust root. The imports go in when something in the module
    // needs them, and the engine above is what maps a fault here onto
    // `zurl_core.Error`.
    //
    // **This is framing and keys alone.** There is no connection engine,
    // no loss recovery, no congestion control, no stream state machine,
    // and no TLS handshake. `lib/zurl-quic/protection.zig` holds the
    // shape a key set has, and the TLS task fills it in by handing over
    // a secret. `lib/zurl-quic/initial.zig` is the one key set that needs
    // no handshake at all, because RFC 9001 section 5.2 derives it from
    // the client's first connection id with a salt the RFC prints.
    //
    // Nothing here allocates. Every length in a QUIC packet is a number
    // the peer chose and a varint can name 2^62, so
    // `lib/zurl-quic/Cursor.zig` checks each one against the bytes that
    // really arrived and a decoded frame borrows the datagram.
    const quic = b.addModule("zurl-quic", .{
        .root_source_file = b.path("lib/zurl-quic.zig"),
        .target = target,
        .optimize = optimize,
    });
    addModuleTests(b, test_step, quic);

    // QPACK, the field compression of HTTP/3, RFC 9204. It is to HTTP/3
    // what `zurl-hpack` is to HTTP/2, and it is wired the same way: with
    // an empty import table, because a codec with a published
    // specification and published test vectors needs no url rule, no error
    // taxonomy, and no trust root.
    //
    // It does not import `zurl-hpack` either, though RFC 9204 borrows
    // HPACK's prefixed integer and Huffman table. The integer needed a
    // wider ceiling here, 62 bits against 32, and the string literal
    // needed a new shape, because a QPACK one may start part way through
    // an octet. Only the Huffman table is the same, and the copy of it is
    // proved complete and canonical when the module compiles.
    //
    // **This is compression alone.** There is no QUIC here, no frame
    // layer, no stream state machine, and no engine. The decoder sets
    // SETTINGS_QPACK_BLOCKED_STREAMS to zero and never waits on an
    // encoder stream, so nothing in it can deadlock.
    //
    // Nothing imports it yet. zurl offers no HTTP/3 in its ALPN, and it
    // will not until an engine can speak it.
    const qpack = b.addModule("zurl-qpack", .{
        .root_source_file = b.path("lib/zurl-qpack.zig"),
        .target = target,
        .optimize = optimize,
    });
    addModuleTests(b, test_step, qpack);

    // The frame layer of HTTP/3, RFC 9114. It is to HTTP/3 what
    // `zurl-h2` is to HTTP/2.
    //
    // **It imports `zurl-quic`, where `zurl-h2` imports nothing, and the
    // import is the point.** RFC 9114 section 7.1 defines no number
    // format of its own: every length, every setting identifier, and
    // every unidirectional stream type is the variable-length integer of
    // RFC 9000 section 16. A second copy of that coder here would be a
    // second place for the 62 bit bound and the minimal-encoding rule to
    // drift from the one the packet layer already passes RFC 9001
    // appendix A with.
    //
    // `zurl-qpack` made the other choice for the opposite reason: RFC
    // 9204's prefixed integer is HPACK's and not QUIC's, so sharing one
    // coder would have meant one function answering to two
    // specifications.
    //
    // **This is framing and the connection rules alone.** There is no
    // QUIC connection here, no field compression, and no engine.
    // `zurl-http/h3.zig` is that engine, and it is the one file that
    // imports this module, `zurl-qpack`, and `zurl-quic-tls` together.
    const h3 = b.addModule("zurl-h3", .{
        .root_source_file = b.path("lib/zurl-h3.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zurl-quic", .module = quic }},
    });
    addModuleTests(b, test_step, h3);

    const tls = b.addModule("zurl-tls", .{
        .root_source_file = b.path("lib/zurl-tls.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zurl-core", .module = core }},
    });
    tls.addAnonymousImport("ca_bundle_pem", .{ .root_source_file = addCaBundle(b, test_step) });
    addModuleTests(b, test_step, tls);

    // The TLS 1.3 handshake of QUIC, RFC 9001. The second of the pieces
    // HTTP/3 needs, after `zurl-quic`.
    //
    // **This one has to import two of ours, and both imports are the
    // point.** `zurl-quic` gives it the key derivation, the packet
    // levels, and the transport parameters, none of which it writes
    // again. `zurl-tls` gives it the certificate chain walk, the host and
    // address walk, the trust store, the CertificateVerify check, the
    // Diffie-Hellman, and the ALPN encoder, none of which it writes
    // again either. So this module holds no certificate code at all, and
    // a trust rule added to the vendored client reaches HTTP/3 with no
    // change here.
    //
    // It is a separate module and not part of `zurl-tls`, because
    // `zurl_tls.Client.init` reads TLS records and QUIC has none. Keeping
    // them apart also keeps `zurl-tls` free of any QUIC import, so a
    // build that speaks HTTPS and not HTTP/3 pulls in neither.
    //
    // There is no connection engine here either: no socket, no datagram,
    // no loss recovery, and no timer. `Session.zig` is pure key state,
    // and the engine above drives it.
    const quic_tls = b.addModule("zurl-quic-tls", .{
        .root_source_file = b.path("lib/zurl-quic-tls.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-quic", .module = quic },
            .{ .name = "zurl-tls", .module = tls },
        },
    });
    addModuleTests(b, test_step, quic_tls);

    // Dialing and TLS session setup, the layer a protocol engine sits on.
    // It imports `zurl-tls`, so anything built over it reaches the
    // vendored TLS client and its ECDSA patch. The architecture also
    // allows it `zurl-stream`; nothing in it needs a stream decorator
    // yet, so that import is not wired until something does.
    const net = b.addModule("zurl-net", .{
        .root_source_file = b.path("lib/zurl-net.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-tls", .module = tls },
        },
    });
    addModuleTests(b, test_step, net);

    // The HTTP engine owns its connection, so it imports `zurl-net` and
    // reaches the vendored TLS client through it. It does not import
    // `zurl-tls` itself: the trust roots come from the front package, and
    // nothing in this module builds a TLS session of its own.
    //
    // `zurl-h2` and `zurl-hpack` are the two HTTP/2 pieces under
    // `zurl-http/h2.zig`, which is the connection engine that turns them
    // into transfers. They are wired here and nowhere else: no other
    // module speaks a frame or a header block.
    const http = b.addModule("zurl-http", .{
        .root_source_file = b.path("lib/zurl-http.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
            .{ .name = "zurl-h2", .module = h2 },
            .{ .name = "zurl-hpack", .module = hpack },
            // The four HTTP/3 pieces, under `zurl-http/h3.zig` and
            // `zurl-http/quic.zig`. `zurl-quic` is the packet and stream
            // layer, `zurl-quic-tls` runs the handshake and reaches the
            // vendored TLS client's certificate rules through it,
            // `zurl-h3` is the framing, and `zurl-qpack` is the field
            // compression. They are wired here and nowhere else: no other
            // module speaks a QUIC packet or an HTTP/3 frame.
            //
            // **`zurl-tls` still does not come in.** The trust roots come
            // from the front package as a `std.crypto.Certificate.Bundle`,
            // and `zurl-quic-tls` is what turns one into the vendored
            // client's own option, the same way `zurl-net` does for a TLS
            // session over TCP.
            .{ .name = "zurl-quic", .module = quic },
            .{ .name = "zurl-quic-tls", .module = quic_tls },
            .{ .name = "zurl-h3", .module = h3 },
            .{ .name = "zurl-qpack", .module = qpack },
        },
    });
    addModuleTests(b, test_step, http);

    // One protocol, one module. This one reads the local filesystem, so
    // it needs no dial and no TLS: `zurl-core` gives it the url rules and
    // the error taxonomy, and nothing else of ours is in its import
    // table. It must never import `zurl`, because a protocol package that
    // imports the front package cannot be left out of a build that does
    // not want it, and cannot be taken into another project on its own.
    // `zurl-file/Fetcher.zig`'s `protocol` takes the front package's
    // namespace as a comptime parameter instead of importing it.
    const file = b.addModule("zurl-file", .{
        .root_source_file = b.path("lib/zurl-file.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zurl-core", .module = core }},
    });
    addModuleTests(b, test_step, file);

    // The three protocol packages below each own one wire protocol and
    // each import `zurl-core` and `zurl-net` and nothing else of ours.
    // They dial, so they need the socket layer that `zurl-file` did not.
    // None of them imports `zurl`, for the reason written above
    // `zurl-file`: a protocol package that imports the front package
    // cannot be left out of a build that does not want it.
    //
    // `zurl-dict` is RFC 2229, on TCP 2628. It writes a `CLIENT` line, one
    // command, and `QUIT`, and reads until the peer closes.
    const dict = b.addModule("zurl-dict", .{
        .root_source_file = b.path("lib/zurl-dict.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, dict);

    // `zurl-gopher` is RFC 1436, on TCP 70, and `gophers` over TLS on the
    // same port. One package owns both schemes, the way `zurl.protocol`
    // gives `http` and `https` one vtable: the request and the answer are
    // the same bytes, and only the transport under them differs.
    const gopher = b.addModule("zurl-gopher", .{
        .root_source_file = b.path("lib/zurl-gopher.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, gopher);

    // `zurl-tftp` is RFC 1350, on UDP 69. It is the one protocol package
    // that reads no stream: it owns its own block acknowledgement and its
    // own retransmission over datagrams. `zurl-net` gives it the error
    // taxonomy for a dial, and `std.Io.net.Socket` gives it the datagrams.
    const tftp = b.addModule("zurl-tftp", .{
        .root_source_file = b.path("lib/zurl-tftp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, tftp);

    // `zurl-ftp` is RFC 959, on TCP 21, and `ftps` on 990 with implicit
    // TLS, plus RFC 4217's `AUTH TLS` on 21 for `--ssl-reqd`. One package
    // owns both schemes, the way `zurl-gopher` does, because the commands
    // and the replies are the same and only the transport under them
    // differs.
    //
    // It is the one protocol package that opens two connections for one
    // transfer: the control connection carries the dialogue and the data
    // connection carries the file. `zurl-net` gives it both, and
    // `zurl_net.bounded.readLine` gives it the line framing the
    // architecture scoped for exactly this protocol.
    const ftp = b.addModule("zurl-ftp", .{
        .root_source_file = b.path("lib/zurl-ftp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, ftp);

    // The three mail protocol packages below. One protocol, one module, so
    // a build that wants POP3 and not SMTP takes one and leaves the other,
    // and a program outside this repository takes just the one it needs.
    //
    // All three read their line framing, their command writer, and their
    // injection gate from `zurl-net`. What each one owns is its own
    // grammar: POP3 answers `+OK` and `-ERR`, IMAP answers with a tag, and
    // SMTP answers with a three digit code, which is the one grammar of
    // the three that is shared, with `zurl-ftp`, in `zurl_net.reply`.
    //
    // `zurl-pop3` is RFC 1939, on TCP 110, and `pop3s` on 995 with
    // implicit TLS, plus RFC 2595's `STLS` on 110 for `--ssl-reqd`.
    const pop3 = b.addModule("zurl-pop3", .{
        .root_source_file = b.path("lib/zurl-pop3.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, pop3);

    // `zurl-imap` is RFC 3501, on TCP 143, and `imaps` on 993 with
    // implicit TLS, plus RFC 2595's `STARTTLS` on 143 for `--ssl-reqd`.
    // It is the one protocol package whose answers name the command they
    // answer: every command carries a tag, and a reader that took an
    // untagged line as an end would read every later answer against the
    // wrong command.
    const imap = b.addModule("zurl-imap", .{
        .root_source_file = b.path("lib/zurl-imap.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, imap);

    // `zurl-smtp` is RFC 5321, on TCP 25, and `smtps` on 465 with implicit
    // TLS, plus RFC 3207's `STARTTLS` on 25 for `--ssl-reqd`. It is the
    // one protocol package that sends rather than fetches, so the care in
    // it goes into the `DATA` phase: a message body line of one period
    // ends that phase, and every byte after it is read as a command.
    const smtp = b.addModule("zurl-smtp", .{
        .root_source_file = b.path("lib/zurl-smtp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, smtp);

    // `zurl-ws` is RFC 6455, on TCP 80 for `ws` and TCP 443 for `wss`. It
    // is the one protocol package whose transfer opens as an HTTP request:
    // a `GET` with an `Upgrade:` line, and only the answer to it turns the
    // connection into a frame stream.
    //
    // **It imports `zurl-core` and `zurl-net` and not `zurl-http`.** The
    // handshake needs a small piece of HTTP, and that piece lives in
    // `lib/zurl-ws/handshake.zig`. An import of the HTTP engine would tie
    // this package to it, and a build that wanted WebSockets without HTTP
    // could not have one.
    const ws = b.addModule("zurl-ws", .{
        .root_source_file = b.path("lib/zurl-ws.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, ws);

    // `zurl-telnet` is RFC 854, on TCP 23. It is the smallest protocol
    // package that dials: it writes what the caller gave it and reads
    // until the peer closes. What it owns is the `IAC` escaping, which is
    // the same class of rule as SMTP's dot-stuffing: an octet of 255 that
    // is not doubled lets data reach the peer as a command.
    const telnet = b.addModule("zurl-telnet", .{
        .root_source_file = b.path("lib/zurl-telnet.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, telnet);

    // `zurl-ssh` is an SSH client with no url scheme of its own: RFC 4253
    // for the transport, RFC 4252 for the login, and RFC 4254 for the
    // channels. It registers nothing, and `zurl-sftp` is what turns it
    // into a transfer.
    //
    // **It is still not in `Protocols` and not in `addCli`.** A protocol
    // package earns a place there when it can run a transfer, and an SSH
    // client with no file protocol over it cannot. It is in the import
    // list of `zurl-sftp` and nowhere else.
    //
    // Every algorithm it speaks comes from `std.crypto`: `dh.X25519`,
    // `sign.Ed25519`, `aead.chacha_poly`, `aead.aes_gcm`, `hash.sha2`,
    // `hash.Md5` and `auth.hmac.HmacSha1` for `known_hosts`, and
    // `pwhash.bcrypt` for an encrypted key file. There is no C dependency
    // here and there will not be one, which is the whole reason this
    // package exists rather than a binding to libssh2.
    const ssh = b.addModule("zurl-ssh", .{
        .root_source_file = b.path("lib/zurl-ssh.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, ssh);

    // `zurl-sftp` is the SSH file transfer protocol, version 3, on TCP 22.
    // It is the one protocol package that imports another protocol
    // package: `zurl-ssh` is an SSH client and no url scheme, and this is
    // one url scheme over it. The split is the same one `zurl-http` and
    // `zurl-h2` have, and it is there so that a second scheme over SSH
    // adds a module beside this one rather than a copy of the client.
    //
    // It does not import `zurl`, for the reason written above
    // `zurl-file`: a protocol package that imports the front package
    // cannot be left out of a build that does not want it.
    const sftp = b.addModule("zurl-sftp", .{
        .root_source_file = b.path("lib/zurl-sftp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
            .{ .name = "zurl-ssh", .module = ssh },
        },
    });
    addModuleTests(b, test_step, sftp);

    // `zurl-scp` is the old rcp protocol over an SSH `exec` channel, on
    // TCP 22. It is the second scheme over `zurl-ssh`, which is what the
    // split between that package and this one was for: a scheme over SSH
    // adds a module beside `zurl-sftp` rather than a copy of the client.
    //
    // **It carries the one shell quoting rule in this repository.** A path
    // from a url reaches a shell on the far side, and `zurl-scp/command.zig`
    // states the rule and enforces it. Nothing else in this build writes an
    // `exec` command.
    const scp = b.addModule("zurl-scp", .{
        .root_source_file = b.path("lib/zurl-scp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
            .{ .name = "zurl-ssh", .module = ssh },
        },
    });
    addModuleTests(b, test_step, scp);

    // `zurl-ldap` is RFC 4511 on TCP 389, and `ldaps` on 636 with implicit
    // TLS, plus RFC 4511 section 4.14's StartTLS on 389 for `--ssl-reqd`.
    // The url form is RFC 4516.
    //
    // **It is the one protocol package whose messages are not text.** Every
    // other one writes commands as lines and reads answers as lines. This
    // one writes BER, and a BER length is a number the peer chose that
    // decides how many bytes this process then reads. `lib/zurl-ldap/ber.zig`
    // is where every bound on that number lives, and it is its own module
    // for exactly that reason.
    //
    // It carries this repository's RFC 4515 escaping rule, in
    // `lib/zurl-ldap/filter.zig`: a filter comes out of a url and reaches
    // the wire, and a bare parenthesis in one would ask the server a
    // different question than the user did.
    const ldap = b.addModule("zurl-ldap", .{
        .root_source_file = b.path("lib/zurl-ldap.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, ldap);

    // `zurl-mqtt` is MQTT 3.1.1 on TCP 1883, and `mqtts` on 8883 with
    // implicit TLS. A url names its topic in the path.
    //
    // **It carries the same hazard `zurl-ldap` does**: the remaining length
    // of MQTT 3.1.1 section 2.2.3 is a number the peer chose that decides
    // how many bytes this process then reads.
    // `lib/zurl-mqtt/varint.zig` refuses a fifth continuation byte and
    // `lib/zurl-mqtt/Session.zig` checks the decoded length against a
    // ceiling before it allocates, because four legal bytes still name 256
    // MiB.
    //
    // It calls `zurl_net.line.write` nowhere, and
    // `lib/zurl-mqtt/topic.zig` holds the argument for why: MQTT counts
    // the octets in front of every string, so no byte can end a field.
    // What that file does refuse is a NUL and a wildcard in a topic this
    // build publishes to, because both change what the topic names.
    const mqtt = b.addModule("zurl-mqtt", .{
        .root_source_file = b.path("lib/zurl-mqtt.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, mqtt);

    // `zurl-rtsp` is RFC 2326 on TCP 554. There is no TLS twin: `rtsps`
    // belongs to RTSP 2.0 and curl 8.21.0 carries none, measured.
    //
    // **It looks like HTTP and it is not HTTP.** The target of a request
    // is an absolute url, every request and reply carries a `CSeq` that
    // ties one to the other, and a reply with no `Content-Length` has no
    // body at all. `lib/zurl-rtsp/Session.zig` is where the `CSeq` tie is
    // checked, and a reply carrying another request's number ends the
    // session rather than being read as an answer to this one.
    //
    // It is a line protocol, so `lib/zurl-rtsp/request.zig` puts every
    // part through `zurl_net.line.write`, which is the one gate this
    // repository keeps. Four flags and every `-H` reach a header line
    // through it.
    const rtsp = b.addModule("zurl-rtsp", .{
        .root_source_file = b.path("lib/zurl-rtsp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-net", .module = net },
        },
    });
    addModuleTests(b, test_step, rtsp);

    const zurl = b.addModule("zurl", .{
        .root_source_file = b.path("lib/zurl.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-stream", .module = stream },
            .{ .name = "zurl-tls", .module = tls },
            .{ .name = "zurl-http", .module = http },
        },
    });
    addModuleTests(b, test_step, zurl);

    addCli(b, test_step, target, optimize, core, stream, http, tls, .{
        .file = file,
        .dict = dict,
        .gopher = gopher,
        .tftp = tftp,
        .ftp = ftp,
        .pop3 = pop3,
        .imap = imap,
        .smtp = smtp,
        .ws = ws,
        .telnet = telnet,
        .sftp = sftp,
        .scp = scp,
        .ldap = ldap,
        .mqtt = mqtt,
        .rtsp = rtsp,
    }, zurl);
    addVendorCheck(b, test_step);

    // Last, because it reads the map every `addModule` above fills in.
    addPackageCheck(b, test_step, target, optimize);
}

/// Every module name a project outside this repository may ask for.
///
/// A consumer reaches a module with `dep.module(name)`, which reads the map
/// `b.addModule` fills in. A name that leaves that map breaks every
/// consumer and breaks no test here, because a test inside this repository
/// holds the module in a local variable instead.
const exported_modules = [_][]const u8{
    "zurl",
    "zurl-core",
    "zurl-stream",
    "zurl-tls",
    "zurl-net",
    "zurl-http",
    "zurl-hpack",
    "zurl-h2",
    "zurl-h3",
    "zurl-quic",
    "zurl-quic-tls",
    "zurl-qpack",
    "zurl-file",
    "zurl-dict",
    "zurl-gopher",
    "zurl-tftp",
    "zurl-ftp",
    "zurl-pop3",
    "zurl-imap",
    "zurl-smtp",
    "zurl-ws",
    "zurl-telnet",
    "zurl-ssh",
    "zurl-sftp",
    "zurl-scp",
    "zurl-ldap",
    "zurl-mqtt",
    "zurl-rtsp",
};

/// The paths `build.zig` reads for itself, whatever modules it exports.
///
/// A consumer runs this build file, so a package that ships without these
/// fails at configure time. They are written down because no module's root
/// source file names them.
const build_time_paths = [_][]const u8{
    // This file, and the manifest a consumer reads to find it.
    "build.zig",
    "build.zig.zon",
    // `addCaBundle`, `addPublicSuffixList`, `addVendorCheck`, and this
    // function all run a tool from here.
    "tools",
    // `addCli` builds the program from here.
    "src",
};

/// Adds `zig build check-package`, which fails when this package stops
/// being importable by a project outside this repository.
///
/// **Two failures break every consumer and no test.** A module that is
/// never passed to `b.addModule` is not in the map `dep.module(name)`
/// reads, and a directory that is missing from the `.paths` of
/// `build.zig.zon` is not copied into the package a consumer fetches. In
/// both cases every test here still passes, because a test builds from the
/// working tree and reaches each module through a local variable.
///
/// So this step does two things and nothing else:
///
/// 1. It looks every name of `exported_modules` up in the map, the way a
///    consumer does, and builds `tools/package_consumer.zig` against the
///    two a consumer starts from. That file names `Client.perform`,
///    `Diagnostics`, and `errors.curlCode`, so a public name that goes
///    away fails the compile.
/// 2. It runs `tools/check_package.zig` over the manifest, with the
///    directory of every exported module's root source file and the paths
///    this build file reads for itself.
///
/// **A build step and not a test**, because neither failure can be seen
/// from inside a test binary: a test already holds the module, and a test
/// cannot know which files the package ships. The check needs the build
/// graph and the manifest, which only a step has.
///
/// It runs under `zig build test` as well. A guard that runs only when
/// somebody types its name reports the break after the consumer found it.
fn addPackageCheck(
    b: *std.Build,
    test_step: *std.Build.Step,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const step = b.step("check-package", "Check that this package is importable from outside");

    for (exported_modules) |name| {
        if (b.modules.get(name) != null) continue;
        const fail = b.addFail(b.fmt(
            "check-package: the module '{s}' is not exported, so no project outside this repository can import it",
            .{name},
        ));
        step.dependOn(&fail.step);
        test_step.dependOn(&fail.step);
    }

    // The two a consumer starts from. They are looked up here rather than
    // passed in, because the lookup is the half of the check that a local
    // variable would hide.
    const front = b.modules.get("zurl");
    const core = b.modules.get("zurl-core");
    if (front != null and core != null) {
        const consumer = b.createModule(.{
            .root_source_file = b.path("tools/package_consumer.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zurl", .module = front.? },
                .{ .name = "zurl-core", .module = core.? },
            },
        });
        const run_consumer = b.addRunArtifact(b.addTest(.{ .root_module = consumer }));
        run_consumer.skip_foreign_checks = true;
        step.dependOn(&run_consumer.step);
        test_step.dependOn(&run_consumer.step);
    }

    const tool = b.createModule(.{
        .root_source_file = b.path("tools/check_package.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    });
    // The tool's own tests read the real manifest, so the check of the
    // scanner and the check of this repository are one run.
    tool.addAnonymousImport("zurl_manifest", .{ .root_source_file = b.path("build.zig.zon") });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = tool })).step);

    const exe = b.addExecutable(.{ .name = "check-package", .root_module = tool });
    const run = b.addRunArtifact(exe);
    run.addFileArg(b.path("build.zig.zon"));

    // A short list in the order it was built, so the command line this
    // step runs is the same on every configure. A linear search is enough
    // for the handful of directories a module root can sit in.
    var wanted: std.ArrayList([]const u8) = .empty;
    for (build_time_paths) |path| appendOnce(b, &wanted, path);
    for (b.modules.values()) |module| {
        const source = module.root_source_file orelse continue;
        const sub_path = switch (source) {
            .src_path => |src| src.sub_path,
            else => continue,
        };
        const end = std.mem.indexOfScalar(u8, sub_path, '/') orelse sub_path.len;
        appendOnce(b, &wanted, sub_path[0..end]);
    }
    for (wanted.items) |path| run.addArg(path);

    step.dependOn(&run.step);
    test_step.dependOn(&run.step);
}

/// Every protocol package a build carries, as one value.
///
/// A struct and not four parameters, because `addCli` takes them as a
/// group and a list of four modules in a row is a list nobody reads. A new
/// protocol package adds one field here and one row at each of the two
/// import lists inside `addCli`.
const Protocols = struct {
    file: *std.Build.Module,
    dict: *std.Build.Module,
    gopher: *std.Build.Module,
    tftp: *std.Build.Module,
    ftp: *std.Build.Module,
    pop3: *std.Build.Module,
    imap: *std.Build.Module,
    smtp: *std.Build.Module,
    ws: *std.Build.Module,
    telnet: *std.Build.Module,
    sftp: *std.Build.Module,
    scp: *std.Build.Module,
    ldap: *std.Build.Module,
    mqtt: *std.Build.Module,
    rtsp: *std.Build.Module,
};

/// The upstream file that `lib/zurl-tls/Client.zig` is a copy of, under the
/// library directory of the Zig that runs this build.
const vendored_upstream = "std/crypto/tls/Client.zig";

/// The copy that zurl keeps.
const vendored_copy = "lib/zurl-tls/Client.zig";

/// Adds `zig build check-vendor`, which fails when the vendored TLS client
/// differs from upstream on a line that carries no `ZURL PATCH` comment.
///
/// The fork stays a delta only while every re-sync is mechanical. Nothing but
/// this step enforces that, so a change made and not marked would be found by
/// the next person to copy a new upstream file over it, which is exactly when
/// it costs the most.
///
/// The upstream path comes from `b.graph.zig_lib_directory`, which the build
/// runner fills in from the Zig executable that started it. A path written
/// down here would name one build of Zig and would be wrong after the next
/// update.
///
/// The tool tests run under `zig build test` as well, because the check is
/// only worth its output while its own comparison is right.
///
/// The comparison itself runs under `zig build test` too. A guard that runs
/// only when somebody types its name is a guard that reports drift on the day
/// the drift is most expensive. The cost is that a test run needs the library
/// directory of the Zig that runs it, and the `addFail` arm below is what a
/// Zig that names none gets: a failure that says so, rather than a test run
/// that passes because it compared nothing.
fn addVendorCheck(b: *std.Build, test_step: *std.Build.Step) void {
    const tool = b.createModule(.{
        .root_source_file = b.path("tools/check_vendor.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    });

    const tool_tests = b.addTest(.{ .root_module = tool });
    test_step.dependOn(&b.addRunArtifact(tool_tests).step);

    const step = b.step("check-vendor", "Check the vendored TLS client against upstream");

    const exe = b.addExecutable(.{ .name = "check-vendor", .root_module = tool });
    const run = b.addRunArtifact(exe);

    const lib_dir = b.graph.zig_lib_directory.path orelse {
        // The build runner knows where the standard library is, so this is a
        // Zig that was built to carry it somewhere this step cannot name. The
        // step fails with that reason rather than passing on no comparison.
        const fail = b.addFail(
            "check-vendor: this Zig gives no library directory, so the upstream file cannot be found",
        );
        step.dependOn(&fail.step);
        test_step.dependOn(&fail.step);
        return;
    };
    run.addArg(b.pathJoin(&.{ lib_dir, vendored_upstream }));
    run.addFileArg(b.path(vendored_copy));

    step.dependOn(&run.step);
    test_step.dependOn(&run.step);
}

/// Builds the `zurl` executable and installs it, then wires up its own
/// tests.
///
/// The executable and its tests share one root file, `src/main.zig`, but
/// not one `Module`: the test module carries two extra imports, and the
/// shipped binary carries neither.
///
/// `build_options` names the installed binary's path, which the tests
/// spawn. `zurl-http` gives the tests `test_server`, the loopback HTTP
/// fixture the library's own tests use, and `zurl-tls` gives them
/// `test_server` as well, which is the loopback TLS one. No test reaches
/// the network, and the CLI itself talks to a server only through `zurl`,
/// so the binary needs none of those imports. A `const` in `src/main.zig`
/// that names one sits in the test section, and Zig analyses it only in a
/// test build.
///
/// `zurl-stream` goes to both modules. `-w` reports the size, the rate,
/// and the time of a transfer, and `zurl-stream.Speedometer` is the one
/// place that counts all three. The binary needs it, so it is not a test
/// import.
///
/// Every protocol package goes to both too. The CLI is what decides which
/// protocol packages this program speaks: it holds one `Fetchers` beside
/// each `Client` and registers each one. `zurl` itself imports no protocol
/// package, so leaving a package out of these two lists, out of
/// `run.Fetchers`, and out of `run.registerProtocols` is all it takes to
/// build a zurl without that protocol.
fn addCli(
    b: *std.Build,
    test_step: *std.Build.Step,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    core: *std.Build.Module,
    stream: *std.Build.Module,
    http: *std.Build.Module,
    tls: *std.Build.Module,
    protocols: Protocols,
    zurl: *std.Build.Module,
) void {
    const cli_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-stream", .module = stream },
            .{ .name = "zurl-file", .module = protocols.file },
            .{ .name = "zurl-dict", .module = protocols.dict },
            .{ .name = "zurl-gopher", .module = protocols.gopher },
            .{ .name = "zurl-tftp", .module = protocols.tftp },
            .{ .name = "zurl-ftp", .module = protocols.ftp },
            .{ .name = "zurl-pop3", .module = protocols.pop3 },
            .{ .name = "zurl-imap", .module = protocols.imap },
            .{ .name = "zurl-smtp", .module = protocols.smtp },
            .{ .name = "zurl-ws", .module = protocols.ws },
            .{ .name = "zurl-telnet", .module = protocols.telnet },
            .{ .name = "zurl-sftp", .module = protocols.sftp },
            .{ .name = "zurl-scp", .module = protocols.scp },
            .{ .name = "zurl-ldap", .module = protocols.ldap },
            .{ .name = "zurl-mqtt", .module = protocols.mqtt },
            .{ .name = "zurl-rtsp", .module = protocols.rtsp },
            .{ .name = "zurl", .module = zurl },
        },
    });
    const cli = b.addExecutable(.{ .name = "zurl", .root_module = cli_module });
    const install_cli = b.addInstallArtifact(cli, .{});
    b.getInstallStep().dependOn(&install_cli.step);

    // The binary's own tests spawn it as a subprocess, so they need its
    // installed path. `getInstallPath` is known at configure time; a
    // build option bakes it into the test binary, and never into `cli`
    // itself.
    const cli_test_options = b.addOptions();
    cli_test_options.addOption([]const u8, "exe_path", b.getInstallPath(.bin, "zurl"));

    const cli_test_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zurl-core", .module = core },
            .{ .name = "zurl-stream", .module = stream },
            .{ .name = "zurl-file", .module = protocols.file },
            .{ .name = "zurl-dict", .module = protocols.dict },
            .{ .name = "zurl-gopher", .module = protocols.gopher },
            .{ .name = "zurl-tftp", .module = protocols.tftp },
            .{ .name = "zurl-ftp", .module = protocols.ftp },
            .{ .name = "zurl-pop3", .module = protocols.pop3 },
            .{ .name = "zurl-imap", .module = protocols.imap },
            .{ .name = "zurl-smtp", .module = protocols.smtp },
            .{ .name = "zurl-ws", .module = protocols.ws },
            .{ .name = "zurl-telnet", .module = protocols.telnet },
            .{ .name = "zurl-sftp", .module = protocols.sftp },
            .{ .name = "zurl-scp", .module = protocols.scp },
            .{ .name = "zurl-ldap", .module = protocols.ldap },
            .{ .name = "zurl-mqtt", .module = protocols.mqtt },
            .{ .name = "zurl-rtsp", .module = protocols.rtsp },
            .{ .name = "zurl", .module = zurl },
            .{ .name = "zurl-http", .module = http },
            // The loopback TLS server, for the end to end tests of `-k`
            // and of the trust store. The shipped binary links neither
            // this nor `zurl-http`: both go to the test module alone.
            .{ .name = "zurl-tls", .module = tls },
            .{ .name = "build_options", .module = cli_test_options.createModule() },
        },
    });
    const cli_tests = b.addTest(.{ .root_module = cli_test_module });
    const run_cli_tests = b.addRunArtifact(cli_tests);
    run_cli_tests.skip_foreign_checks = true;
    // The tests spawn the installed binary, so it must exist first.
    run_cli_tests.step.dependOn(&install_cli.step);
    test_step.dependOn(&run_cli_tests.step);
}

/// Runs `tools/certdata2pem.zig` over NSS's `certdata.txt`, and returns the
/// generated PEM. `zurl-tls` embeds it under the name `ca_bundle_pem`, so a
/// static zurl carries its own trust roots and needs no filesystem.
///
/// The bundle is always generated and always embedded. There is no build
/// option to skip this: a build option here would let somebody build a
/// zurl that verifies nothing.
///
/// The generator's own tests run under `zig build test` too. A generator
/// with no tests of its own is how a silently empty bundle ships.
fn addCaBundle(b: *std.Build, test_step: *std.Build.Step) std.Build.LazyPath {
    const generator = b.createModule(.{
        .root_source_file = b.path("tools/certdata2pem.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = generator })).step);

    const nss = b.dependency("nss", .{});
    const exe = b.addExecutable(.{ .name = "certdata2pem", .root_module = generator });
    const run = b.addRunArtifact(exe);
    run.addFileArg(nss.path("lib/ckfw/builtins/certdata.txt"));
    const ca_pem = run.addOutputFileArg("ca-bundle.pem");

    // The bundle is not installed. `zurl-tls` embeds it, so the binary
    // carries its own trust roots and a copy on disk gives nothing.
    return ca_pem;
}

/// Appends `path` to `list`, unless it is already there.
fn appendOnce(b: *std.Build, list: *std.ArrayList([]const u8), path: []const u8) void {
    for (list.items) |item| {
        if (std.mem.eql(u8, item, path)) return;
    }
    list.append(b.allocator, path) catch @panic("out of memory");
}

/// Runs `tools/psl2bin.zig` over the public suffix list, and returns the
/// compact table it writes. `zurl-core` embeds it under the name
/// `psl_data`, so a static zurl carries the suffix rules and needs no
/// filesystem and no libpsl.
///
/// The table is always generated and always embedded. There is no build
/// option to skip this, for the reason `addCaBundle` has none: a build
/// option here would let somebody build a zurl that lets one site set a
/// cookie for every site under a suffix.
///
/// `lib/zurl-core/psl/format.zig` goes to the generator as a module, so the
/// writer and the reader of the table are one file. A second copy of
/// either half would be a second place for the layout to drift.
///
/// The generator's own tests run under `zig build test` too. A generator
/// with no tests of its own is how a silently empty list ships. The
/// generator also reads its own output back before it writes the file, and
/// refuses a list that holds too few rules to be the list.
fn addPublicSuffixList(b: *std.Build, test_step: *std.Build.Step) std.Build.LazyPath {
    const table_format = b.createModule(.{
        .root_source_file = b.path("lib/zurl-core/psl/format.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    });
    const generator = b.createModule(.{
        .root_source_file = b.path("tools/psl2bin.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
        .imports = &.{.{ .name = "psl-format", .module = table_format }},
    });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = generator })).step);

    const list = b.dependency("public_suffix_list", .{});
    const exe = b.addExecutable(.{ .name = "psl2bin", .root_module = generator });
    const run = b.addRunArtifact(exe);
    run.addFileArg(list.path("public_suffix_list.dat"));

    // The table is not installed. `zurl-core` embeds it, so the binary
    // carries the rules and a copy on disk gives nothing.
    return run.addOutputFileArg("public-suffix-list.bin");
}

/// Adds a test run for `module` to `test_step`.
///
/// A build for a different target analyses every declaration and skips only
/// the run. `zig build test -Dtarget=aarch64-macos` therefore compiles each
/// module for Darwin instead of failing the whole build on the first module.
fn addModuleTests(b: *std.Build, test_step: *std.Build.Step, module: *std.Build.Module) void {
    const tests = b.addTest(.{ .root_module = module });
    const run = b.addRunArtifact(tests);
    run.skip_foreign_checks = true;
    test_step.dependOn(&run.step);
}
