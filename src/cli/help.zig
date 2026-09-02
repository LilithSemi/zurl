//! zurl: the text `--help` prints.
//!
//! This file owns one sentence and one list: what zurl is, which flags
//! this build accepts, and what each accepted flag does not do. It is the
//! contract a user reads before they run anything.
//!
//! It owns no behaviour. A flag named here is a flag `src/cli/Args.zig`
//! parses and `src/cli/run.zig` honours, and a limitation named here is
//! one of those two files' own. A line added here without the code behind
//! it is a promise zurl does not keep, so the "Known limitations" block
//! grows whenever a flag is accepted and does less than curl's.
//!
//! `src/main.zig` calls `print` for `--help` alone, as the first argument
//! and nowhere else. The last line of the block below says so.
//!
//! **The options block is not written here. It is rendered from
//! `Args.flag_table`, the same table the parser reads.** A flag with two
//! spellings therefore shows two spellings, and a flag the parser does not
//! accept cannot appear at all. That is not tidiness: `-o`, `-O`, and `-D`
//! were once short forms with no long form, and the help lines that showed
//! only the short spelling were what made the gap look deliberate for as
//! long as it lasted. One table, read twice, cannot say two things.

const std = @import("std");
const Args = @import("Args.zig");
const Io = std.Io;

/// The column the one-line description starts in.
///
/// Wide enough for the longest spelling pair and argument the table holds.
/// A row wider than this still prints whole, with two spaces before its
/// description, so a new flag with a long name reads badly and never
/// wrongly.
const description_column: usize = 28;

/// Writes the whole help text to `w`.
pub fn print(w: *Io.Writer) !void {
    try w.writeAll(
        \\Usage: zurl [options] <url>...
        \\       zurl --version
        \\       zurl --help
        \\
        \\zurl is a pure-Zig replacement for curl. It is not finished: the
        \\flags below are the ones this build accepts. A response body goes
        \\to standard output unless -o or -O names a file.
        \\
        \\This build speaks http://, https://, file://, dict://, gopher://,
        \\gophers://, tftp://, ftp://, ftps://, pop3://, pop3s://, imap://,
        \\imaps://, smtp://, smtps://, ws://, wss://, telnet://, sftp://,
        \\scp://, ldap://, ldaps://, mqtt://, mqtts://, and rtsp://. A
        \\file:// url reads a local file, and its host must be empty or
        \\localhost, as in file:///etc/hosts.
        \\A redirect reaches only the protocols
        \\--proto-redir names. The default list is http, https, ftp, and
        \\ftps, so a redirect reaches no other protocol until the flag says
        \\it may, which curl treats as consent.
        \\
        \\Options:
        \\
    );

    for (Args.flag_table) |flag| try printFlag(w, flag);

    // `--version` and `--help` are the only two lines here that no row of
    // `Args.flag_table` produces. `src/main.zig` reads both out of argv
    // itself, before any parse, so the parser never sees either one and
    // neither belongs in a table the parser drives.
    try w.writeAll(
        \\  -V, --version            Print the version and exit.
        \\  -h, --help               Print this help and exit.
        \\
    );

    try w.writeAll(
        \\
        \\Known limitations in this build:
        \\  Only http://, https://, and rtsp:// report a response head.
        \\  An rtsp reply has a real status line and header block, so
        \\  there is nothing to invent. Every other protocol reports
        \\  none, so -D and -I write no file and fail
        \\  that url with 4, and -i writes no head there. curl invents a
        \\  head for some of them: Content-Length, Accept-ranges, and
        \\  Last-Modified for a file:// url, and a SIZE and an MDTM for
        \\  -I on an ftp:// url. -v shows the same gap: it prints the
        \\  effective url and any recovered fault, and none of the command
        \\  dialogue that curl -v shows for ftp and the mail protocols.
        \\  zurl reports the status 000 for a file:// transfer, which
        \\  is what curl reports for %{http_code} there. A directory reads
        \\  as a body of no bytes, which is what curl does too.
        \\  -x and the proxy environment variables reach http:// and
        \\  https:// alone. A url of any other scheme beside -x, a
        \\  --socks flag, or all_proxy is refused with 4, rather than
        \\  dialled direct after the user asked for a proxy. --noproxy
        \\  names the hosts that are meant to be reached direct.
        \\  smtp:// and smtps:// send no AUTH command, so -u and a url
        \\  userinfo are refused with 4 rather than send the message with
        \\  no credential.
        \\  dict:// looks a word up, RFC 2229, on port 2628.
        \\  dict://host/d:word runs DEFINE, dict://host/m:word runs MATCH,
        \\  and dict://host/d:word:database:n and
        \\  dict://host/m:word:database:strategy:n name the rest. A path
        \\  that names neither is sent as the command line itself, with
        \\  each colon turned into a space, so dict://host/SHOW:DB works.
        \\  Every byte the server sends reaches standard output, the RFC
        \\  2229 status lines included, which is what curl writes too.
        \\  gopher:// and gophers:// fetch one selector, RFC 1436, on port
        \\  70. The selector is the url path with the leading slash and the
        \\  item type dropped, so gopher://host/0/f.txt asks for /f.txt. A
        \\  tab in the path reaches the wire, which is what a type 7 search
        \\  needs. gophers:// verifies the peer certificate exactly as
        \\  https:// does, and -k is the one flag that turns that off.
        \\  tftp:// downloads one file over UDP, RFC 1350, on port 69. The
        \\  read request carries the same tsize, blksize, and timeout
        \\  options curl sends by default. This build has no
        \\  --tftp-blksize and no --tftp-no-options, and it uploads
        \\  nothing: a tftp:// url with -T is not a write request.
        \\  ftp:// downloads one file or lists one directory, RFC 959, on
        \\  port 21. A url that ends in a slash is a listing, and every
        \\  other url names a file. Each directory of the path is its own
        \\  CWD, which is curl's own default method. The login is anonymous
        \\  unless -u, the url userinfo, or a netrc entry names a
        \\  credential, and the three are read in that order, which is
        \\  curl's. -C sends REST. -l sends NLST instead of LIST.
        \\  ftp:// is passive only. zurl sends EPSV, and PASV when the
        \\  server refuses it. There is no -P/--ftp-port and no active
        \\  mode: that would ask zurl to listen for an inbound connection.
        \\  The address a PASV answer names is never dialed. The data
        \\  connection goes to the host the url named, because the address
        \\  in the answer is written by the server and a hostile one could
        \\  point zurl at any machine at all. curl does the same by
        \\  default, and zurl has no --no-ftp-skip-pasv-ip to change it.
        \\  ftps:// is implicit TLS on port 990, which is what curl does.
        \\  --ssl-reqd puts TLS on an ftp:// control connection with
        \\  AUTH TLS instead, RFC 4217, and a server that refuses ends the
        \\  transfer with 64 and no credential sent. Either way PBSZ 0 and
        \\  PROT P go out after the login, so the data connection is inside
        \\  the same session and verifies the same certificate. There is no
        \\  --ssl, which would carry on in the clear after a refusal.
        \\  -r on an ftp:// url answers the open ended form alone, such as
        \\  -r 4-, which is one REST. A range with an end, such as -r 5-15,
        \\  and the last-n form, such as -r -100, are refused with 33
        \\  before any command goes out: RFC 959 has no command that says
        \\  where to stop, and curl answers those by cutting the data
        \\  connection early and sending ABOR to recover.
        \\  ftp:// does not upload, so -T on one is not a STOR. It sends no
        \\  PWD, no MDTM, and no ACCT, and it has no --ftp-method,
        \\  --ftp-create-dirs, --ftp-pret, --ftp-account, or --ftp-ssl-ccc.
        \\  A ;type=a or ;type=i suffix is part of the file name here,
        \\  where curl reads it and sets the transfer type.
        \\  pop3:// with no path sends LIST and reads the whole list.
        \\  pop3://host/1 sends RETR 1 and writes the message out, with the
        \\  doubled period RFC 1939 asks a sender to add taken off again.
        \\  A login happens only when -u, the url userinfo, or a netrc
        \\  entry names a credential, which is what curl does. A greeting
        \\  that offers APOP gets an APOP login, so the password stays off
        \\  the network. A --ssl-reqd session never uses APOP: its
        \\  timestamp arrives before the handshake, where anybody on the
        \\  path could have written it. A greeting with no APOP draws one
        \\  CAPA, whose SASL line names the mechanisms. A server that
        \\  names none gets USER and PASS, where curl ends the transfer
        \\  with 67.
        \\  imap:// with no path sends LIST "" *. imap://host/INBOX lists
        \\  under that mailbox, and imap://host/INBOX;UID=1 sends SELECT
        \\  and then UID FETCH 1 BODY[]. ;MAILINDEX= sends a plain FETCH,
        \\  because a mail index and a UID are different numbers. Those two
        \\  are the only url parameters zurl reads: a url naming ;SECTION=
        \\  or ;PARTIAL= is refused with 3 rather than answered in part.
        \\  A mailbox name that is not an atom goes out inside quotes with
        \\  every " and \ escaped, so a name can never close its own
        \\  argument. The capability list of the greeting is what names
        \\  the SASL mechanisms, so CAPABILITY goes out only when the
        \\  greeting carries none, and zurl's tags run one lower than
        \\  curl's on every server that names them. A server that names
        \\  LOGINDISABLED and no mechanism zurl speaks ends the transfer
        \\  with 67 and sends no LOGIN, where curl sends one anyway.
        \\  smtp:// sends a message. --mail-from names the sender, each
        \\  --mail-rcpt names one recipient, and the message comes from -T
        \\  or from -d. A transfer with no recipient, or with no message,
        \\  is refused with 3 before any socket, where curl sends VRFY for
        \\  a transfer with no upload. One refused recipient ends the
        \\  transfer, where curl carries on with the rest. The url path is
        \\  the EHLO name, and a url that names none sends localhost,
        \\  where curl sends the name of this machine. HELO goes out when
        \\  the server does not know EHLO.
        \\  A CR or an LF in --mail-from or in --mail-rcpt is refused with
        \\  3 before any socket. curl 8.21.0 sends it, and the second line
        \\  reaches the server as another RCPT TO, so the message goes to
        \\  somebody the command line never named.
        \\  A message body line of one period is sent doubled, RFC 5321
        \\  section 4.5.2, and a bare line feed is read as a line ending
        \\  and sent as CRLF. curl stuffs only after a CRLF, so a message
        \\  written with bare line feeds ends early there and the rest of
        \\  it reaches the server as commands. The SIZE= of MAIL FROM
        \\  therefore counts the stuffed octets and not the file.
        \\  --ssl-reqd puts TLS on a pop3, imap, or smtp connection with
        \\  STLS or STARTTLS before the login, and a server that refuses
        \\  ends the transfer with 64 and no credential and no message
        \\  sent. pop3s://, imaps://, and smtps:// are implicit TLS on 995,
        \\  993, and 465.
        \\  All three speak SASL. The mechanisms are OAUTHBEARER, XOAUTH2,
        \\  CRAM-MD5, PLAIN, and LOGIN, and the strongest one the server
        \\  offers is the one used, which is curl's own order. OAUTHBEARER
        \\  and XOAUTH2 need --oauth2-bearer and the rest need -u.
        \\  CRAM-MD5 keeps the password off the network, so it wins
        \\  whenever a server offers it.
        \\  On a connection with no TLS the credential goes out in the
        \\  clear when PLAIN or LOGIN is all a server offers, which is what
        \\  curl does. --ssl-reqd is the flag that demands TLS first, and
        \\  it stops the transfer with 64 rather than send the credential.
        \\  --login-options AUTH=<mechanism> names one mechanism and fails
        \\  rather than use another. --sasl-ir saves one round trip.
        \\  --sasl-authzid names the identity to act as, and only PLAIN
        \\  carries one.
        \\  A NUL, a CR, an LF, or a byte a SASL message reads as a field
        \\  separator is refused in the user name, the password, the
        \\  authzid, and the token, before any of them is encoded. Base64
        \\  would otherwise hide such a byte from the command line check.
        \\  smtp refuses the transfer with 67 when a server offers no
        \\  mechanism zurl speaks, where curl sends the message with no
        \\  credential at all. imap and pop3 fall back to LOGIN and to
        \\  USER and PASS, which is what they always sent.
        \\  -X on a mail url is the whole command line and not an HTTP
        \\  method, so -X 'TOP 1 0' and -X 'FETCH 1 BODY[HEADER]' each go
        \\  out as written. On any other url -X still names a method, and
        \\  a value that is not one is refused with 2.
        \\  ws:// and wss:// open a WebSocket, RFC 6455, on ports 80 and
        \\  443. The transfer starts as one HTTP/1.1 GET with an Upgrade
        \\  line and a Sec-WebSocket-Key of 16 random octets. The server's
        \\  Sec-WebSocket-Accept must be the SHA-1 of that key and the GUID
        \\  of the RFC, in base64, and a value that is not is refused with
        \\  8: without that check the handshake proves nothing.
        \\  zurl then reads. The payload of every text and binary frame
        \\  goes to the output, joined, a ping is answered with a pong, and
        \\  a close is answered with a close. Nothing else goes out, so -d
        \\  on a ws:// url sends no frame, which is what curl's own tool
        \\  does. Every frame zurl writes is masked with a 32-bit key drawn
        \\  again for each frame, RFC 6455 section 5.3, and a masked frame
        \\  from the server is refused with 8. There is no --ws-options.
        \\  The whole answer is bounded at 16 MB, and a frame that declares
        \\  more than the room left is refused with 63 before one octet of
        \\  it is read. zurl offers no subprotocol and no extension, and an
        \\  answer that names either is refused with 8.
        \\  A 3xx on the handshake is followed only with -L, and only into
        \\  a scheme --proto-redir names. The default list does not name ws
        \\  or wss, so --proto-redir +ws is what lets one through. Only an
        \\  absolute target, a //host/path, or a /path is followed: a bare
        \\  relative target is refused with 3 rather than guessed at.
        \\  wss:// verifies the peer certificate exactly as https:// does,
        \\  against the same trust store, and its ALPN offer names
        \\  http/1.1 alone because RFC 9113 has no such upgrade.
        \\  telnet:// opens a session, RFC 854, on port 23. It writes what
        \\  -d or -T names and reads until the peer closes. Every octet of
        \\  255 in what it sends is doubled, RFC 854's IAC escape, so a
        \\  body holding FF FD 18 reaches the peer as data and not as an
        \\  IAC DO TERMINAL-TYPE it never asked for. On the way in a
        \\  doubled 255 is halved again and every command is taken out, so
        \\  the output holds the data octets alone, which is what curl
        \\  writes. Option negotiation is answered the way curl answers it:
        \\  nothing goes out until the peer negotiates first, and then the
        \\  answer is followed once by WILL BINARY, DO BINARY, WILL SGA,
        \\  and DO SGA. There is no -t/--telnet-option, so TERMINAL-TYPE,
        \\  XDISPLOC, and NEW-ENVIRON are refused. curl relays standard
        \\  input with no flag at all, where zurl sends what -d or -T
        \\  names, so -T - is the flag that relays standard input.
        \\  sftp:// transfers a file over SSH, on port 22, with version 3
        \\  of the SSH file transfer protocol, which is the version
        \\  OpenSSH speaks. A url that ends in a slash lists a directory,
        \\  and -l lists the names alone. -T uploads.
        \\  scp:// transfers one file over SSH on the same port, and it is
        \\  a different thing: it runs the scp binary on the far side and
        \\  speaks the old rcp protocol to it. zurl wraps the path in
        \\  single quotes and writes every quote inside it as '"'"', so a
        \\  path holding a semicolon, a backtick, or a $( reaches the far
        \\  side as a file name and never as a command. A path with a NUL
        \\  in it is refused. There is no recursion, no listing, and no
        \\  -C: prefer sftp://, which does all three.
        \\  The host key decides whether an sftp or an scp transfer runs
        \\  at all. A host that ~/.ssh/known_hosts does not name is
        \\  refused with 60,
        \\  and so is a host whose key is on record and different: that
        \\  second one may be somebody in the middle, and zurl never
        \\  updates the record on its own. zurl has nobody to prompt, so
        \\  there is no "yes" to type. --knownhosts names another file.
        \\  --hostpubsha256 pins one key by the text ssh-keygen -l prints
        \\  after SHA256:, and --hostpubmd5 pins it by an MD5 digest,
        \\  which is weaker and is there because curl carries the flag. A
        \\  pin answers on its own and no file is read.
        \\  -k skips the host key check for sftp:// and scp:// the way it
        \\  skips a certificate check for https://, and it is the only
        \\  thing that does. The connection stays encrypted and it is no longer to a
        \\  host anybody identified, so anyone in the path can read and
        \\  change every byte of it.
        \\  An ssh login signs with an ed25519 key under ~/.ssh, or sends
        \\  the password from the url or from -u. RSA and ECDSA keys are
        \\  refused by name, because this build carries no verifier for
        \\  either. There is no passphrase prompt, so an encrypted key
        \\  with no passphrase given is refused by name. SSH has no
        \\  anonymous account: a url that names no user falls back to
        \\  LOGNAME or USER, and a transfer with no name at all is
        \\  refused.
        \\  ldap:// searches a directory, on port 389, and ldaps:// does
        \\  the same inside TLS on port 636. --ssl-reqd puts StartTLS on
        \\  an ldap:// connection before the bind, and a server that
        \\  refuses it is 64 with no credential sent. The url is
        \\  ldap://host/dn?attributes?scope?filter: the scope is base,
        \\  one, or sub, and it is base when the url names none. -u is
        \\  the bind name and password, and the name is a distinguished
        \\  name such as cn=admin,dc=example,dc=com. A url with no
        \\  credential still binds, anonymously, which is what curl does.
        \\  The answer is the text curl writes: DN: and then one tabbed
        \\  line for each value, with a value that is not printable ASCII
        \\  written after :: in base64. zurl base64s a value holding a
        \\  newline where curl writes it raw, so no value a server sends
        \\  can draw a line that reads like another entry. There is no
        \\  SASL, so a bind name holding ;AUTH= is refused with 4. A
        \\  referral names another server and zurl never follows one: it
        \\  reads past it and returns the entries the search did find,
        \\  where curl stops at the first one. Nothing here writes to a
        \\  directory.
        \\  mqtt:// publishes to or subscribes to one topic, MQTT 3.1.1,
        \\  on port 1883, and mqtts:// does the same inside TLS on port
        \\  8883, which verifies the peer exactly as https:// does. The
        \\  topic is the url path with the leading slash dropped, so
        \\  mqtt://broker/sensor/1 is the topic sensor/1, and a url with
        \\  no path is refused with 3. -d publishes and a url with no -d
        \\  subscribes. Everything is QoS 0: this build sends no
        \\  acknowledgement, so a broker that delivers above QoS 0 will
        \\  deliver again, and zurl says so rather than let that pass.
        \\  A subscribe prints each message the way curl does, which is
        \\  the two byte topic length and the topic in front of the
        \\  payload. A subscribe reads one message and ends, where curl
        \\  reads until you stop it: --mqtt-messages asks for more, up to
        \\  100000. --mqtt-client-id names the client id, which curl
        \\  draws at random and gives no way to set. A topic that holds a
        \\  NUL is refused with 3, and so is a + or a # in a topic being
        \\  published to, because both are wildcards and the message
        \\  would reach every topic under the pattern. curl sends all
        \\  three and exits 0 for a message the broker throws away.
        \\  rtsp:// sends one RTSP 1.0 request, RFC 2326, on port 554.
        \\  There is no rtsps://: that scheme belongs to RTSP 2.0, and
        \\  curl carries none either. The default request is OPTIONS *,
        \\  which is the whole of what curl's own command line can send.
        \\  -X and --rtsp-request name another: OPTIONS, DESCRIBE, SETUP,
        \\  PLAY, PAUSE, TEARDOWN, GET_PARAMETER, or SET_PARAMETER.
        \\  ANNOUNCE and RECORD are refused with 4, because both write to
        \\  the server. --rtsp-stream-uri names the request target, which
        \\  is how a SETUP names a track. --rtsp-session-id and
        \\  --rtsp-transport fill the two headers they name, and a SETUP
        \\  with no transport is refused with 3 rather than sent. -H and
        \\  -u reach the head, as they do in curl, and -u is a preemptive
        \\  Basic that answers no 401 challenge. -d fills the body of a
        \\  GET_PARAMETER or a SET_PARAMETER, and it is refused beside any
        \\  other method; curl sends -d nowhere for rtsp. The CSeq counts
        \\  from 1 and a reply carrying another number is 8, not ignored.
        \\  One run is one request, so a SETUP and the PLAY after it are
        \\  two runs and --rtsp-session-id carries the session between
        \\  them. There is no RTP or RTCP: a PLAY starts a stream on a
        \\  socket this build does not open. Interleaved binary data,
        \\  the $ framing of section 10.12, is not read: a frame that
        \\  arrives is 8 rather than read as a reply. No redirect is
        \\  followed. rtsp:// is the one protocol outside http and https
        \\  here that reports a response head, so -i and -D work on it.
        \\  A dict, gopher, tftp, or ftp answer has no length on the wire,
        \\  so zurl bounds each at 16 MB and reports 63 for one past it.
        \\  --max-filesize lowers that bound and never raises it. curl
        \\  keeps no bound of its own on any of the four.
        \\  --proto and --proto-redir name dict, gopher, gophers, and tftp
        \\  the way curl does, so --proto -all,gopher and
        \\  --proto-redir +gopher each do what the flag says. The default
        \\  --proto list permits all four, and the default --proto-redir
        \\  list reaches none of them.
        \\  -F sends a multipart/form-data body. n=value sends a literal,
        \\  n=@path uploads the file with a filename and a guessed type,
        \\  and n=<path sends the file content as the value. ;type= and
        \\  ;filename= name the two the part carries, and --form-string
        \\  reads its argument literally, with no @, no < and no ;. The
        \\  boundary is 22 random characters from the entropy of the
        \\  system, drawn again if a value already holds it. A file part
        \\  streams, so a form may carry a file larger than memory, and
        \\  the body always goes out with a Content-Length.
        \\  -F differs from curl in five places. A comma in a path is a
        \\  file list to curl, which sends a nested multipart/mixed part.
        \\  zurl sends no list and refuses the path. A parameter this
        \\  build does not read, ;encoder= and ;headers= among them, is
        \\  refused rather than dropped without a word. An empty ;type=
        \\  is refused, where curl sends a bare Content-Type line. -F
        \\  n=@- reads standard input whole, bounded at 16 MiB, and a
        \\  path that is not a regular file is refused, because a request
        \\  with a form announces its length. --form-escape writes a
        \\  quote and a backslash with a backslash in front, as curl
        \\  does, and it keeps a CR and an LF percent-encoded, which curl
        \\  does not: a newline written raw there forges a part header.
        \\  A form carries at most 64 parts, a field name and a file name
        \\  at most 1024 bytes each, and a type at most 256 bytes.
        \\  -d and its family join their arguments into one body with an
        \\  ampersand between them, and --json joins with nothing, so two
        \\  --json arguments build one document. -d @file reads a file and
        \\  drops every CR and LF in it, and --data-binary @file keeps
        \\  every byte. @- reads standard input the same two ways. A body
        \\  built this way is held in memory and is refused past 16 MiB;
        \\  use -T for anything larger, which streams the file and has no
        \\  such bound.
        \\  -T sends a file with a Content-Length and no Content-Type,
        \\  and -T - sends standard input with the chunked transfer
        \\  coding. zurl sends no Expect: 100-continue with a chunked
        \\  upload and starts writing the body at once, where curl asks
        \\  the server to answer 100 first. A chunked body cannot be sent
        \\  twice, so a 307, a 308, or a 401 challenge on such an upload
        \\  fails with 23 instead of sending a part of the body again.
        \\  -X names the method and outranks every other flag. Two flags
        \\  that each name a different method, such as -I with -d or -T
        \\  with -d, exit 2, which is what curl does. -G moves the -d data
        \\  into the url query and sends no body.
        \\  A redirect that zurl follows drops the request body on a 301,
        \\  a 302, and a 303, and asks for the target with GET; a 307 and
        \\  a 308 keep the method and the body. One difference from curl:
        \\  curl -X POST -d ... -L through a 302 sends POST with no body,
        \\  because -X fixes the method text, and zurl sends GET. Both
        \\  drop the body.
        \\  -I asks for the head alone and writes it to standard output,
        \\  which is what curl does. A -D beside it still names its own
        \\  file.
        \\  -Z takes the run down to one transfer at a time when there is
        \\  a request body: one body serves every url and it has one
        \\  reader.
        \\  An underscored hostname is refused. curl accepts one. A
        \\  bracketed IPv6 host, such as http://[::1]:8080/, works, and an
        \\  address with a scope, such as http://[fe80::1%25eno1]/, does
        \\  not.
        \\  -D writes every response head of the transfer, one after the
        \\  other, which is what curl writes with -L. A redirect chain
        \\  larger than the engine's own limit writes no file at all and
        \\  fails, rather than write a part of the headers.
        \\  -O writes the url's last path segment exactly as the url wrote
        \\  it, escapes and all, never decoded. A url whose last path
        \\  segment names nothing, such as one ending in /, gets the name
        \\  curl_response instead, matching curl. Only a name that would
        \\  reach outside the working directory, or that carries a byte no
        \\  file name may hold, is refused.
        \\  -o and -O each cover one url, in the order they were given,
        \\  the way curl pairs them: -o a URL1 URL2 writes URL1 to a and
        \\  URL2 to standard output, and -o a -o b writes one file each.
        \\  A url past the last -o or -O goes to standard output. -D is
        \\  not paired: it names one file for the whole run, a later -D
        \\  replaces an earlier one, and every url appends its response
        \\  head to that file.
        \\  --proto and --proto-redir read curl's own list syntax: a comma
        \\  separated list where an entry may carry +, -, or =, and where
        \\  all names every protocol. Both read curl's whole list of
        \\  protocol names, which is more than this build speaks: a url
        \\  naming a protocol with no engine here still exits 1. A name
        \\  outside curl's list changes nothing, which is what curl does
        \\  with a name its own build lacks. A list that leaves no protocol
        \\  enabled is a usage fault and exits 2, which is also what curl
        \\  does. --proto starts from every name, and --proto-redir starts
        \\  from http,https,ftp,ftps, so a redirect
        \\  cannot reach file:// unless --proto-redir says it may.
        \\  --proto-default names the scheme for a url that carries none,
        \\  and it replaces the guess zurl makes otherwise: http for most
        \\  urls, and ftp for a host that starts ftp. A url that spells
        \\  its own scheme is untouched. A name outside http, https, file,
        \\  ftp, and ftps exits 1 before any transfer, and an empty name
        \\  exits 2, which is what curl does with each.
        \\  --proto-redir can permit a redirect into file://, and zurl
        \\  then follows it and reads the file, the way curl does. This
        \\  needs the flag: +file, =file, and all each ask for it, and the
        \\  default list still refuses such a redirect. --proto is not
        \\  read again for a redirect target; --proto-redir is the list
        \\  for those, which is how curl divides the two.
        \\  --tlsv1.2 and --tlsv1.3 set the lowest TLS version to keep.
        \\  This build speaks TLS 1.2 and TLS 1.3 and nothing older, so
        \\  --tlsv1, --tlsv1.0, and --tlsv1.1 are accepted and leave the
        \\  floor at TLS 1.2. curl here does the same: it accepts those
        \\  flags and its OpenSSL still refuses TLS 1.0 and TLS 1.1, so
        \\  such a server fails for both programs with 35.
        \\  --tls-max sets the highest TLS version to keep, and reads
        \\  default, 1.0, 1.1, 1.2, and 1.3. 1.3 and default change
        \\  nothing, because TLS 1.3 is already the ceiling. 1.2 narrows
        \\  the client hello, so a server that speaks both answers with
        \\  TLS 1.2 and the transfer runs. 1.0 and 1.1 are below the
        \\  floor, so no version is left: the flag is accepted and the
        \\  transfer fails with 35, which is what curl does too. A
        \\  --tlsv1.x above a --tls-max is a usage fault and exits 2,
        \\  before any socket, the way curl reports the same pair.
        \\  --compressed sends Accept-Encoding: deflate, gzip, zstd, and
        \\  decodes the answer before it writes it. Without the flag no
        \\  Accept-Encoding goes out at all, which is what curl does, so
        \\  both tools read the same octets off the same url. curl offers
        \\  br as well. This build does not, and it does not ask for br
        \\  either: brotli is not in the Zig standard library, so a
        \\  decoder would be a new dependency, and its static dictionary
        \\  alone is over 100 KiB against a 2.6 MB stripped binary. zstd
        \\  needed no new dependency at all and cost 86 KiB, measured.
        \\  A client that asks for a coding it cannot read gets octets it
        \\  must then refuse, which is worse than never asking. Under
        \\  --compressed a coding this build cannot decode stops the
        \\  transfer with 61, because the flag promised the body and
        \\  compressed octets are not it. Without the flag the
        \\  Content-Encoding header is ignored and the peer's own octets
        \\  are written out, which is what curl does with an unsolicited
        \\  one. --compressed counts the decoded octets in
        \\  %{size_download}, where curl counts the wire.
        \\  -k, --insecure turns off both halves of the certificate check:
        \\  the chain no longer has to reach a trusted root, and the
        \\  certificate no longer has to carry the host name of the url.
        \\  Anyone on the path can then read and rewrite the transfer, and
        \\  zurl cannot tell you that it happened. Only this flag reaches
        \\  that state. A handshake that fails to verify is reported with
        \\  60 and never tried again without the check, and a connection
        \\  opened under -k is never reused for a url that did not ask
        \\  for it.
        \\  -x, --proxy sends every request through a proxy. The scheme of
        \\  the proxy url picks the kind: http, https, socks4, socks4a,
        \\  socks5, and socks5h. A url with no scheme is an http proxy. An
        \\  http origin goes through an http proxy as one request that
        \\  names the whole url, and an https origin goes through a
        \\  CONNECT tunnel. socks5 resolves the host on this machine and
        \\  socks5h lets the proxy resolve it, which is the difference
        \\  between telling a local resolver every host you visit and
        \\  telling the proxy. -x "" turns proxying off, environment
        \\  variables included.
        \\  --socks4, --socks4a, --socks5, and --socks5-hostname each name
        \\  the proxy and the protocol together, so the text after them is
        \\  a host and a port and not a url.
        \\  -U, --proxy-user names the credential the proxy gets. It is
        \\  never sent to the origin server, and -u is never sent to the
        \\  proxy. In a CONNECT tunnel the origin's credential goes inside
        \\  the tunnel, so the proxy never reads it: the CONNECT itself is
        \\  cleartext even for an https url, and it carries the host, the
        \\  port, and the proxy credential and nothing else.
        \\  --proxy-basic is the default. --proxy-digest and
        \\  --proxy-anyauth are refused, and the run stops: this build
        \\  answers a proxy with Basic alone, and answering a Digest
        \\  challenge with Basic would put the password on the wire in
        \\  reversible base64 to a proxy that had offered a scheme where
        \\  the password never travels.
        \\  --noproxy lists the hosts that reach no proxy, and the
        \\  no_proxy environment variable holds the same list. An entry
        \\  matches a host equal to it and every host under it, so
        \\  example.com covers a.example.com. A leading dot changes
        \\  nothing. * is every host. A CIDR block such as 127.0.0.0/8
        \\  matches an address inside it. A port in an entry never
        \\  matches, which is what curl does.
        \\  zurl reads http_proxy, https_proxy, HTTPS_PROXY, all_proxy,
        \\  ALL_PROXY, no_proxy, and NO_PROXY. It does not read
        \\  HTTP_PROXY, and neither does curl: a CGI program takes a
        \\  client's Proxy: request header as HTTP_PROXY, so reading it
        \\  would let whoever sent the request choose the proxy.
        \\  --proxy-insecure, --proxy-cacert, and --proxy-capath answer for
        \\  the proxy's own certificate and for nothing else. An origin
        \\  behind a CONNECT tunnel is still verified against its own name
        \\  and the roots --cacert names, whatever these three say.
        \\  An https proxy carrying an https origin is not accepted in
        \\  this build: that needs a TLS session inside a TLS session. An
        \\  https proxy carrying an http origin runs.
        \\  --preproxy is not accepted. It chains a SOCKS proxy in front of
        \\  an HTTP one, which needs two dials in a row.
        \\  --location-trusted follows a redirect and sends the credential
        \\  to every host in the chain, including one the first server
        \\  chose. Without it, zurl withholds an Authorization and a
        \\  Cookie on every redirect it follows and says that it did,
        \\  which is stricter than curl: curl withholds them only when the
        \\  origin changes. A cookie of the jar is not that Cookie header:
        \\  the jar carries the domain of each cookie, so a jar cookie
        \\  crosses a redirect whenever its own domain rule allows it.
        \\  -b sends cookies and -c writes the jar out afterwards. A -b
        \\  value holding an = is cookie text and goes on the wire exactly
        \\  as typed. A value without an = names a Netscape jar file to
        \\  read, which is curl's own rule. A -H Cookie: replaces the -b
        \\  text.
        \\  Cookies are kept only when -b or -c asked for them, and -j
        \\  needs one of those two beside it, which is what curl does.
        \\  A response may set a cookie for its own host and for a domain
        \\  that host sits under, and for nothing else. zurl carries the
        \\  public suffix list, so it refuses a Domain of one label, such
        \\  as com, and a Domain that is a public suffix, such as co.uk or
        \\  github.io. A Domain equal to the host gives a host-only
        \\  cookie, which is curl 8.22.0's rule for an exact public-suffix
        \\  domain applied to every exact match. A jar file line naming a
        \\  public suffix with the subdomain column TRUE is dropped, where
        \\  curl reads it. A Domain zurl cannot represent, which is any
        \\  name with a byte over 127, is refused: zurl has no IDN and a
        \\  host reaches it as an A-label. A Secure cookie never crosses
        \\  plain http, except to the loopback, where curl sends it too.
        \\  A cookie lives at most 400 days, and a server asking for
        \\  longer gets 400 days, matching curl.
        \\  -m, --max-time bounds the whole transfer, where
        \\  --connect-timeout bounds the connect and the handshake alone.
        \\  A transfer that passes the bound exits 28 and keeps the bytes
        \\  that did arrive, which is what curl does. -m 0 asks for no
        \\  bound at all. A run that cannot start a second task says so
        \\  and goes on with no bound.
        \\  -C, --continue-at asks for the rest of a body with a Range
        \\  header. -C - reads the offset off the file -o or -O names, and
        \\  no such file means the whole body. A server that answers 200
        \\  to a Range request exits 33 and leaves the file untouched,
        \\  which is what curl does.
        \\  --no-clobber writes name.1, name.2, and so on when the name is
        \\  taken, up to name.99, and exits 23 after that. curl does the
        \\  same. The body is still fetched either way.
        \\  --http1.1 offers http/1.1 alone in the ALPN extension, so a
        \\  peer cannot choose HTTP/2 and every hop speaks HTTP/1.1.
        \\  --http2 asks for HTTP/2. On an https hop that is already what
        \\  zurl offers: it names h2 and http/1.1, and the server picks.
        \\  The flag is a request and not a demand, so a peer with no
        \\  HTTP/2 still answers http/1.1 and the transfer runs. On an http
        \\  hop there is no ALPN, so the flag asks to upgrade instead: the
        \\  request carries Upgrade: h2c, HTTP2-Settings, and Connection,
        \\  and a peer that answers 101 finishes the request on HTTP/2. A
        \\  peer that answers anything else has answered on HTTP/1.1 and
        \\  that answer is the one you read. curl sends the same three
        \\  fields for the same flag.
        \\  --http2-prior-knowledge speaks HTTP/2 and takes no other
        \\  answer. On an http url the connection preface goes out first
        \\  and no HTTP/1.1 byte is ever written, which is what a gRPC
        \\  service on a loopback port needs. On an https url the ALPN
        \\  offer is h2 alone, so a peer with no HTTP/2 ends the handshake
        \\  rather than answer on HTTP/1.1. curl behaves the same way for
        \\  both.
        \\  --http3 asks for HTTP/3 over QUIC, on UDP port 443. HTTP/3 is
        \\  never the default, because QUIC needs UDP reachable end to end
        \\  and many networks pass TCP and drop UDP. The flag is a request
        \\  and not a demand: a host with no HTTP/3 is fetched over the
        \\  TCP hop instead, with no word on standard error, and
        \\  -w %{http_version} says which version answered. curl falls back
        \\  the same way. An http url opens no QUIC at all, and neither
        \\  does a hop through a proxy.
        \\  --http3-only speaks HTTP/3 and takes no other answer. A host
        \\  with no QUIC exits 7, and an http url exits 3, which is what
        \\  curl gives for each.
        \\  --no-keepalive is accepted and changes nothing. It turns off
        \\  TCP keepalive probes, which zurl turns on for no connection.
        \\  It does not stop a connection being used for a second
        \\  request, and curl reuses one under it too.
        \\  -N, --no-buffer is accepted and changes nothing, because zurl
        \\  writes the body straight through as it arrives.
        \\  --no-alpn leaves the ALPN extension out of the TLS client
        \\  hello. A peer cannot choose a protocol it was never offered,
        \\  so the hop speaks HTTP/1.1. The flag is there for a peer or a
        \\  middlebox that answers ALPN badly.
        \\  -g, --globoff is accepted and changes nothing, because zurl
        \\  reads no { } or [ ] in a url. Every zurl run already behaves
        \\  the way curl -g does.
        \\  -l, --list-only asks an ftp url that names a directory for the
        \\  names alone: NLST instead of LIST. HTTP ignores it, which is
        \\  what curl does, and so do dict, gopher, and tftp: measured
        \\  against curl 8.21.0, -l gives byte for byte the same answer for
        \\  a dict:// and a gopher:// url as no flag does. It changes
        \\  nothing for an ftp url that names a file.
        \\  --retry sends the request again after a failure the peer did
        \\  not answer, and after the six statuses curl retries: 408, 429,
        \\  500, 502, 503, and 504. A bare --retry also covers a transfer
        \\  that ran out of time and a host name with no address, and it
        \\  covers nothing else. --retry-connrefused adds a connection the
        \\  peer did not take, and --retry-all-errors adds every other
        \\  failure. A 4xx other than 408 and 429 is never retried, and a
        \\  --fail beside --retry-all-errors makes every 4xx a failure and
        \\  therefore one to retry, which is what curl does.
        \\  A request the peer answered any byte of is never sent again
        \\  for a failure. Only the six statuses above, which are the peer
        \\  saying it did not serve the request, send one again.
        \\  The wait starts at one second and doubles, up to ten minutes.
        \\  --retry-delay holds it still, --retry-max-time stops the tries
        \\  once that many seconds have passed, and a Retry-After header
        \\  of plain digits raises the wait. A Retry-After holding a date
        \\  is read as no header at all, where curl reads the date.
        \\  Nothing is written to the output before a try is decided, so a
        \\  retried url leaves its file exactly as it was. curl instead
        \\  writes the body and rewinds the file.
        \\  --resolve and --connect-to move the dial and nothing else. The
        \\  Host header, the TLS server name, and the name the peer
        \\  certificate is checked against all stay the ones the url
        \\  wrote, so neither flag can reach a peer holding a certificate
        \\  for another host. An entry that does not read exits 49, which
        \\  is curl's own code, and no socket opens. --resolve takes one
        \\  address and not a list, and a - in front of an entry is
        \\  refused because zurl keeps no name cache to remove from.
        \\  -e, --referer sends the Referer of the first request, and the
        \\  ;auto suffix replaces it on each redirect with the url of the
        \\  hop before. -e ';auto' alone sends none on the first request.
        \\  -r, --range and -C, --continue-at cannot both be given, which
        \\  is what curl answers too. A -H 'Range: ...' replaces either.
        \\  A -r holding a character that is not a digit is named on
        \\  standard error and sent anyway, which is what curl does.
        \\  An option in the default curlrc that this build cannot use is
        \\  a warning naming the file and the line, and the run goes on,
        \\  which is what curl does. The same option in a -K file is a
        \\  usage fault, which is also what curl does.
        \\  -w knows six variables: http_code, size_download,
        \\  speed_download, time_total, url_effective, and content_type.
        \\  Any other variable prints nothing and names itself on standard
        \\  error, which is what curl does. A format string longer than
        \\  65536 bytes is refused.
        \\  The Current Speed column of the meter shows the average rate of
        \\  the whole transfer, where curl shows the rate of the last few
        \\  seconds.
        \\  -Z runs eight transfers at a time, where curl runs 50.
        \\  --parallel-max names another number, from 1 to 300, and a
        \\  number outside that range is named on standard error and the
        \\  default is used, which is what curl does with no word at all.
        \\  -Z draws no progress meter: curl draws a second
        \\  meter for parallel transfers and zurl has only the one meter.
        \\  -Z overlaps the transfers only when every url writes a file of
        \\  its own: one -o or -O for each url, and no two of them naming
        \\  one path. A url whose body goes to standard output, two urls
        \\  writing one file, and -D all take the run down to one transfer
        \\  at a time, and each says so on standard error. curl instead
        \\  mixes the bodies of parallel transfers into standard output,
        \\  byte by byte, as they arrive.
        \\  -Z exits with the first failure and no -Z exits with the last
        \\  one, which is the same split curl has.
        \\  --capath reads every file in a plain directory. curl wants a
        \\  directory that OpenSSL c_rehash has filed under subject
        \\  hashes, so a plain directory works with zurl and not with
        \\  curl. An entry zurl cannot read as certificates is skipped,
        \\  the other entries still load, and the skip is named on
        \\  standard error. A directory with no usable entry fails the
        \\  transfer with 60, because it holds no root at all.
        \\  -v, --verbose says what the transfer did, on standard error.
        \\  It writes one line for the method and the url, one line for
        \\  each header of each response head, marked with <, one line for
        \\  the effective url, and one line for each fault zurl recovered
        \\  from and would otherwise never show: a TCP_NODELAY that did
        \\  not take, a connect timeout this build could not enforce, a
        \\  credential withheld across a redirect, and a 401 challenge
        \\  left unanswered. -s does not silence it, which is what curl
        \\  does with the same pair.
        \\  -v prints no request header at all, where curl prints each one
        \\  marked with >. That is the rule that keeps a password out of a
        \\  verbose run: an Authorization line, whether zurl built it from
        \\  -u or you wrote it with -H, exists only in a request head, and
        \\  -v reads only what the server sent. Every url and every header
        \\  it does print goes through the one printer that masks a
        \\  userinfo password and drops a control byte. -v also prints no
        \\  connect line and no line from inside a proxy CONNECT, so
        \\  --suppress-connect-headers is accepted and changes nothing.
        \\  --trace, --trace-ascii, --trace-time, and --trace-ids are
        \\  refused by name and the run stops. Each asks for a byte for
        \\  byte dump of the wire, and this build has no tap to take one
        \\  from. A trace file written from what -v knows would be missing
        \\  every request byte, and a dump that is quietly incomplete is
        \\  worse than none.
        \\  --stderr names the file every message goes to, and - names
        \\  standard output. It is read after the command line is parsed,
        \\  so a usage fault in the command line itself still reaches the
        \\  real standard error. A file that cannot be opened exits 2.
        \\  -i, --show-headers and --include write the head of the last
        \\  response where the body goes, before the body. This is not -D,
        \\  which names a file of its own and writes the head of every
        \\  hop. Only http:// and https:// report a head, so -i writes
        \\  none for any other protocol, where curl invents one for some.
        \\  --basic, --digest, and --anyauth choose where the password
        \\  goes and when. --basic is the default: -u sends Basic with the
        \\  first request. --digest and --anyauth send no credential at
        \\  all until the server answers 401 and names a scheme, so the
        \\  password never travels on a request nobody asked it of.
        \\  --digest then answers a Digest challenge alone: a server that
        \\  offers Basic and nothing else gets no answer, the 401 is
        \\  returned as it came, and the reason is printed under -v. That
        \\  is the whole point of the flag, and answering with Basic
        \\  instead would send the password it exists to protect.
        \\  -n, --netrc, --netrc-optional, and --netrc-file are all
        \\  accepted, and they are curl's whole netrc family. -u outranks
        \\  a netrc entry, and a url userinfo outranks neither.
        \\  --cert, -E, --cert-type, --key, --key-type, and --pass are
        \\  refused by name and the run stops. This build sends no client
        \\  certificate: the vendored TLS client has no code path for one.
        \\  A run that accepted the flag and sent nothing would look to
        \\  you like a server that turned your certificate down, and you
        \\  would go looking at the server. The message names the flag and
        \\  never its argument, so a --pass phrase never reaches a log.
        \\  --ciphers and --curves are refused by name and the run stops.
        \\  This build offers one fixed suite list and one fixed curve
        \\  list, and it can neither narrow nor widen either. A flag
        \\  accepted here would read as a policy that was applied.
        \\  --output-dir puts every -o and -O file under that directory
        \\  and changes no file name. It creates no directory of its own;
        \\  --create-dirs does that, which is what curl asks for too.
        \\  --create-file-mode gives a file zurl creates that octal mode,
        \\  at the moment it is created and never with a later chmod, so
        \\  the body is never readable to anyone the mode shuts out. The
        \\  umask of the process still applies. A file that already exists
        \\  keeps the mode it has. A platform with no file modes ignores
        \\  it.
        \\  --remove-on-error deletes the output file when the transfer
        \\  failed, instead of leaving the bytes that did arrive. A -C
        \\  resume never deletes: the file held the first part of the body
        \\  before the transfer started, and those bytes are not this
        \\  transfer's to throw away. curl deletes there too.
        \\  -R, --remote-time gives the file the Last-Modified time the
        \\  server sent. A header that does not read leaves the file with
        \\  the time of the write, which is what curl does.
        \\  -J, --remote-header-name takes the -O name from the response's
        \\  own Content-Disposition header. It reads a url that -O covers
        \\  and no other: -J with -o writes the -o path, and -J with
        \\  neither writes standard output, which is what curl does with
        \\  each. The name goes through the one rule that judges every -O
        \\  name, so it is still one new entry in the working directory and
        \\  never a path. The directory part is cut off first, the way curl
        \\  cuts it: a header naming ../../evil.txt writes evil.txt here,
        \\  and /tmp/evil.txt writes evil.txt here too. A header naming
        \\  nothing usable leaves the name -O took from the url, and zurl
        \\  says so on standard error.
        \\  -J never overwrites a file that is already there. The url named
        \\  the request and the server named the file, so a server that
        \\  could also replace an existing file could replace any file in
        \\  the directory whose name it guessed. curl keeps the same rule
        \\  and fails that url with 23. --no-clobber outranks it and writes
        \\  the next free .1 or .2 name instead, which is what curl does
        \\  for that pair too. -J and -C are refused together, because -C
        \\  must know the file before the request goes out and -J does not
        \\  learn the name until the answer comes back. curl refuses the
        \\  same pair with 2.
        \\  --etag-save writes the response ETag to a file, quotes and all,
        \\  with one newline after it. A response with no ETag leaves the
        \\  file there and empty, rather than leave an older tag in place.
        \\  --etag-compare reads such a file and sends what it holds as
        \\  If-None-Match, with every line ending dropped and nothing else
        \\  changed. A file that is missing, empty, or unreadable sends the
        \\  two bytes "" and costs no exit code, which is what curl sends
        \\  and what curl exits. One difference from curl: a -H
        \\  If-None-Match you wrote replaces the file, where curl sends
        \\  both lines.
        \\  -z, --time-cond asks the server whether the body changed. A
        \\  leading - turns it into If-Unmodified-Since, a leading + or no
        \\  prefix is If-Modified-Since, and a leading = asks about a
        \\  Last-Modified, which puts no header on an http request under
        \\  either program. The moment is a date or a file whose own
        \\  modification time is read. The dates are the ones curl reads:
        \\  Sun, 06 Nov 1994 08:49:37 GMT, Sunday, 06-Nov-94 08:49:37 GMT,
        \\  Sun Nov 6 08:49:37 1994, 06 Nov 1994 08:49:37, 1994 Nov 6,
        \\  19941106 08:49:37, and 19941106. A numeric zone such as +0100
        \\  is read, and GMT, UTC, UT, and Z are read. An ISO date such as
        \\  1994-11-06, a bare epoch second, and a word such as now are
        \\  refused by name and send no header, which is what curl does
        \\  with each of them. zurl says which argument it could not read.
        \\  --rate starts this many transfers each unit of time, in a
        \\  serial run. The argument is a count and an optional unit out of
        \\  s, m, h, and d, and an argument with no unit is per hour, which
        \\  is curl's own default. The ceiling is 1000 transfers each
        \\  second under every unit, which is curl's ceiling too. The flag
        \\  paces the starts, so a transfer that ran longer than the gap
        \\  leaves no wait in front of the next one. -Z runs are not paced
        \\  by it, under either program.
        \\  --parallel-immediate is accepted and changes nothing. It tells
        \\  curl not to hold a transfer back while it waits to learn
        \\  whether an existing connection can carry it too. Each -Z worker
        \\  here has a connection pool of its own and waits on no other
        \\  worker, so every transfer already starts at once.
        \\  --parallel-max-host bounds the whole -Z run here, not one host.
        \\  Each worker holds one connection at a time, so capping the
        \\  workers keeps the promise for every host in the list whatever
        \\  mix of hosts it holds. A run over several hosts may therefore
        \\  use fewer workers than curl would; it never uses more than you
        \\  asked for, and zurl writes a line when the cap is what decided
        \\  the count.
        \\  --clobber is the other half of --no-clobber, so the pair reads
        \\  in either order and the last one wins. Overwriting is already
        \\  the default.
        \\  --url adds one url and keeps its place on the command line, so
        \\  -o a --url URL1 URL2 still writes URL1 to a.
        \\  --expect100-timeout, --happy-eyeballs-timeout-ms,
        \\  --keepalive-time, and --keepalive-cnt are accepted, each reads
        \\  and checks its own argument, and each changes nothing. zurl
        \\  sends no Expect: 100-continue, so no wait for a 100 starts. It
        \\  dials one address at a time, so no address family has a head
        \\  start to bound. It turns SO_KEEPALIVE on for no connection, so
        \\  there are no probes to space out or to count.
        \\  --next is not accepted. It splits one command line into
        \\  several runs, each with its own options and its own urls, and
        \\  this build builds one set of options for the whole command
        \\  line. It is the one curl flag this build does not know at all.
        \\  Every other flag curl 8.21.0 lists has a line in the options
        \\  block above, and that line carries one of three verdicts: the
        \\  flag does what it says, the flag is accepted and changes
        \\  nothing, or the flag is refused by name. A flag is never
        \\  accepted and dropped without a word.
        \\
        \\  These flags are accepted and change nothing, because each one
        \\  names a state this build is already in:
        \\  --path-as-is: zurl never squashes a .. in the url you typed.
        \\  A .. inside a Location: header is still resolved by RFC 3986,
        \\  which is what curl does with the flag too.
        \\  --ftp-pasv, --disable-eprt, and --ftp-skip-pasv-ip: passive is
        \\  the only ftp mode here, no EPRT can go out, and the address a
        \\  PASV answer names is never dialled.
        \\  --tcp-nodelay: TCP_NODELAY is already set. --no-tcp-nodelay is
        \\  the flag that takes it off, and the pair reads in either
        \\  order.
        \\  --no-sessionid: no TLS session is cached and every session
        \\  ticket is dropped, so none can be reused.
        \\  --ssl-allow-beast and --proxy-ssl-allow-beast: the floor here
        \\  is TLS 1.2, and the flaw the flag permits is a TLS 1.0 one.
        \\  --ssl-no-revoke, --ssl-revoke-best-effort,
        \\  --ssl-auto-client-cert, and --proxy-ssl-auto-client-cert are
        \\  Schannel options. curl on this platform accepts each and does
        \\  nothing with it, and this build checks no revocation and sends
        \\  no client certificate either way.
        \\  --false-start, --no-npn, --egd-file, --random-file,
        \\  --metalink, and --ntlm-wb are flags curl itself has dropped.
        \\  --socks5-basic names the one SOCKS5 authentication offered.
        \\  --styled-output: a response head is written with no styling
        \\  whichever way the flag is given, so every byte is the same.
        \\  --tcp-fastopen and --mptcp: an ordinary TCP connection is
        \\  opened, and the bytes on the wire are the same either way.
        \\
        \\  These flags do what they say, and each is new here:
        \\  -B and --use-ascii ask ftp for TYPE A on a file as well as on
        \\  a listing, and turn each CRLF of the answer into one LF.
        \\  --disable-epsv sends PASV and never EPSV, which saves a round
        \\  trip against a server that refuses EPSV. It does not change
        \\  which host the data connection dials.
        \\  --tftp-blksize asks for that blksize, from 8 to 8192. A number
        \\  outside the range is refused by name and never clamped, before
        \\  any datagram. --tftp-no-options sends the bare request.
        \\  --remote-name-all gives every url an -O, and --out-null throws
        \\  every body away. Both answer for a url that no -o and no -O
        \\  covers, so an explicit -o still wins, and the last of the two
        \\  wins over the other. --out-null still runs the transfer, so -w
        \\  still prints the status, the timings, and the size.
        \\  --skip-existing leaves a url alone when its output file is
        \\  already there. The file is measured and never opened, so it is
        \\  left byte for byte, no socket opens, and the exit is 0. A url
        \\  that writes to standard output has no file to find.
        \\  --url-query percent-encodes its argument and adds it to the
        \\  url query, reading all four --data-urlencode forms. It is not
        \\  -G: a request body still goes out beside it.
        \\  --disallow-username-in-url refuses any url of the run that
        \\  carries a credential, with 67, before any socket. A password
        \\  with no user name counts too.
        \\  --dump-ca-embed writes the trust bundle this binary carries to
        \\  standard output and runs no transfer, even beside a url.
        \\  --oauth2-bearer sends Authorization: Bearer with the first
        \\  request. It outranks -u, a url userinfo, and a netrc entry,
        \\  and it answers no 401 challenge: a Digest challenge is
        \\  reported rather than answered with a password you did not name
        \\  for that server. A -H Authorization still outranks it.
        \\  --proxy-ca-native is --ca-native for the proxy trust store,
        \\  which is a separate store from the origin's and stays one.
        \\  --post301, --post302, and --post303 keep the method and the
        \\  body across that one status, instead of asking for the target
        \\  with GET and no body. Each names one status alone, so --post301
        \\  leaves a 302 and a 303 rewriting. A 307 and a 308 keep the
        \\  method whatever these say, because neither status permits a
        \\  rewrite. A body that is kept has to be sendable twice, so a
        \\  body read from a pipe fails with 23 on the second hop rather
        \\  than start in the middle of itself.
        \\  --follow follows a redirect and keeps nothing, so it is -L
        \\  here. curl's two flags differ in one place: -X pins the method
        \\  text across a redirect for curl's -L and not for its --follow.
        \\  Measured, curl -L -X PUT -d a=1 through a 302 sends PUT and
        \\  curl --follow -X PUT -d a=1 sends GET. zurl cannot tell the
        \\  two apart, because nothing below the parser knows whether you
        \\  named the method, so zurl sends PUT for both. Every command
        \\  line without -X reads the same under either flag.
        \\
        \\  Every remaining curl flag is refused by name, and the run
        \\  stops before any socket. Each says in its own line above what
        \\  this build does instead. In short: there is no local address
        \\  or port to bind, no resolver to steer and no DoH, no unix
        \\  socket, no packet marking, no revocation check and no key
        \\  pinning, no TLS-SRP and no ECH and no session file, no SPNEGO
        \\  and no Kerberos and no NTLM and no AWS signature, no SASL
        \\  GSSAPI and no SASL DIGEST-MD5 and no SASL on ldap,
        \\  no HTTP/0.9 and no HTTP/3 to a proxy,
        \\  no HSTS and no Alt-Svc cache, no proxy
        \\  header and no CONNECT for a cleartext url, no ftp ACCT and no
        \\  MKD and no PRET and no CCC and no active mode, no telnet
        \\  subnegotiation, and no extended file attribute. --ssl is
        \\  refused for a reason of its own: it carries on in the clear
        \\  when a server refuses TLS, and the credential goes out anyway.
        \\  --ssl-reqd stops instead, and that is the flag to use.
        \\  --variable is refused because this build expands no variable,
        \\  so nothing on the command line would read the value.
        \\  --version and --help are read only as the first argument.
        \\
    );
}

/// Writes one option line: the short spelling, the long spelling, the
/// argument name, and the description.
///
/// A row with no short spelling gets four spaces where `-x, ` would be, so
/// every long form starts in one column. A row with no long spelling would
/// print its short form alone; the table holds no such row today, and this
/// prints one correctly if a later flag needs it.
fn printFlag(w: *Io.Writer, flag: Args.Flag) !void {
    var width: usize = 2;
    try w.writeAll("  ");

    if (flag.short) |short| {
        try w.print("-{c}", .{short});
        width += 2;
        if (flag.long != null) {
            try w.writeAll(", ");
            width += 2;
        }
    } else if (flag.long != null) {
        try w.writeAll("    ");
        width += 4;
    }

    if (flag.long) |long| {
        try w.print("--{s}", .{long});
        width += 2 + long.len;
    }

    if (flag.arg.len > 0) {
        try w.print(" {s}", .{flag.arg});
        width += 1 + flag.arg.len;
    }

    // Two spaces at the least, so a row past the column still reads as
    // two fields and never runs into its own description.
    const padding = if (width < description_column) description_column - width else 2;
    try w.splatByteAll(' ', padding);

    try w.print("{s}\n", .{flag.help});
}

const testing = std.testing;

/// How much scratch a test gives `render`.
///
/// `print` writes to a `std.Io.Writer` and puts no bound on itself, so
/// this is a test's buffer and not a limit on the help text. It is named
/// once because every test below renders the whole text, and the help
/// grows with each flag: the cookie flags took it past a 16 KiB buffer,
/// and six tests failed at once with a write fault that said nothing about
/// the cause. The three mail protocols took it past 32 KiB the same way,
/// and the hundred and thirty flags that closed the gap against curl took
/// it past 64 KiB. One name, one place to raise it.
const render_buffer_len = 128 * 1024;

/// Renders the whole help text into `buffer` and returns it.
fn render(buffer: []u8) ![]const u8 {
    var w: Io.Writer = .fixed(buffer);
    try print(&w);
    return w.buffered();
}

test "the options block names every spelling the parser accepts" {
    // **The test that keeps the help text and the parser in step.** Both
    // read `Args.flag_table`, so this cannot fail while that holds; it
    // fails the moment somebody writes an option line by hand again.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);

    for (Args.flag_table) |flag| {
        if (flag.long) |long| {
            var spelling: [64]u8 = undefined;
            const printed = try std.fmt.bufPrint(&spelling, "--{s}", .{long});
            try testing.expect(std.mem.indexOf(u8, text, printed) != null);
        }
        if (flag.short) |short| {
            var spelling: [8]u8 = undefined;
            const printed = try std.fmt.bufPrint(&spelling, "  -{c}", .{short});
            try testing.expect(std.mem.indexOf(u8, text, printed) != null);
        }
    }
}

test "a flag with both spellings shows both on one line" {
    // The exact fault this file was changed to close: -o, -O, and -D each
    // printed a short form with no long form beside it.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, "  -o, --output <path>") != null);
    try testing.expect(std.mem.indexOf(u8, text, "  -O, --remote-name") != null);
    try testing.expect(std.mem.indexOf(u8, text, "  -D, --dump-header <path>") != null);
    try testing.expect(std.mem.indexOf(u8, text, "  -#, --progress-bar") != null);
    try testing.expect(std.mem.indexOf(u8, text, "  -Y, --speed-limit <n>") != null);
    try testing.expect(std.mem.indexOf(u8, text, "  -y, --speed-time <s>") != null);
}

test "a flag with no short form starts its long form in the same column" {
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, "\n      --cacert <path>") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\n      --proto <list>") != null);
}

test "no flag this build accepts is still named as not accepted" {
    // `--tls-max` and `--proto-default` were both written into this block
    // as refused, with a reason. Both are accepted now, so the sentences
    // are false and must not come back. A help text that names a flag as
    // missing while the parser takes it is worse than no line at all: a
    // user reads it and rewrites a script that would have worked.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);

    try testing.expect(std.mem.indexOf(u8, text, "--tls-max is\n  not accepted") == null);
    // `-d`, `-T` and `-F` are all accepted now, so every sentence that
    // said one of them was not must never come back.
    try testing.expect(std.mem.indexOf(u8, text, "No request body") == null);
    try testing.expect(std.mem.indexOf(u8, text, "-d, -F, and -T are not accepted") == null);
    try testing.expect(std.mem.indexOf(u8, text, "-F and --form are not accepted") == null);
    try testing.expect(std.mem.indexOf(u8, text, "A multipart body is a format") == null);
    // And the block says what `-F` does now, and where it differs from
    // curl. A user who reads only the first half would send a file list
    // that this build refuses.
    try testing.expect(std.mem.indexOf(u8, text, "-F sends a multipart/form-data body") != null);
    try testing.expect(std.mem.indexOf(u8, text, "-F differs from curl in five places") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--proto-default is not accepted") == null);
    try testing.expect(std.mem.indexOf(u8, text, "not accepted: the TLS client") == null);

    // And each is still described, because the block has to say what the
    // flag does now.
    try testing.expect(std.mem.indexOf(u8, text, "--tls-max sets the highest") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--proto-default names the scheme") != null);
}

test "the help text says a redirect into file needs the flag" {
    // The default still refuses, and the opt-in is the user's own. Both
    // halves are written down, because a user who reads only the first
    // would think the target is unreachable and a user who reads only the
    // second would think it is the default.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, "cannot reach file:// unless") != null);
    try testing.expect(std.mem.indexOf(u8, text, "This\n  needs the flag") != null);
    // The old sentence said the hop fails with 3. It does not any more.
    try testing.expect(std.mem.indexOf(u8, text, "still fails with 3") == null);
}

test "the help text says which flags are refused and why" {
    // A flag refused by name is only better than one accepted and dropped
    // when the user can find out why. Each of these has a line here, and
    // each line names the flag.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);

    const refused = [_][]const u8{
        "--cert",        "--cert-type",  "--key",       "--key-type",
        "--pass",        "--ciphers",    "--curves",    "--trace",
        "--trace-ascii", "--trace-time", "--trace-ids",
    };
    for (refused) |flag| {
        try testing.expect(std.mem.indexOf(u8, text, flag) != null);
    }
    try testing.expect(std.mem.indexOf(u8, text, "refused by name and the run stops") != null);
    try testing.expect(std.mem.indexOf(u8, text, "sends no client certificate") != null);
    try testing.expect(std.mem.indexOf(u8, text, "one fixed suite list") != null);
    try testing.expect(std.mem.indexOf(u8, text, "no tap to take one") != null);
}

test "the help text says -v prints no request header, and why that matters" {
    // **The one guarantee a verbose mode has to make in writing.** A user
    // who cannot read that `-v` never prints a request header cannot know
    // that their password stays out of a log.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);

    try testing.expect(std.mem.indexOf(u8, text, "-v prints no request header") != null);
    try testing.expect(std.mem.indexOf(u8, text, "masks a\n  userinfo password") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Authorization line") != null);
}

test "the help text says which flags are accepted and change nothing" {
    // The other half of the same contract. A flag that does nothing must
    // say so, or a user reads its acceptance as a promise.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);

    try testing.expect(std.mem.indexOf(u8, text, "--expect100-timeout") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--happy-eyeballs-timeout-ms") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--keepalive-time") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--keepalive-cnt") != null);
    try testing.expect(std.mem.indexOf(u8, text, "each changes nothing") != null);
    // `--next` is the one curl flag this build does not know at all, so
    // it is the one that still reads "is not accepted".
    try testing.expect(std.mem.indexOf(u8, text, "--next is not accepted") != null);
    // `--variable` is known and refused now, so the old sentence must not
    // come back: a user who read it would think zurl had never heard of
    // the flag, which is a different thing from a refusal with a reason.
    try testing.expect(std.mem.indexOf(u8, text, "--variable is not accepted") == null);
    try testing.expect(std.mem.indexOf(u8, text, "--variable is refused") != null);
}

test "every flag row carries a verdict a user can act on" {
    // **The guard on the whole gap-closing change.** Every row of
    // `Args.flag_table` reaches the options block, and each has to say
    // one of three things: what it does, that it changes nothing, or that
    // it is refused. A row whose help line said none of the three would
    // read as a promise the build does not keep.
    //
    // The test is on the help text and not on the table, because the help
    // text is what a user reads.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);

    for (Args.flag_table) |flag| {
        try testing.expect(flag.help.len != 0);
        // Every line ends in a full stop, so no verdict is cut off.
        try testing.expectEqual(@as(u8, '.'), flag.help[flag.help.len - 1]);
    }

    // The three verdict blocks are all there, each under its own heading,
    // so a user can find the one their flag belongs to.
    try testing.expect(std.mem.indexOf(u8, text, "accepted and change nothing, because each one") != null);
    try testing.expect(std.mem.indexOf(u8, text, "These flags do what they say") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Every remaining curl flag is refused by name") != null);
}

test "the flags added to close the gap each name their verdict" {
    // One flag out of each of the three verdicts, named here so a change
    // that drops the block fails on the flag and not on a byte count.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);

    // Behaviour.
    try testing.expect(std.mem.indexOf(u8, text, "--skip-existing leaves a url alone") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--dump-ca-embed writes the trust bundle") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--oauth2-bearer sends Authorization: Bearer") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--tftp-blksize asks for that blksize") != null);
    // Accepted and inert.
    try testing.expect(std.mem.indexOf(u8, text, "--path-as-is: zurl never squashes") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--socks5-basic names the one SOCKS5") != null);
    // Refused, and the one refusal that carries its own paragraph because
    // it is the one that would send a password.
    try testing.expect(std.mem.indexOf(u8, text, "carries on in the clear") != null);
    try testing.expect(std.mem.indexOf(u8, text, "--ssl-reqd stops instead") != null);
}

test "the help text says what the TLS floor is" {
    // A user who reads --tlsv1.0 in the option list must be able to find
    // out that it cannot lower anything.
    var buffer: [render_buffer_len]u8 = undefined;
    const text = try render(&buffer);
    try testing.expect(std.mem.indexOf(u8, text, "--tlsv1.0") != null);
    try testing.expect(std.mem.indexOf(u8, text, "leave the") != null);
    try testing.expect(std.mem.indexOf(u8, text, "floor at TLS 1.2") != null);
}
