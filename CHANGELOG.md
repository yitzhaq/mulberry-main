# Changelog

This file attempts to document the recent release history of Mulberry.

The format is based on [Common Changelog](https://common-changelog.org/).

For the commercial-era changelog (versions up to 4.0.8), see `Build/Bits/`.
For granular change history, see `git log`.

## [4.2a1] - 2026-04-25

First version with significant development activity in over a decade.
This version brings Mulberry to modern 64-bit Linux with current
compilers and libraries, fixes numerous long-standing bugs, and
recovers work from the original developer's SVN repository.

Development and testing focused exclusively on Linux (x86_64,
Ubuntu 24.04, GCC 13). Some incidental fixes for Win32 and macOS
are included (mostly from recovered SVN patches and code analysis)
but are entirely untested. Building for other platforms may or may
not work.

### Recovered patches from original developer

Sixteen patches by Cyrus Daboo were recovered from his Subversion
repository (archived by the Wayback Machine before it went offline) and
integrated into the codebase. These fixes were never included in any
public build or fork. Each patch was individually reviewed and adapted
where necessary.

Notable recovered fixes include: drag-and-drop data corruption from
pointer arithmetic error, toolbar popup menus silently ignoring
selections, LDIF import using uninitialized pointer, address book import
silently reporting failure as success, unmappable characters vanishing
instead of showing a placeholder, Win32 AltGr keyboard and window
placement fixes, SMIME base64 encoding safety improvements, and Linux
font menu caching (updated to show modern fonts instead of only legacy
X11 bitmap fonts).

### Changed

- RFC 8098 MDN compliance: MDN messages now use null envelope sender
  (`MAIL FROM:<>`) to prevent DSN bounce loops, remove internal
  hostname/IP from the Reporting-UA field for privacy, conditionally
  emit Original-Message-ID only when the original has one, and use
  RFC-correct case-sensitive local-part comparison for the
  Disposition-Notification-To vs Return-Path security check.
- Improve format=flowed reply quoting: replies to flowed messages now
  join soft-wrapped paragraphs before re-quoting, and alternative
  quote markers used by some mail clients (`|`, `#`) are recognized
  and normalized to the user's configured reply prefix (RFC 3676).
- Display human-readable text for Unicode characters that the JX
  toolkit cannot render (anything outside Latin-1). Common emoji
  show ASCII emoticons (e.g., `[:)]` for 😊, `[<3]` for ❤️);
  other emoji and symbols show CLDR short names (e.g.,
  `[:waving hand:]` for 👋); multi-codepoint sequences like country
  flags and skin-tone variants are matched correctly (longest match
  first); Unicode mathematical styled letters
  (bold, italic, script, etc.) render as their plain ASCII
  equivalents; typographic characters like curly quotes, en/em
  dashes, and ellipsis render transparently as their ASCII
  counterparts; invisible formatting characters (zero-width
  joiners, variation selectors, soft hyphens, bidi marks) are
  suppressed; remaining unmapped characters show `[U+XXXX]`
  codepoint placeholders. The CLDR annotation table is generated
  at build time from the `unicode-cldr-core` package. Applies to
  Linux and macOS, where the GUI toolkits (JX and PowerPlant)
  cannot render characters outside Latin-1.
- Hide HTML elements with inline `display:none` style. Prevents
  preheader text, hidden tracking content, and soft-hyphen padding
  from being rendered as visible text in HTML messages. Handles
  nested same-name tags, void elements (img, br, etc.), and
  multi-line tags correctly.
- Use `aria-label` and `title` attributes as fallback for image
  alt text in HTML messages, before falling back to the filename.
- Replace custom XML parser with system libxml2 for CalDAV, CardDAV,
  WebDAV, and address book XML parsing. Adds XXE protection, entity
  expansion limits, and network access blocking. The custom parser
  (XMLSAXSimple) remains available as fallback via --without-libxml2.
- IMAP APPENDLIMIT extension (RFC 7889). Parse server-advertised
  maximum message size from CAPABILITY and STATUS responses. Reject
  oversized APPENDs before transmission with a clear error message.
- IMAP LIST-EXTENDED (RFC 5258). Extended LIST command with selection
  and return options. Replaces LSUB with `LIST (SUBSCRIBED)` for
  accurate subscription flags. Parses `\Subscribed`, `\NonExistent`
  attributes, CHILDINFO extended data, and OLDNAME extended data
  (RFC 9051 §6.3.9.7) for server-pushed rename/delete notifications.
- IMAP LIST-STATUS (RFC 5819). Combines STATUS data into LIST
  responses, retrieving message counts for all mailboxes in a single
  round-trip instead of individual STATUS commands per mailbox.
- IMAP STATUS=SIZE (RFC 8438). Server-reported mailbox storage size,
  replacing the expensive manual fetch-all-sizes calculation. Mailbox
  size field widened to 64-bit for 63-bit RFC compliance.
- IMAP SEARCHRES (RFC 5182). Save search results on server via
  SEARCH RETURN (SAVE ALL), reference with `$` in subsequent COPY,
  MOVE, STORE, FETCH, and EXPUNGE commands. Avoids retransmitting
  large result sets. Safety check ensures `$` only used when the
  command set matches the saved results exactly.
- IMAP SORT=DISPLAY (RFC 5957). DISPLAYFROM and DISPLAYTO sort
  keys for server-side display name sorting. When supported by
  the server, the "From / To" smart address column now uses
  server-side sorting, choosing DISPLAYTO for Sent/Copy-To
  mailboxes and DISPLAYFROM for all others. Note: this works
  per-folder rather than per-message — the original client-side
  smart sort examined each message's From address to decide
  individually, which required downloading all envelopes and
  is less efficient.
- IMAP ESORT + CONTEXT=SEARCH (RFC 5267). Compact ESEARCH-format
  responses for SORT and SEARCH commands with COUNT, MIN, MAX
  return data. CONTEXT=SEARCH enables live-updating search views:
  when a mailbox filter is active, the server pushes incremental
  ADDTO/REMOVEFROM notifications as messages change, keeping the
  filtered view current without re-searching. Includes CANCELUPDATE
  command, NOUPDATE response code handling, and PARTIAL response
  parsing. CONTEXT=SORT intentionally deferred (near-zero server
  adoption). Tested against Dovecot.
- IMAP WITHIN (RFC 5032). OLDER and YOUNGER search keys for
  date-relative searches (e.g., messages from the last N days).
- IMAP IDLE (RFC 2177). Server-push notifications replacing NOOP
  polling. Delivers new mail notifications in under one second.
  Re-IDLEs at the configured tickle interval (default 25 minutes,
  under the RFC 2177 29-minute recommendation). Falls back to
  NOOP polling on servers without IDLE support.
- IMAP BINARY (RFC 3516). Server-side CTE decoding for FETCH,
  eliminating client-side base64/QP decoding and reducing
  attachment bandwidth by ~25%. Includes literal8 (~{size})
  response parsing.
- IMAP MULTIAPPEND (RFC 3502). Upload multiple messages in a
  single APPEND command with server-guaranteed atomicity. Reduces
  round-trips when copying messages between servers. Falls back to
  individual APPENDs on servers without MULTIAPPEND support.
- IMAP SPECIAL-USE (RFC 6154). Parse server-advertised special-use
  mailbox attributes (\Drafts, \Sent, \Trash, \Junk, \Archive,
  \All, \Flagged) from LIST responses. Auto-configures identity
  Copy-To from \Sent and per-account Drafts mailbox from \Drafts
  when not already configured. Adds per-account Drafts mailbox
  preference. Supports both RETURN (SPECIAL-USE) and selection
  option. This completes all 15 mandatory IMAP4rev2 extensions.
  Win32/MacOS Drafts preference UI requires dialog resource updates.
- IMAP REPLACE (RFC 8508). Atomic draft message replacement,
  eliminating duplicate drafts when saving repeatedly. Falls back
  to APPEND + delete on servers without REPLACE support. Draft UID
  persisted across sessions in local safety-save files on all
  platforms. Opened drafts seed the UID for seamless re-save.
- Server-side draft auto-save. When a per-account Drafts mailbox
  is configured (manually or auto-detected via SPECIAL-USE),
  periodic auto-save now saves to the server in addition to local
  disk. Uses REPLACE for atomic updates when available, APPEND +
  delete otherwise. Server draft automatically cleaned up on send.
  5-minute throttle prevents excessive server saves. Old drafts
  cleaned up via UID EXPUNGE. Identity, signature, signing, and
  encryption settings persist in local safety-save files for crash
  recovery (all platforms).
- IMAP $Important keyword and \Important special-use attribute
  (RFC 8457). Recognizes server-assessed message importance
  (distinct from user-set \Flagged). Keyword preserved across
  COPY, MOVE, APPEND, and REPLACE operations.
- IMAP Response Codes (RFC 5530). Human-readable explanations for
  17 standard error response codes (AUTHENTICATIONFAILED, NOPERM,
  OVERQUOTA, NONEXISTENT, etc.) appended to server error messages.
- HTTP Content-Encoding support (RFC 9110 §8.4/§12.5.3). All
  CalDAV, CardDAV, and WebDAV preferences traffic now requests
  compressed responses. Supports gzip/deflate (always available
  via zlib), Brotli (RFC 7932, optional), and Zstandard (RFC 8878/
  9659, optional). Reduces HTTP bandwidth by 60-80%. Legacy
  x-gzip/x-deflate aliases accepted per RFC 9110.
- IMAP CONDSTORE + QRESYNC (RFC 7162). Per-message modification
  sequence tracking and quick mailbox resynchronization. ENABLE
  CONDSTORE/QRESYNC sent after login. MODSEQ tracked per message,
  HIGHESTMODSEQ tracked per mailbox from SELECT, STATUS, and
  FETCH responses. Incremental flag sync via CHANGEDSINCE FETCH
  on reconnection, with automatic fallback to full re-fetch if
  UIDVALIDITY changes or the server reports NOMODSEQ. QRESYNC
  SELECT parameter sends last-known UIDVALIDITY, HIGHESTMODSEQ,
  and cached UIDs so the server returns only VANISHED UIDs and
  changed flags in one round-trip. VANISHED response parsing
  handles both historical (EARLIER) and real-time expunges.
  UNCHANGEDSINCE STORE modifier for conditional flag updates.
  CLOSED response code for mailbox switching under QRESYNC.
  MODSEQ and HIGHESTMODSEQ persisted in offline cache (format
  version 0x0C). Turns multi-second reconnection resyncs into
  sub-second operations on servers that support it (Dovecot 1.2+,
  Cyrus 2.4+, Exchange 2013+).
- IMAP COMPRESS=DEFLATE (RFC 4978). Reduces IMAP bandwidth by
  60-75% using zlib compression. Activated automatically after
  login when the server supports it. Includes decompression bomb
  protection and graceful fallback on failure.
- IMAP INPROGRESS (RFC 9585). Server progress notifications for
  long-running commands displayed in the status bar.
- SMTP PIPELINING (RFC 2920). Send MAIL FROM and RCPT TO commands
  in a single batch, reducing latency by (N-1) round-trips for N
  recipients. Falls back to synchronous on servers without support.
- SMTP CHUNKING + BINARYMIME (RFC 3030). Send messages via BDAT
  command instead of DATA, eliminating dot-stuffing overhead.
  Non-text attachments sent with binary content-transfer-encoding
  when the server supports BINARYMIME, saving ~33% bandwidth by
  skipping base64 encoding. Multiple BDAT chunks pipelined when
  the server also supports PIPELINING (RFC 2920). Falls back to
  traditional DATA on servers without CHUNKING support.
- SMTP BURL extension (RFC 4468). Forward-without-download
  submission: detect BURL capability with "imap" argument in EHLO
  response, send BURL command with IMAP URL and LAST marker,
  interleave with BDAT when CHUNKING is available. Completes the
  SMTP side of the Lemonade profile.
- IMAP CATENATE extension (RFC 4469). Server-side message assembly
  via extended APPEND command with URL and TEXT parts. Enables
  composing messages on the IMAP server from existing message parts
  without downloading them. Handles BADURL, TOOBIG, and TRYCREATE
  response codes. APPENDUID parsing for the catenated result.
- IMAP $SubmitPending and $Submitted keywords (RFC 5788 §3.4.3-
  3.4.4, RFC 5550 §5.10). Track message submission state: awaiting
  ($SubmitPending), being submitted ($SubmitPending + $Submitted),
  submitted ($Submitted). Atomic state transitions via CONDSTORE
  UNCHANGEDSINCE. Completes all seven RFC 5788 registered keywords.
- Lemonade Profile (RFC 5550). All 27 mandatory extensions now
  implemented (IMAP: CATENATE, URLAUTH, URL-PARTIAL, BINARY,
  CONDSTORE, QRESYNC, ENABLE, COMPRESS, SORT, ESEARCH, ESORT,
  CONTEXT, IDLE, NOTIFY, NAMESPACE, UIDPLUS, LITERAL+, SASL-IR,
  I18NLEVEL, STARTTLS; SMTP: BURL, 8BITMIME, PIPELINING, CHUNKING,
  BINARYMIME, SIZE, DSN, ENHANCEDSTATUSCODES, AUTH, STARTTLS;
  keywords: $Forwarded, $SubmitPending, $Submitted).
  fcc-via-BURL optimization (RFC 5550 §8.6): when the SMTP server
  supports BURL and the IMAP server supports URLAUTH, sent messages
  are uploaded once to the Sent folder and submitted via BURL URL
  reference, eliminating the traditional double upload. Automatic
  transparent fallback to DATA/BDAT if BURL fails. $SubmitPending
  and $Submitted flags track submission state on the fcc copy per
  RFC 5550 §5.10. Queue drain path also uses BURL when IMAP is
  available at drain time. Forward-without-download UI deferred.
- SMTP Enhanced Status Codes (RFC 2034/3463). Parse x.y.z status
  codes from SMTP responses for detailed error diagnostics with
  full RFC 3463 status code registry.
- $Forwarded and $MDNSent flags in the Flags context menu and main
  menu, with keyboard shortcuts (Alt+Ctrl+6/7). Forwarded messages
  show a right-pointing arrow in the message list flags column,
  mirroring the left-pointing arrow for answered messages.
- "Reflow Lines" command in compose window (context menu and Draft
  menu). When replying to messages where the quoting merged items
  that should be separate (e.g., numbered lists), the user can
  manually insert line breaks, select the text, and trigger Reflow
  Lines to properly re-wrap with correct quote prefixes. Handles
  multiple quote depths.
- Fix text selection after Wrap/Unwrap/Quote/Unquote/Requote/Reflow
  and Shift operations in the compose window. The selection used
  UTF-8 byte count instead of character count, causing the selection
  to overflow into subsequent text when non-ASCII characters were
  present. Fixed on all platforms (Linux, Win32, macOS).
- Fix SMTP partial recipient failure: one rejected RCPT TO no
  longer aborts the entire message. Valid recipients still receive
  the message when others are rejected.
- Fix filter rules using COPY+DELETE instead of atomic MOVE (RFC
  6851) when moving messages. MOVE was implemented but the filter
  pipeline was never updated to use it.
- Fix Y2038 timestamp truncation. All serialized time_t values in
  offline cache, sync metadata, and calendar/address book XML now
  use 64-bit representations. Offline cache date fields use 8-byte
  big-endian format. SIndexHeader timestamps use Hi/Lo uint32_t pairs.
  Calendar/address book sync timestamps serialized via text to bypass
  XMLLib's int32_t truncation. SetLastSync API chain changed from
  unsigned long to time_t for cross-platform correctness. CICalendar
  and vCard DaysSince1970 and duration arithmetic widened to int64_t.
- Timezone database updated from 2008 (tzdata2008i) to current IANA
  data. Timezone files are now generated at build time from the latest
  IANA source via vzic, so they stay current with each build. Fixes
  18 years of DST rule changes affecting calendar operations.
- Default new accounts to Implicit TLS (RFC 8314). New IMAP, POP3,
  SMTP, CalDAV, CardDAV, and WebDAV accounts now use SSL/TLS on the
  dedicated secure port (993, 995, 465, 443) instead of connecting
  in cleartext. Existing accounts are unaffected.
- Change default SMTP submission port from 25 to 587 (RFC 6409).
  Port 25 is the MTA relay port, commonly blocked by ISPs. Port 587
  is the standard submission port for email clients. Existing accounts
  are unaffected.
- Rename TLS security options to match modern terminology (Thunderbird
  convention). "SSLv23" → "SSL/TLS", "STARTTLS - TLSv1" → "STARTTLS".
  The legacy SSLv3 and STARTTLS-SSL variants are hidden from the UI as
  they are functionally identical with modern OpenSSL. Existing
  preferences files are read correctly. Updated on Linux and Win32;
  macOS labels are in binary PowerPlant resources (PPob) and cannot
  be updated without macOS build tools.
- Update IMAP QUOTA from RFC 2087 to RFC 9208. Quota values now use
  64-bit integers (was platform-dependent `long`), and the capability
  check recognizes both `QUOTA` (RFC 2087) and `QUOTA=RES-*` (RFC 9208)
  capability strings. The existing quota UI already supported arbitrary
  resource types, so no display changes were needed.
- Require STARTTLS capability advertisement before attempting STARTTLS
  upgrade (RFC 8314). Previously, Mulberry issued the STARTTLS command
  without checking whether the server advertised the capability in IMAP,
  ACAP, and SIEVE. SMTP already checked correctly.
- Preserve unrecognized ACL rights on edit roundtrip (RFC 4314).
  Servers using RFC 4314 rights (t, e, x, k) instead of RFC 2086
  (d, c) had these rights silently stripped when editing mailbox
  permissions. Now preserved and merged back.
- Modernize Debian packaging with desktop entry, AppStream metadata,
  updated dependencies, and lintian compliance.
- Add `mulberry(1)` man page covering all command-line options,
  supported protocols, external editor integration, and environment
  variables.
- System timezone detection for calendar default. Calendar events
  no longer default to US/Eastern (the original developer's personal
  timezone). Reads from /etc/localtime symlink (Linux, macOS) with
  /etc/timezone fallback (Debian/Ubuntu). Falls back to UTC.
  Win32: deferred (requires CLDR windowsZones.xml mapping table).
- IMAP STATUS DELETED attribute (RFC 9051). Parse the count of
  \Deleted-flagged messages from STATUS and LIST-STATUS responses.
  Not yet requested from servers (requires IMAP4rev2 capability
  negotiation, G2).
- Enforce LOGINDISABLED capability (RFC 9051 §6.2.3). Client no
  longer sends LOGIN when the server advertises LOGINDISABLED.
- Enforce TLS 1.2 minimum (RFC 8996, RFC 9051 §11.1). TLS 1.0 and
  1.1 are now disabled via SSL_OP_NO_TLSv1 and SSL_OP_NO_TLSv1_1.
- TLS Server Name Indication (SNI). The server hostname is now
  sent during the TLS handshake for virtual hosting compatibility.
- PREAUTH rejected on cleartext ports when STARTTLS is required
  (RFC 9051 §7.1.4). Previously, PREAUTH was accepted regardless
  of TLS state, bypassing encryption for the entire session.
- ALERT response codes filtered before TLS or authentication is
  established (RFC 9051 §11.3), preventing MITM injection of
  fake alerts on unauthenticated cleartext connections.
- RFC822.SIZE and literal sizes now parsed as 64-bit values per
  RFC 9051 Appendix D (63-bit number64).
- UIDNOTSTICKY, NOTSAVED, BADCHARSET, and HASCHILDREN response
  codes parsed (RFC 9051 §7.1). NOTSAVED clears the saved search
  result variable. UIDNOTSTICKY sets a flag on the mailbox.
- $Junk, $NotJunk, $Phishing keyword string constants defined
  (RFC 9051 §2.3.2). Flag enum bits and UI deferred.

### Added

- IMAP OBJECTID extension (RFC 8474). Persistent server-assigned
  identifiers for mailboxes (MAILBOXID) and messages (EMAILID,
  THREADID) that survive renames, copies, and moves. MAILBOXID
  parsed from SELECT/EXAMINE, CREATE, and STATUS responses.
  EMAILID and THREADID fetched automatically with message summaries
  when the server advertises the OBJECTID capability. EMAILID and
  THREADID SEARCH keys supported. THREADID NIL handled for servers
  without threading support.
- IMAP SEARCH=FUZZY extension (RFC 6203). Server-side inexact/fuzzy
  matching for SEARCH commands. The FUZZY search key wraps any other
  search criterion, allowing the server to perform implementation-
  defined matching (stemming, phonetic, typo tolerance). RELEVANCY
  score-list parsed from ESEARCH responses. Search UI, RELEVANCY
  sort key, and score display deferred.
- IMAP SAVEDATE extension (RFC 8514). Server-reported date when a
  message was saved in its current mailbox (distinct from INTERNALDATE,
  which can be set arbitrarily on APPEND or copied on COPY/MOVE).
  Fetched automatically when the server advertises the SAVEDATE
  capability. Includes SAVEDBEFORE, SAVEDON, SAVEDSINCE, and
  SAVEDATESUPPORTED search keys. Search UI deferred.
- IMAP URLAUTH extension suite: full IMAP URL parser/builder (RFC 5092),
  URLAUTH authorization (RFC 4467) with GENURLAUTH, URLFETCH, and
  RESETKEY commands, extended URLFETCH for binary and converted parts
  (RFC 5524, URLAUTH=BINARY capability), generic access identifiers
  (RFC 5593), and URL-PARTIAL capability (RFC 5550). Foundation for
  forward-without-download workflow (CATENATE and BURL to follow).
- SCRAM-SHA-1 and SCRAM-SHA-256 authentication plugins (RFC 5802,
  RFC 7677). SASL challenge-response authentication with salted
  password hashing and mutual server verification. Includes channel
  binding support (RFC 9266): tls-exporter for TLS 1.3+, tls-unique
  for TLS 1.2 with Extended Master Secret. Automatic -PLUS negotiation
  when the server advertises channel binding support. SASL-IR (RFC 4959)
  for single-round-trip authentication on capable IMAP servers.
- IMAP TRYCREATE handling (RFC 9051 §7.1). When COPY, MOVE, APPEND,
  REPLACE, or MULTIAPPEND targets a deleted mailbox, prompt the user
  to recreate it and retry. Covers same-server and cross-account paths.
  Also offer to recreate when SELECT fails on a mailbox deleted by
  another client while Mulberry was running.
- IMAP $Junk/$NotJunk/$Phishing keyword support (RFC 9051 §2.3.2).
  Parse, store, and send the standard junk classification keywords.
  Enforce mutual exclusivity: if both $Junk and $NotJunk are present,
  treat as neither (MUST). SBitFlags widened from `unsigned long` to
  `uint64_t` for cross-platform correctness (keywords use bits 32-34).
  Offline cache updated to persist 64-bit flags.
  UI for marking messages as junk is planned.
- IMAP NOTIFY extension (RFC 5465). Server-pushed mailbox change
  notifications replacing periodic STATUS polling. Monitors subscribed
  mailboxes for message changes and personal namespace for hierarchy
  changes (create, delete, rename, subscribe). IDLE without a selected
  mailbox is enabled when NOTIFY is active so the main connection
  receives pushed events in real-time. Handles NOTIFICATIONOVERFLOW
  by falling back to polling, and BADEVENT by retrying with the
  server's supported event subset. Servers without NOTIFY continue
  with the existing polling flow unchanged.
- POP3 SYS/AUTH response codes (RFC 3206). Parse structured error
  codes from POP3 servers to distinguish authentication failures
  from temporary and permanent server errors.
- IMAP internationalization (RFC 5255). Detects LANGUAGE, I18NLEVEL=1,
  and I18NLEVEL=2 capabilities. Queries available languages via the
  LANGUAGE command and the active comparator via the COMPARATOR command
  after login. Parses `* LANGUAGE` and `* COMPARATOR` untagged responses
  and handles the BADCOMPARATOR response code. I18NLEVEL=2 implies
  I18NLEVEL=1 (superset). LANGUAGE pre-auth negotiation and NAMESPACE
  TRANSLATION support are deferred.
- IMAP4rev2 capability negotiation (RFC 9051). Mulberry detects
  IMAP4rev2 in server CAPABILITY, sends ENABLE IMAP4rev2 when both
  rev1 and rev2 are advertised, and activates rev2-specific behavior:
  STATUS omits deprecated RECENT and adds DELETED, SEARCH omits
  CHARSET (UTF-8 default), LSUB replaced by LIST (SUBSCRIBED),
  deprecated SEARCH keys (RECENT/NEW/OLD) substituted. Folded-in
  extension flags set for pure rev2 servers. LIST \Remote attribute
  parsed as unselectable (no referral support).
- IMAP STATUS APPENDLIMIT (RFC 7889). Per-mailbox append size limits
  requested in STATUS when the server advertises APPENDLIMIT.
- IMAP ENABLE extension (RFC 5161). Capability detection and
  scaffolding for CONDSTORE/QRESYNC activation.
- IMAP CHILDREN extension (RFC 3348). Parse \HasChildren and
  \HasNoChildren LIST attributes for accurate hierarchy display.
  The constants and flag bits already existed but parsing was
  disabled.
- IMAP ESEARCH extension (RFC 4731). When the server advertises
  ESEARCH, search results are returned in compact sequence-set
  format instead of individual message numbers. Prerequisite for
  MULTISEARCH (RFC 7377, cross-mailbox search).
- SASL-IR initial response (RFC 4959). When the server advertises
  SASL-IR, Mulberry sends the initial authentication data on the
  same line as the AUTHENTICATE command, eliminating one round-trip.
- IMAP MOVE command (RFC 6851). When moving messages between folders
  on the same account, Mulberry now uses the atomic MOVE command
  instead of COPY + flag \Deleted. This prevents duplicate messages
  if the connection drops mid-operation. MOVE is mandatory in
  IMAP4rev2 and supported by all major servers. Cross-account moves
  (between different IMAP servers) continue to use COPY + DELETE
  as before — the operation remains completely transparent.
- $Forwarded keyword (RFC 9051). Source messages are now flagged with
  the $Forwarded IMAP keyword after forwarding, so other clients and
  the server can distinguish forwarded from merely-read messages.
  Analogous to the existing \Answered flag set on replies.
- 64-bit Linux support (x86_64 / LP64). Mulberry now builds and runs
  correctly on 64-bit systems. This required fixing type sizes in
  offline cache file formats, network protocol buffers, plugin
  interfaces, binary file format parsers (AppleSingle/BinHex), and
  pointer-to-integer storage throughout the codebase.
- OpenSSL 1.1 through 3.x support via dynamic loading. Mulberry
  detects the installed OpenSSL version at runtime and uses the
  appropriate API, supporting all three major OpenSSL generations
  (pre-1.1, 1.1-2.x, and 3.x).
- GCC 13+ and Clang 18+ compatibility (C++17 standard).
- libsodium dependency for cryptographic primitives: keyring
  encryption (Argon2id + XChaCha20-Poly1305), random byte
  generation (Message-ID, MIME boundaries, UIDValidity), and
  BLAKE2b hashing (POP3 UIDL). Replaces use of OpenSSL MD5 and
  RC4, which are deprecated in OpenSSL 3.x.
- Add delsp=yes to outgoing format=flowed messages, as recommended by
  RFC 3676. Mulberry already supported format=flowed for both sending
  and receiving, but without delsp, which caused trailing spaces in
  soft-wrapped lines when viewed by non-flowed clients. Outgoing
  messages now display cleanly in all mail clients.
- Strip accumulated reply/forward subject prefixes in other languages
  (Sv:, AW:, Rif:, etc.) back to a single `Re:` or `Fwd:`, per
  RFC 5322 section 3.6.5. Ships with 28 common prefixes across major
  languages. The prefix list is configurable by editing the preferences
  file directly; a preferences UI has not yet been implemented.
- IMAP ID extension (RFC 2971). Mulberry identifies itself to the
  server, and parses the server's ID response (name, version,
  vendor) for display in server properties.
- User-Agent header on all HTTP requests (CalDAV, CardDAV, WebDAV).
- Compose key and dead key support on Linux. Accented character
  input (e.g., AltGr+e for é) now works throughout the application.
  Limited to characters available in ISO 8859-1 (Western European) due
  to JX toolkit constraints; Eastern European and other accented
  characters beyond Latin-1 are not supported via compose sequences.
- Fix clipboard on Linux. Ctrl+V and context menu paste now read
  from the CLIPBOARD X11 selection (what Ctrl+C writes) instead of
  PRIMARY (mouse-highlighted text). Middle-click paste still reads
  PRIMARY. Non-ASCII text (accented characters, CJK, etc.) is
  handled correctly via UTF8_STRING negotiation, with automatic
  UTF-8 detection for sources that return UTF-8 data as XA_STRING.
  CRLF line endings from external clipboard sources are normalized.
- Fall back to xdg-open for opening attachments on Linux when no
  mailcap entry matches the MIME type. Previously, attachments with
  no mailcap match (notably application/octet-stream) simply could
  not be opened. Mailcap entries, when present, still take precedence.
- Fall back to xdg-open for opening URL links on Linux when no
  url.helpers mapping exists. Previously, clicking a link in a
  message body did nothing on modern systems where url.helpers
  files are not configured.
- Accept bare `mailto:` URLs on the command line, so desktop mail
  handlers can launch Mulberry directly.
- ICS file import via command line and file association. Passing an
  `.ics` file to Mulberry (by command line, file manager double-click,
  or while the app is already running) imports the calendar data.
  Single-event files open the edit dialog with the event pre-filled —
  OK saves, Cancel discards. Multi-event files prompt to choose a
  target calendar from the list of active calendars (default
  pre-selected), showing the number of events and tasks to be
  imported. Registered as `text/calendar` MIME type handler.
- RFC 8601 Authentication-Results header parsing, RFC 8617 ARC chain
  consumption, and iTIP anti-spoofing. Mulberry now parses
  Authentication-Results headers added by the receiving MTA to verify
  DKIM, DMARC, SPF, and ARC authentication status. ARC (Authenticated
  Received Chain) results are used as a fallback when DKIM breaks in
  transit through mailing lists or forwarding services. When processing
  incoming calendar invitations (iMIP), the organizer's domain is
  checked against the authentication results — if the domain did not
  pass any authentication, the user is warned before accepting. Three
  distinct warnings guide the user: authentication failed, untrusted
  server (with configuration guidance), or missing authentication data.
  Trust is established by matching the authserv-id against the user's
  configured mail account domains (email address, IMAP server, SMTP
  server). Configurable via preferences: `Auth Results Enabled`
  (default on) and `Auth Results Trusted Servers` (empty = auto-match
  from account domains). Addresses the organizer spoofing prevention
  that the original developer marked as IMPORTANT in four separate
  iTIP receive methods.
- Automatic recovery of dead per-mailbox IMAP connections. When a
  clone connection dies (server restart, network interruption, WiFi
  loss), Mulberry now detects the dead connection and transparently
  reconnects — re-authenticating, re-SELECTing the mailbox, and
  reloading messages. Previously, dead clones either looped silently
  or blocked indefinitely, requiring the user to close and reopen
  the folder. Detection combines three mechanisms: dead-socket
  checks in the IDLE tickle path, TCP keepalive probes at the kernel
  level (~120s detection on Linux), and a 5-second timeout on IDLE
  DONE response. Stale connections in the connection cache pool are
  also detected and discarded. TCP keepalive parameters are
  configurable via preferences (`TCP Keepalive Enabled`, `Idle`,
  `Interval`, `Count`); platform-specific tuning on Linux
  (TCP_KEEPIDLE/INTVL/CNT) and macOS (TCP_KEEPALIVE); Windows uses
  OS default pending Winsock 2 upgrade.
- Visual Studio 2019 build support (Win32, untested).
  Contributed by Quanah Gibson-Mount.
- IMAP UTF-8 support (RFC 9755, obsoletes RFC 6855). Negotiates
  UTF8=ACCEPT via ENABLE after login, enabling native UTF-8 mailbox
  names (bypassing modified UTF-7), UTF-8 in IMAP quoted strings,
  and CHARSET suppression in SEARCH. Handles UTF8=ONLY servers.
  Parses message/global (RFC 6532) in BODYSTRUCTURE alongside
  message/rfc822. Forces AUTHENTICATE over LOGIN when credentials
  contain non-ASCII characters (§5). Mailbox name encoding is now
  centralized through EncodeMailboxName(), which correctly skips
  modified UTF-7 for both UTF8=ACCEPT and IMAP4rev2 connections.
- PRECIS username and password preparation (RFC 8265). Usernames and
  passwords are now normalized before authentication using the three
  PRECIS profiles: UsernameCasePreserved for plaintext protocols
  (LOGIN, PLAIN, AUTH=LOGIN, HTTP Basic/Digest, LDAP bind),
  UsernameCaseMapped for SASL mechanisms that compute hashes client-side
  (CRAM-MD5, DIGEST-MD5), and OpaqueString for passwords. Processing
  includes width mapping (fullwidth/halfwidth decomposition), PRECIS
  IdentifierClass/FreeformClass validation, NFC normalization, non-ASCII
  space mapping (for passwords), and RFC 5893 Bidi Rule enforcement
  (for usernames). Full CONTEXTJ/CONTEXTO rule validation per RFC 5892
  Appendix A. New build dependency: libunistring.

### Fixed

- Fix IMAP capability handling: refresh capabilities after login
  (RFC 9051 §6.2.2). Previous versions used pre-auth capabilities for
  the entire session, missing post-auth extensions like SORT, MOVE,
  COMPRESS, LIST-STATUS, and NOTIFY. Parse `[CAPABILITY ...]` from
  server greeting and auth OK response code when available, saving up
  to two round-trips per connection. Falls back to explicit CAPABILITY
  command when not available.
- Fix RFC 2047 encoded-word NUL byte injection (Mailsploit class).
  Strip NUL bytes and C0 control characters from decoded header
  output at the ostrstream level before C string conversion.
  Prevents display-name spoofing that bypasses DMARC. All 15
  TextFrom1522 call sites protected.
- Fix mailto: URI header injection. Restrict accepted parameters
  to safe allowlist (to, cc, subject, body per RFC 6068 §5). Strip
  CR/LF from header parameters to prevent header injection via
  percent-encoded newlines. Remove bcc acceptance and
  x-mulberry-file local file attachment parameter.
- Fix attachment filename RLO spoofing. Strip Unicode bidirectional
  control characters (U+200E-200F, U+202A-202E, U+2066-2069) from
  filenames to prevent Right-to-Left Override display attacks that
  disguise file extensions.
- Fix HTML URI scheme injection. Only create clickable links for
  known-safe URI schemes (http, https, mailto, ftp, webcal).
  Blocks javascript:, vbscript:, data:, and unknown schemes from
  being passed to the OS.
- Fix HTML base tag hijacking. Disable `<base>` href extraction
  from email HTML to prevent malicious relative URL redirection.
  Strip iframe, frame, frameset, and object tags as
  defense-in-depth.
- Fix mailto: URI fragment identifier handling and scheme parsing
  (RFC 6068 compliance). Strip fragment identifiers before parsing
  parameters. Replace fragile strtok-based scheme extraction with
  proper colon-delimited split.
- Fix LDAP STARTTLS accepting invalid certificates.
  LDAP_OPT_X_TLS_ALLOW changed to LDAP_OPT_X_TLS_DEMAND for
  STARTTLS connections, matching the SSL path which already uses
  LDAP_OPT_X_TLS_HARD.
- Fix IMAP EXISTS race condition in STORE/FETCH/COPY response
  parsers. Replace blanket try-catch with explicit bounds check
  against GetNumberFound() to avoid masking unrelated exceptions.
- Fix BOM detection for mislabeled charsets. Detect UTF-8 and
  UTF-16 byte order marks at the CCharsetManager::ToUTF8 entry
  point and override the declared charset when mislabeled.
- Fix cross-server copy losing destination UIDs. Store source-to-
  destination UID mapping in copy_uids after APPEND in the
  cross-server copy path.
- Fix CalDAV/CardDAV DELETE losing concurrent server modifications.
  DELETE requests now include an If-Match header with the component's
  ETag. The server returns 412 Precondition Failed if the item was
  modified by another client since the last fetch, instead of
  silently overwriting the change.
- Fix calendar default timezone hardcoded to US/Eastern. Now reads
  from /etc/localtime symlink (Linux, macOS) with /etc/timezone
  fallback (Debian/Ubuntu). Falls back to UTC. Win32: deferred
  (requires CLDR windowsZones.xml mapping table).
- Fix single-instance forwarding on Linux. Passing a `mailto:` URL,
  `.ics` file, or any argument to Mulberry while it is already running
  now forwards to the existing instance instead of launching a second
  one. Root cause: the MDI socket name was derived from a legacy
  `"cyrusoft-mulberry"` signature, while the running instance registered
  under `"Mulberry"` — the two never matched.
- Fix IMAP connection recovery after server restart or network
  interruption. Dead connections left open folders in a non-functional
  zombie state with no way to recover. Root cause: iostream exceptions
  not recognized as network errors, bypassing all recovery. Also
  fixed dead connections returned from the connection pool and an
  O(N²) loop during mailbox recovery.
- Fix O(N²) performance during bulk FETCH on large mailboxes.
  GetNumberUnseen() called CountFlags() which scanned the entire
  message list on every flag change, and MessageChanged() queued
  per-message UI tasks whose processing blocked the IMAP thread.
  On mailboxes with 100k+ messages, recovery could take 20+ minutes
  instead of seconds. Fixed by using the maintained unseen counter
  directly and suppressing per-message UI notifications during
  bulk fetch operations.
- Fix background mailbox tabs closing instead of reconnecting.
  When switching back to a mailbox tab after idle time, the IMAP
  connection may have died (server timeout). Previously, the tab
  assumed the connection was alive, hit the dead connection, and
  closed the folder. Now verifies and re-opens if needed.
- Fix ACE_Thread_ID::operator== returning inverted result on Linux
  (macOS and Windows unaffected — they use native thread ID types).
  pthread_equal() returns non-zero for equal threads, but the
  comparison used == 0. This silently broke all mutex recursion on
  Linux: cdomutex deadlocked on re-entry (despite having full
  recursion code), and cdmutex never enforced mutual exclusion
  between threads. The architecture's implicit serialization
  (per-mailbox connections, single-threaded UI) masked the broken
  mutexes. Fixed by changing == 0 to != 0 in the ACE submodule.
- Comprehensive concurrency audit fixing 21 crash sites in CMbox
  where mOpenInfo->mMsgMailer was dereferenced without protection
  against concurrent mailbox close. Applied Cyrus's OpenIfOpen()
  refcount pattern (previously used on only 2 methods) to all
  methods that do network I/O through the per-mailbox connection
  clone. Also fixed: Recover() deleting messages without notifying
  open windows (dangling CMessage pointers), sPeriodics vector
  data race, TCPSelectYield/TLSReceiveData yield guards,
  TCPSendData arithmetic bug, and 5 additional protocol reconnect
  guards.
- Fix TLS teardown crash during search. SSL_connect/SSL_read/
  SSL_write loops yield to process UI events; if the connection
  is torn down by another thread during the yield, the SSL
  object becomes NULL. Guard all three TLS operations against
  connection teardown during yield.
- Fix connection drop rendering Mulberry permanently unusable.
  Two fixes: clear the error recovery flag after failed reconnection
  (previously stuck permanently, blocking all server communication),
  and recover dead per-mailbox connections on demand (previously,
  open folders became silently non-functional after a transient
  network interruption). Both bugs have existed for the entire life
  of the open-source release.
- Fix crash when cancelling timezone "Other..." dialog on Linux.
  The CTimezonePopup::mOldValue member was uninitialized, causing
  the popup to use a garbage index value on cancel. Also fix
  the "Other..." dialog not appearing immediately in the event
  editor (was deferred until form read).
- Fix SMTP AUTH EXTERNAL sending empty base64 instead of "=" for
  zero-length initial response. Fix missing re-EHLO after successful
  AUTH (server capabilities may change). Differentiate 4xx temporary
  failures from 5xx permanent failures in SMTP queue handling.
- Fix offline flag sync using wrong flag for draft messages (IsDraft
  check used IsAnswered value — copy-paste error in SyncRemote).
- Fix mailbox hierarchy search silently broken: unsigned loop variable
  made the search condition always false, so new mailboxes were never
  found in existing hierarchies (OpenMbox).
- Fix ~300 issues found by static analysis tools (Coverity, Infer,
  CodeQL, cppcheck, clang-tidy). Notable categories: allocation/
  deallocation mismatches (strdup/malloc freed with delete[]),
  invalid iterator use after vector erase, null pointer dereferences
  (unchecked dynamic_cast, find, return values), uncaught exceptions
  in destructors (std::terminate risk), uninitialized members,
  unsigned integer underflow, printf format mismatches, missing
  break in switch, non-array delete, copy-paste errors, use-after-free
  in stack operations, double-scaled pointer arithmetic in UTF-16,
  and resource leaks.
- Fix recurrence frequency not saving in calendar event repeat dialog.
  The frequency popup (Daily/Weekly/Monthly/Yearly) was read from the
  wrong control (the end-condition radio group instead of the frequency
  dropdown), so the saved frequency was always wrong. Copy-paste bug
  in Linux platform code; Mac and Win32 were correct.
- Fix calendar event cross mark constant (copy-paste: same bytes as
  tick mark). Wire up cross mark prefix for cancelled events.
- Change default recurrence frequency from Yearly to Daily (all
  platforms), matching Google Calendar, Outlook, and Thunderbird.
- Add check mark, heavy check mark, ballot X, and heavy ballot X to
  typographic substitution table for calendar status display.
- Fix mojibake in messages containing a UTF-8 byte-order mark (BOM).
  Several mail clients (notably Outlook and iOS Mail) embed BOMs in
  their messages, which caused Mulberry's UTF-16 converter to flip
  byte order, garbling all subsequent characters. A BOM at the start
  of a message garbled the entire message; a BOM mid-stream (common
  in quoted reply text) garbled everything after it.
- Fix format=flowed delsp buffer boundary bug. When a trailing space
  for delsp fell exactly on an 8KB filter buffer boundary, it was not
  removed, producing extra spaces in the displayed text. Documented by
  original author as a known bug (`FIXME` comment) but never fixed.
- Fix spurious blank lines in messages from the Microsoft mail stack
  (Outlook, Exchange). These products QP-encode bare carriage returns
  in message bodies, which were rendered as extra blank lines instead
  of being normalized per RFC 5322 section 4.
- Fix preferences corruption and offline mail cache corruption on
  64-bit systems. Several on-disk data structures used `unsigned long`
  (8 bytes on LP64, 4 bytes on ILP32) for fields that are serialized
  as 4 bytes, causing silent data corruption. In the case of
  preferences, a corrupted version stamp triggered an infinite rewrite
  loop causing 100% CPU and eventual out-of-memory crash.
- Fix "Undisclosed recipients:;" appearing as a reply target when
  replying to messages with empty group addresses.
- Fix 12-hour time display on Debian/Ubuntu despite 24-hour locale
  setting (missing `setlocale()` call at startup).
- Fix auto-save drafts interval checkbox being non-functional
  (duplicated condition checked wrong control).
- Replace deprecated 3DES with AES-128-CBC for S/MIME encryption.
  3DES was withdrawn by NIST in 2023 and is vulnerable to Sweet32
  attacks on large messages. AES-128-CBC is the current standard
  across modern S/MIME implementations.
- Replace SHA-1 with SHA-256 for PGP signatures. SHA-1 is broken
  for collision attacks since 2017 (SHAttered) and has been deprecated
  by GPG since 2019. SHA-256 is universally supported by all current
  OpenPGP implementations.
- Modernize internal keyring encryption from MD5+RC4 to Argon2id
  key derivation and XChaCha20-Poly1305 authenticated encryption
  via libsodium. Fix keyring file permissions to 0600.
- Replace MD5 hashing in Message-ID and MIME boundary generation
  with libsodium random bytes. Provides better entropy and
  eliminates platform-specific random number generation.
- Replace SHA-1 with SHA-256 for X.509 certificate fingerprints.
- Replace 3DES with AES-256-CBC for private key file encryption.
- Fix HTML attribute values with non-ASCII characters being
  truncated. Quoted attribute values (alt text, URLs, etc.)
  containing characters outside US-ASCII were cut off at the
  first non-ASCII character.
- Fix empty HTML attribute values (`=""`) causing subsequent
  attributes to be consumed as part of the value.
- Fix use-after-free in JX string insert and replace operations
  when the source data pointed into the string being modified.
- Fix missing comma concatenating adjacent string literals in match
  descriptors, memory leaks on realloc failure, and uninitialized
  variables in HTTP content handling and window setup.

### Removed

- Bundled OpenSSL 0.9.8m library (22MB). Mulberry uses the system
  OpenSSL via dynamic loading; the bundled copy was unused.
- Bundled PCRE 4.5 (from 2004) and GNU regex from the JX toolkit.
  Mulberry now links system libpcre3 and glibc regex, eliminating
  multiple Coverity findings in the outdated bundled copies.
- Dead `cSTATUS_CHECK` constant (unreferenced; STATUS attributes are
  built dynamically).
- Obsolete `lround()` polyfill that conflicted with modern C library
  headers.

## Prior history

Mulberry was created by Cyrus Daboo and Matt Wall in 1995, originally
for Macintosh, and developed primarily by Daboo ever since. It was
marketed commercially by Cyrusoft International, Inc. (later ISAMET,
Inc.), a company Daboo co-founded. Windows support was added by 2000,
and the first Linux release followed in February 2001 (v2.0.6).
Following ISAMET's Chapter 7 bankruptcy in October 2005, Daboo
acquired the source code rights and made Mulberry available at no
cost in August 2006. The last commercial release was version 4.0.8
(February 2007). In November 2007, he released the full source as
open source under the Apache 2.0 license. Daboo continued development
into the 2010s, working toward a 4.1 release via a Subversion
repository at svn.mulberrymail.com (now offline). Commercial-era
changelogs are preserved in `Build/Bits/`.

In 2009, Martin Dietze ([mbert](https://github.com/mbert/mulberry-main))
ported the Subversion repository to GitHub and maintained the fork
until 2016, cherry-picking patches from Daboo's SVN and achieving
working builds on Linux and macOS.

Several other contributors made notable contributions during the
GitHub era: Kenneth Porter (Win32 builds, fixes, and modernization),
Mike Alexander (GSSAPI Kerberos improvements and build fixes), Lutz
Pogrell (vCard/CalDAV enhancements and GPG signing fix), and Quanah
Gibson-Mount (Visual Studio 2019 support). Their work, and mbert's,
is greatly appreciated and preserved in git history. None of it would
exist without Cyrus Daboo's remarkable two decades of solo development
and his decision to open-source the result.

[4.2a1]: https://github.com/yitzhaq/mulberry-main/releases/tag/v4.2a1
