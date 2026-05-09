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
  attributes and CHILDINFO extended data.
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
  keys for server-side display name sorting.
- IMAP ESORT (RFC 5267). Compact ESEARCH-format responses for
  SORT commands via RETURN (ALL).
- IMAP WITHIN (RFC 5032). OLDER and YOUNGER search keys for
  date-relative searches (e.g., messages from the last N days).
- IMAP IDLE (RFC 2177). Server-push notifications replacing NOOP
  polling. Delivers new mail notifications in under one second.
  Re-IDLEs every 29 minutes. Falls back to NOOP polling on
  servers without IDLE support.
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
- IMAP COMPRESS=DEFLATE (RFC 4978). Reduces IMAP bandwidth by
  60-75% using zlib compression. Activated automatically after
  login when the server supports it. Includes decompression bomb
  protection and graceful fallback on failure.
- IMAP INPROGRESS (RFC 9585). Server progress notifications for
  long-running commands displayed in the status bar.
- SMTP PIPELINING (RFC 2920). Send MAIL FROM and RCPT TO commands
  in a single batch, reducing latency by (N-1) round-trips for N
  recipients. Falls back to synchronous on servers without support.
- SMTP Enhanced Status Codes (RFC 2034/3463). Parse x.y.z status
  codes from SMTP responses for detailed error diagnostics with
  full RFC 3463 status code registry.
- Fix SMTP partial recipient failure: one rejected RCPT TO no
  longer aborts the entire message. Valid recipients still receive
  the message when others are rejected.
- Fix filter rules using COPY+DELETE instead of atomic MOVE (RFC
  6851) when moving messages. MOVE was implemented but the filter
  pipeline was never updated to use it.
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

### Added

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
- Unicode clipboard support on Linux. Copy and paste of non-ASCII text
  (accented characters, CJK, etc.) now works correctly with modern
  desktop applications via UTF8_STRING X11 selection.
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
- Visual Studio 2019 build support (Win32, untested).
  Contributed by Quanah Gibson-Mount.

### Fixed

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
