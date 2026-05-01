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
  `[:waving hand:]` for 👋); Unicode mathematical styled letters
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
  from being rendered as visible text in HTML messages.
- Use `aria-label` and `title` attributes as fallback for image
  alt text in HTML messages, before falling back to the filename.
- Replace custom XML parser with system libxml2 for CalDAV, CardDAV,
  WebDAV, and address book XML parsing. Adds XXE protection, entity
  expansion limits, and network access blocking. The custom parser
  (XMLSAXSimple) remains available as fallback via --without-libxml2.
- IMAP APPENDLIMIT extension (RFC 7889). Parse server-advertised
  maximum message size from CAPABILITY and STATUS responses. Reject
  oversized APPENDs before transmission with a clear error message.
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
- Modernize Debian packaging with desktop entry, AppStream metadata,
  updated dependencies, and lintian compliance.

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
  server, aiding server-side diagnostics and statistics.
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
- Fix 36 issues found by Infer static analysis (biabduction + Pulse):
  32 null dereferences across mail core, UI, calendar, and plugin
  code (unchecked GetEnvelope, GetAttachment, GetNode, GetCellMbox,
  dynamic_cast, and malloc results), 4 uninitialized POD members in
  preference structs (SColumnInfo, SFontInfo, SStyleTraits,
  SStyleTraits2), and an operator precedence bug in TPopupMenu::Draw
  on Linux.
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
- Fix numerous latent bugs discovered through comprehensive static
  analysis with cppcheck, clang-tidy, Facebook Infer, CodeQL,
  Coverity, and extended GCC warnings. Notable finds include:
  use-after-free in stack operations, null pointer dereferences in
  message display and drag operations, double-scaled pointer
  arithmetic in UTF-16 string operations, missing comma concatenating
  adjacent string literals in match descriptors, array delete/delete
  mismatch in DIGEST-MD5 plugin, memory leaks on realloc failure,
  uninitialized variables in HTTP content handling and window setup,
  and 23 allocation/deallocation mismatches (strdup freed with delete,
  new[] freed with delete).

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
