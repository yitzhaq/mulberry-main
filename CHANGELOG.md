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
- Show `[U+XXXXX]` placeholder for emoji and other characters above the
  Basic Multilingual Plane, instead of silently replacing them with `?`.
  This affects Linux and macOS, where the GUI toolkits (JX and
  PowerPlant) cannot render characters outside the BMP. The Win32 build
  may handle these natively, but this has not been tested.
- Timezone database updated from 2008 (tzdata2008i) to current IANA
  data. Timezone files are now generated at build time from the latest
  IANA source via vzic, so they stay current with each build. Fixes
  18 years of DST rule changes affecting calendar operations.
- Modernize Debian packaging with desktop entry, AppStream metadata,
  updated dependencies, and lintian compliance.

### Added

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
- Compose key and dead key support on modern Linux. Accented character
  input (e.g., AltGr+e for é) now works throughout the application.
  Limited to characters available in ISO 8859-1 (Western European) due
  to JX toolkit constraints; Eastern European and other accented
  characters beyond Latin-1 are not supported via compose sequences.
- Unicode clipboard support. Copy and paste of non-ASCII text (accented
  characters, CJK, etc.) now works correctly with modern desktop
  applications via UTF8_STRING selection.
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

- Fix connection drop rendering Mulberry permanently unusable. After any
  network interruption, the error recovery flag was never cleared,
  preventing all further server communication until restart. This bug
  has existed for the entire life of the open-source release.
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
- Fix numerous latent bugs discovered through comprehensive static
  analysis with cppcheck, clang-tidy, Facebook Infer, CodeQL, and
  extended GCC warnings. Notable finds include: use-after-free in stack
  operations, null pointer dereferences in message display and drag
  operations, double-scaled pointer arithmetic in UTF-16 string
  operations, missing comma concatenating adjacent string literals in
  match descriptors, array delete/delete mismatch in DIGEST-MD5 plugin,
  memory leaks on realloc failure, uninitialized variables in
  HTTP content handling and window setup, and 23 allocation/deallocation
  mismatches (strdup freed with delete, new[] freed with delete).

### Removed

- Bundled OpenSSL 0.9.8m library (22MB). Mulberry uses the system
  OpenSSL via dynamic loading; the bundled copy was unused.
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
