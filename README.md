# Mulberry

Mulberry is a standards-focused desktop email and calendaring client
for Linux, macOS, and Windows. Built around IMAP from the ground up,
it emphasizes server-side operations — searching, sorting, filtering,
and threading happen on the server rather than locally, making it
efficient with large mailboxes. It supports IMAP4rev1, POP3, SMTP,
CalDAV, CardDAV, LDAP, SIEVE, ManageSieve, S/MIME, PGP, and more,
with features including multiple account and identity management,
IMAP ACLs for shared folders, a GUI for server-side Sieve filtering,
offline mail caching, and calendar/address book synchronization.

Mulberry's calendaring and contacts support is equally thorough —
its original author co-authored the CalDAV RFC and authored the
CardDAV RFC, and Mulberry was an early and complete implementation
of both. It works well against modern CalDAV/CardDAV servers such
as Nextcloud and Cyrus IMAPd.

The interface is consistent across all three platforms and
prioritizes control and efficiency over visual polish.

## Current status

**Version 4.2a1** — first version with significant development
activity in over a decade.

This version brings Mulberry to modern 64-bit Linux (x86_64) with
GCC 13+, OpenSSL 1.1–3.x, and current Debian/Ubuntu packaging.
It includes comprehensive bug fixes found through static analysis
with six tools (cppcheck, clang-tidy, Facebook Infer, GCC extended
warnings, CodeQL, and Coverity), improved RFC 3676 format=flowed
compliance, Unicode clipboard support, and recovery of sixteen
patches from the original developer's SVN repository.

Development and testing focused exclusively on Linux (x86_64,
Ubuntu 24.04, GCC 13). Some incidental fixes for Win32 and macOS
are included but are entirely untested.

See [CHANGELOG.md](CHANGELOG.md) for the full list of changes.

## Building

```sh
git clone --recursive https://github.com/yitzhaq/mulberry-main.git
cd mulberry-main
```

If you cloned without `--recursive`, run `git submodule update --init`
to fetch the required libraries.

### Debian/Ubuntu package (recommended)

```sh
sudo apt install build-essential autoconf libssl-dev libldap-dev \
    libaspell-dev libfontconfig-dev libfreetype-dev libxft-dev \
    libxext-dev libxpm-dev pkg-config zlib1g-dev debhelper
dpkg-buildpackage -us -uc -b
```

The `.deb` package appears in the parent directory. This builds
everything: the JX toolkit, the application, and all plugins.

### Manual build

```sh
autoconf
./configure
make
make install
```

Use `make SKIPJX="yes" install` to skip rebuilding the JX library
after the initial build.

See `./configure --help` for options (OpenSSL paths, LDAP paths,
Kerberos, aspell).

## Architecture

Mulberry uses a three-layer architecture:

```text
Platform UI (Linux/JX, macOS/PowerPlant, Win32/WinAPI)
     |
Sources_Common (platform-independent core)
     |
Libraries (JX, CICalendar, vCard, XMLLib) + Plugins
```

The platform-independent core in `Sources_Common/` implements all
protocol clients (IMAP, SMTP, POP3, CalDAV, CardDAV), the message
model, address books, calendars, preferences, and text processing.
Platform-specific directories provide the GUI layer using each
platform's native toolkit.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## History and acknowledgments

Mulberry is the work of Cyrus Daboo, who created it in 1995 and
developed it for nearly two decades — first commercially, then as
open source. This repository would not exist without his remarkable
effort and his decision to release the source. For the full history,
including contributions from Martin Dietze (mbert), Kenneth Porter
(SpareSimian), Mike Alexander (mtalexander), Lutz Pogrell
(lutzpogrell), and Quanah Gibson-Mount (quanah), see
[CHANGELOG.md](CHANGELOG.md).

The 4.2a1 development work was carried out entirely in collaboration
with [Claude](https://claude.ai) by Anthropic. The owner of this
repository is not a C++ developer; all code changes, analysis, and
documentation were produced through this collaboration.
