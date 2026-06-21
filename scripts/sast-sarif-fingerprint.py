#!/usr/bin/env python3
"""Inject a stable, context-insensitive partialFingerprint into every SARIF result
so GitHub code scanning matches alerts across uploads -- i.e. dismissals persist --
even when line numbers shift or lines next to a finding change.

Why this exists: GitHub links an incoming SARIF result to an existing alert by
fingerprint. Tools that emit no fingerprint (or a context-sensitive one) let GitHub
fall back to a hash of the source AROUND the finding, so an edit on a neighbouring
line, or any line-number shift, mints a brand-new (open) alert while the old
dismissal lingers -- a "twin". Run this on a tool's SARIF before upload-sarif.

Fingerprint material = ruleId + repo-relative path + the finding's OWN source line
(from region.snippet if the tool embedded it, else read from the file in the CI
workspace). The line NUMBER is deliberately excluded so the id survives edits above
the finding; the line CONTENT keeps distinct findings distinct. A per-material
occurrence counter disambiguates the rare case of identical lines flagged by the
same rule in the same file. The value is written to partialFingerprints
.primaryLocationLineHash (the key GitHub uses), overriding any context-sensitive
fingerprint the tool supplied.

Tool-agnostic: used for CodeChecker and PVS-Studio. SonarCloud is handled in
sonarcloud-to-sarif.py, which already emits the stable SonarCloud issue key (an
even better id, since it survives content changes too).
"""
import hashlib
import json
import os
import sys
import urllib.parse

WS = os.environ.get("GITHUB_WORKSPACE", os.getcwd())


def _to_abs(uri):
    if uri.startswith("file:"):
        uri = urllib.parse.urlparse(uri).path
    uri = os.path.normpath(uri)
    return uri if os.path.isabs(uri) else os.path.join(WS, uri)


def _to_rel(uri):
    try:
        return os.path.relpath(_to_abs(uri), WS)
    except ValueError:
        return os.path.normpath(uri)


def _read_line(uri, line):
    try:
        with open(_to_abs(uri), "r", errors="replace") as f:
            for i, ln in enumerate(f, 1):
                if i == line:
                    return ln.strip()
    except OSError:
        return None
    return None


def fingerprint(path):
    with open(path) as f:
        sarif = json.load(f)
    counts = {}
    total = by_content = by_fallback = 0
    for run in sarif.get("runs", []):
        for r in run.get("results", []):
            loc = ((r.get("locations") or [{}])[0] or {}).get("physicalLocation", {}) or {}
            uri = (loc.get("artifactLocation") or {}).get("uri", "") or ""
            region = loc.get("region") or {}
            line = region.get("startLine")
            rule = r.get("ruleId", "")
            rel = _to_rel(uri) if uri else ""
            snippet = (region.get("snippet") or {}).get("text")
            content = snippet.strip() if snippet else (_read_line(uri, line) if (uri and line) else None)
            if content:
                material = f"{rule}\x00{rel}\x00{content}"
                by_content += 1
            else:
                material = f"{rule}\x00{rel}\x00L{line}"
                by_fallback += 1
            occ = counts.get(material, 0)
            counts[material] = occ + 1
            if occ:
                material = f"{material}\x00#{occ}"
            digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()
            r.setdefault("partialFingerprints", {})["primaryLocationLineHash"] = digest
            total += 1
    with open(path, "w") as f:
        json.dump(sarif, f)
    print(f"[fingerprint] {path}: {total} results "
          f"({by_content} by line-content, {by_fallback} by line-number fallback)")
    return by_fallback


if __name__ == "__main__":
    fallback = 0
    for p in sys.argv[1:]:
        fallback += fingerprint(p)
    if fallback:
        # Non-fatal: a high fallback count means source content was not resolvable
        # (path mismatch / missing snippet); those ids are less stable. Never block
        # the upload over it.
        print(f"[fingerprint] WARNING: {fallback} result(s) used the line-number "
              f"fallback (less stable across edits)", file=sys.stderr)
