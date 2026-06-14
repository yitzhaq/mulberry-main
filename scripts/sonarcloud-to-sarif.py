#!/usr/bin/env python3
"""Pull SonarCloud issues via API and convert to SARIF 2.1.0 for GitHub Security tab."""

import json
import os
import sys
import urllib.request
import urllib.error

PROJECT_KEY = "yitzhaq_mulberry-main"
API_BASE = "https://sonarcloud.io/api"
PAGE_SIZE = 500
MAX_RESULTS = 5000  # GitHub SARIF upload limit

SEVERITY_MAP = {
    "BLOCKER": "error",
    "CRITICAL": "error",
    "MAJOR": "warning",
    "MINOR": "note",
    "INFO": "note",
}

# SonarCloud v2 impact severities (new taxonomy)
IMPACT_SEVERITY_MAP = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def fetch_issues(token):
    issues = []
    page = 1
    while True:
        url = (
            f"{API_BASE}/issues/search"
            f"?componentKeys={PROJECT_KEY}"
            f"&statuses=OPEN,CONFIRMED,REOPENED"
            f"&types=BUG,VULNERABILITY"
            f"&ps={PAGE_SIZE}"
            f"&p={page}"
        )
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            print(f"API error {e.code}: {e.read().decode()}", file=sys.stderr)
            sys.exit(1)

        issues.extend(data.get("issues", []))
        paging = data.get("paging", {})
        total = paging.get("total", 0)
        print(f"Page {page}: fetched {len(data.get('issues', []))} issues ({len(issues)}/{total})")

        if len(issues) >= total or len(issues) >= MAX_RESULTS:
            break
        page += 1

    return issues[:MAX_RESULTS]


def issue_severity(issue):
    """Extract SARIF severity, handling both legacy and v2 impact taxonomies."""
    legacy = issue.get("severity")
    if legacy and legacy in SEVERITY_MAP:
        return SEVERITY_MAP[legacy]
    for impact in issue.get("impacts", []):
        s = impact.get("severity", "")
        if s in IMPACT_SEVERITY_MAP:
            return IMPACT_SEVERITY_MAP[s]
    return "warning"


def issue_to_result(issue):
    component = issue.get("component", "")
    file_path = component.replace(f"{PROJECT_KEY}:", "", 1)

    location = {"physicalLocation": {"artifactLocation": {"uri": file_path}}}
    text_range = issue.get("textRange")
    if text_range:
        region = {}
        if "startLine" in text_range:
            region["startLine"] = text_range["startLine"]
        if "endLine" in text_range:
            region["endLine"] = text_range["endLine"]
        if "startOffset" in text_range:
            region["startColumn"] = text_range["startOffset"] + 1  # SARIF is 1-based
        if "endOffset" in text_range:
            region["endColumn"] = text_range["endOffset"] + 1
        if region:
            location["physicalLocation"]["region"] = region

    return {
        "ruleId": issue.get("rule", "unknown"),
        "level": issue_severity(issue),
        "message": {"text": issue.get("message", "No message")},
        "locations": [location],
    }


def build_sarif(results):
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SonarCloud",
                        "informationUri": f"https://sonarcloud.io/project/overview?id={PROJECT_KEY}",
                    }
                },
                "results": results,
            }
        ],
    }


def main():
    token = os.environ.get("SONAR_TOKEN")
    if not token:
        print("Error: SONAR_TOKEN environment variable not set", file=sys.stderr)
        sys.exit(1)

    issues = fetch_issues(token)
    print(f"Fetched {len(issues)} issues total")

    results = [issue_to_result(i) for i in issues]
    sarif = build_sarif(results)

    output = "sonarcloud.sarif"
    with open(output, "w") as f:
        json.dump(sarif, f, indent=2)

    size_mb = os.path.getsize(output) / (1024 * 1024)
    print(f"Wrote {output} ({len(results)} results, {size_mb:.1f} MB)")

    if size_mb > 10:
        print("WARNING: SARIF file exceeds 10 MB GitHub upload limit", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
