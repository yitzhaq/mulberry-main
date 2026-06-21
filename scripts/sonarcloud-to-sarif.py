#!/usr/bin/env python3
"""Pull SonarCloud issues via API and convert to SARIF 2.1.0 for GitHub Security tab."""

import json
import os
import sys
import time
import urllib.request
import urllib.error

PROJECT_KEY = "yitzhaq_mulberry-main"
API_BASE = "https://sonarcloud.io/api"
PAGE_SIZE = 500
MAX_RESULTS = 5000  # GitHub SARIF upload limit
REPORT_TASK = os.environ.get("SONAR_REPORT_TASK", ".scannerwork/report-task.txt")
CE_WAIT_TIMEOUT = 900  # seconds to wait for SonarCloud Compute Engine processing

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


def api_get(url, token):
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def wait_for_ce_task(token):
    """Block until the analysis this CI run just submitted is fully processed.

    The scanner writes .scannerwork/report-task.txt with the Compute Engine task
    id; the issues API only reflects the new analysis once that task reaches
    SUCCESS. Without this wait the export races the (asynchronous) CE processing
    and reads the PREVIOUS analysis, so fixed findings linger in the Security tab.
    """
    if not os.path.exists(REPORT_TASK):
        print(f"warning: {REPORT_TASK} not found; exporting without CE wait "
              f"(results may lag one analysis)", file=sys.stderr)
        return
    props = {}
    for line in open(REPORT_TASK):
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v
    task_id = props.get("ceTaskId")
    if not task_id:
        print("warning: no ceTaskId in report-task.txt; exporting without CE wait",
              file=sys.stderr)
        return

    deadline = time.monotonic() + CE_WAIT_TIMEOUT
    while True:
        status = api_get(f"{API_BASE}/ce/task?id={task_id}", token).get("task", {}).get("status")
        print(f"CE task {task_id}: {status}")
        if status == "SUCCESS":
            return
        if status in ("FAILED", "CANCELED"):
            print(f"warning: CE task ended {status}; exporting prior analysis", file=sys.stderr)
            return
        if time.monotonic() >= deadline:
            print("warning: timed out waiting for CE task; results may lag", file=sys.stderr)
            return
        time.sleep(5)


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

    result = {
        "ruleId": issue.get("rule", "unknown"),
        "level": issue_severity(issue),
        "message": {"text": issue.get("message", "No message")},
        "locations": [location],
    }

    # Stable fingerprint so GitHub tracks each SonarCloud issue 1:1 across SARIF
    # uploads instead of closing the whole batch and re-opening fresh alerts every
    # scan. The SonarCloud issue key is globally unique and persists across
    # analyses while the issue stays open.
    key = issue.get("key")
    if key:
        result["partialFingerprints"] = {"sonarIssueKey/v1": key}

    return result


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

    wait_for_ce_task(token)

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
