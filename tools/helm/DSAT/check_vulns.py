#!/usr/bin/env python3
"""
InsightAppSec Vulnerability Checker for TeamCity Pipelines.

Looks up an application by name, finds its latest completed scan,
retrieves vulnerabilities from that scan, and logs a report.

Usage:
    export RAPID7_API_KEY="your-api-key"
    python check_vulns.py --app "My Application"
    python check_vulns.py --app "My Application" --fail-on CRITICAL
    python check_vulns.py --app "My Application" --fail-on NONE --json
"""

import argparse
import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["SAFE", "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

EXCLUDED_STATUSES = {"FALSE_POSITIVE", "REMEDIATED", "DUPLICATE", "IGNORED"}

REGION_BASE_URLS = {
    "us":  "https://us.api.insight.rapid7.com/ias/v1",
    "us2": "https://us2.api.insight.rapid7.com/ias/v1",
    "us3": "https://us3.api.insight.rapid7.com/ias/v1",
    "eu":  "https://eu.api.insight.rapid7.com/ias/v1",
    "ca":  "https://ca.api.insight.rapid7.com/ias/v1",
    "au":  "https://au.api.insight.rapid7.com/ias/v1",
    "ap":  "https://ap.api.insight.rapid7.com/ias/v1",
}

PAGE_SIZE = 500  # max 1000, keep reasonable


# ---------------------------------------------------------------------------
# API Client
# ---------------------------------------------------------------------------

class InsightAppSecClient:
    """Thin wrapper around the InsightAppSec REST API."""

    def __init__(self, api_key: str, region: str = "us3"):
        base = REGION_BASE_URLS.get(region)
        if not base:
            raise ValueError(
                f"Unknown region '{region}'. Valid: {', '.join(REGION_BASE_URLS)}"
            )
        self.base_url = base
        self.session = requests.Session()
        self.session.headers.update({
            "X-Api-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    # -- low-level helpers ---------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _search(
        self,
        resource_type: str,
        query: str,
        size: int = PAGE_SIZE,
        sort: str | None = None,
        index: int = 0,
    ) -> dict:
        """POST /search with the InsightAppSec query DSL."""
        url = f"{self.base_url}/search"
        params: dict = {"index": index, "size": size}
        if sort:
            params["sort"] = sort
        body = {"type": resource_type, "query": query}
        resp = self.session.post(url, json=body, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _search_all(
        self,
        resource_type: str,
        query: str,
        sort: str | None = None,
    ) -> list[dict]:
        """Paginate through all search results."""
        all_data: list[dict] = []
        index = 0
        while True:
            page = self._search(resource_type, query, size=PAGE_SIZE, sort=sort, index=index)
            data = page.get("data", [])
            all_data.extend(data)
            metadata = page.get("metadata", {})
            total = metadata.get("total_data", 0)
            if len(all_data) >= total or not data:
                break
            # Use page_token if available (needed beyond 10k results)
            page_token = metadata.get("page_token")
            if page_token:
                # For token-based paging, we re-request with token instead of index
                url = f"{self.base_url}/search"
                params: dict = {"size": PAGE_SIZE, "page-token": page_token}
                if sort:
                    params["sort"] = sort
                body = {"type": resource_type, "query": query}
                resp = self.session.post(url, json=body, params=params, timeout=30)
                resp.raise_for_status()
                token_page = resp.json()
                token_data = token_page.get("data", [])
                if not token_data:
                    break
                all_data.extend(token_data)
                metadata = token_page.get("metadata", {})
                total = metadata.get("total_data", total)
                page_token = metadata.get("page_token")
                if not page_token or len(all_data) >= total:
                    break
                continue
            index += 1
        return all_data

    # -- domain methods ------------------------------------------------------

    def find_app(self, app_name: str) -> dict:
        """Find an app by exact name. Raises if not found or ambiguous."""
        results = self._search("APP", f"app.name = '{app_name}'")
        data = results.get("data", [])
        if not data:
            raise SystemExit(f"ERROR: No application found with name '{app_name}'")
        if len(data) > 1:
            names = [a.get("name", "?") for a in data]
            raise SystemExit(
                f"ERROR: Multiple apps matched '{app_name}': {names}. "
                "Use the exact name."
            )
        return data[0]

    def find_latest_scan(self, app_id: str) -> dict | None:
        """Find the most recent COMPLETE scan for an app."""
        query = f"scan.app.id = '{app_id}' && scan.status = 'COMPLETE'"
        results = self._search(
            "SCAN", query, size=1, sort="scan.completion_time,DESC"
        )
        data = results.get("data", [])
        return data[0] if data else None

    def get_vulns_for_scan(self, app_id: str, scan_id: str) -> list[dict]:
        """Get all vulnerabilities discovered in a specific scan."""
        query = (
            f"vulnerability.app.id = '{app_id}' "
            f"&& vulnerability.scans.id = '{scan_id}'"
        )
        return self._search_all(
            "VULNERABILITY", query, sort="vulnerability.severity,DESC"
        )

    def get_vulns_for_app(self, app_id: str) -> list[dict]:
        """Get all current vulnerabilities for an app (no scan filter)."""
        query = f"vulnerability.app.id = '{app_id}'"
        return self._search_all(
            "VULNERABILITY", query, sort="vulnerability.severity,DESC"
        )


# ---------------------------------------------------------------------------
# Report Formatting
# ---------------------------------------------------------------------------

def filter_vulns(vulns: list[dict], include_statuses: set[str] | None = None) -> list[dict]:
    """Filter out non-actionable vulnerability statuses."""
    if include_statuses is None:
        return [v for v in vulns if v.get("status") not in EXCLUDED_STATUSES]
    return [v for v in vulns if v.get("status") in include_statuses]


def severity_counts(vulns: list[dict]) -> dict[str, int]:
    """Count vulns by severity."""
    counts: dict[str, int] = {}
    for sev in SEVERITY_ORDER:
        counts[sev] = 0
    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def format_table(vulns: list[dict], max_url_width: int = 70) -> str:
    """Format vulns as a text table for log output."""
    if not vulns:
        return "  (no vulnerabilities found)\n"

    lines: list[str] = []
    hdr = f"  {'SEVERITY':<14} {'STATUS':<14} {'CVSS':>5}  {'METHOD':<6} {'URL'}"
    lines.append(hdr)
    lines.append("  " + "-" * (len(hdr) - 2))

    for v in vulns:
        sev = v.get("severity", "?")
        status = v.get("status", "?")
        score = v.get("vulnerability_score")
        score_str = f"{score:.1f}" if score is not None else "  -"
        rc = v.get("root_cause", {}) or {}
        method = rc.get("method", "-") or "-"
        url = rc.get("url", "-") or "-"
        if len(url) > max_url_width:
            url = url[: max_url_width - 3] + "..."
        lines.append(f"  {sev:<14} {status:<14} {score_str:>5}  {method:<6} {url}")

    return "\n".join(lines) + "\n"


def format_summary(counts: dict[str, int], total: int) -> str:
    """One-line summary of severity distribution."""
    parts = []
    for sev in reversed(SEVERITY_ORDER):
        c = counts.get(sev, 0)
        if c > 0:
            parts.append(f"{sev}: {c}")
    return f"  Total: {total} | " + " | ".join(parts) if parts else f"  Total: {total}"


def format_report(
    app: dict,
    scan: dict | None,
    vulns: list[dict],
    scan_mode: str,
) -> str:
    """Build the full text report."""
    lines: list[str] = []
    sep = "=" * 72

    lines.append(sep)
    lines.append("  InsightAppSec Vulnerability Report")
    lines.append(sep)
    lines.append(f"  Application : {app.get('name', '?')}")
    lines.append(f"  App ID      : {app.get('id', '?')}")

    if scan:
        lines.append(f"  Scan ID     : {scan.get('id', '?')}")
        lines.append(f"  Scan Status : {scan.get('status', '?')}")
        ct = scan.get("completion_time", "?")
        lines.append(f"  Completed   : {ct}")
    else:
        lines.append(f"  Scan        : {'(all vulns — no scan filter)' if scan_mode == 'all' else '(no completed scans found)'}")

    lines.append(f"  Report Time : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append(sep)

    filtered = filter_vulns(vulns)
    counts = severity_counts(filtered)
    total = len(filtered)

    lines.append("")
    lines.append(format_summary(counts, total))
    lines.append("")
    lines.append(format_table(filtered))
    lines.append(sep)

    # Also show what was excluded
    excluded_count = len(vulns) - total
    if excluded_count > 0:
        lines.append(
            f"  ({excluded_count} vulns excluded with status: "
            f"{', '.join(sorted(EXCLUDED_STATUSES))})"
        )
        lines.append(sep)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Threshold Gate
# ---------------------------------------------------------------------------

def check_threshold(vulns: list[dict], fail_on: str) -> tuple[bool, str]:
    """
    Check if any filtered vuln meets or exceeds the fail-on severity.
    Returns (should_fail, reason).
    """
    if fail_on == "NONE":
        return False, ""

    filtered = filter_vulns(vulns)
    threshold_idx = SEVERITY_ORDER.index(fail_on)

    failing = [
        v for v in filtered
        if v.get("severity") in SEVERITY_ORDER[threshold_idx:]
    ]

    if failing:
        counts = severity_counts(failing)
        parts = [f"{s}: {c}" for s, c in counts.items() if c > 0]
        reason = (
            f"Found {len(failing)} vuln(s) at or above {fail_on}: "
            + ", ".join(parts)
        )
        return True, reason

    return False, ""


# ---------------------------------------------------------------------------
# TeamCity Service Messages (optional nice-to-have)
# ---------------------------------------------------------------------------

def tc_message(text: str, status: str = "NORMAL") -> None:
    """Emit a TeamCity build status message."""
    # Escape per TC spec
    escaped = (
        text.replace("|", "||")
        .replace("'", "|'")
        .replace("\n", "|n")
        .replace("[", "|[")
        .replace("]", "|]")
    )
    print(f"##teamcity[message text='{escaped}' status='{status}']")


def tc_build_problem(description: str) -> None:
    """Report a build problem to TeamCity."""
    escaped = (
        description.replace("|", "||")
        .replace("'", "|'")
        .replace("\n", "|n")
        .replace("[", "|[")
        .replace("]", "|]")
    )
    print(f"##teamcity[buildProblem description='{escaped}']")


def tc_statistic(key: str, value: int | float) -> None:
    """Report a custom statistic to TeamCity."""
    print(f"##teamcity[buildStatisticValue key='{key}' value='{value}']")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check InsightAppSec vulnerabilities for an application.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Environment variables:
              RAPID7_API_KEY   (required) InsightAppSec API key
              RAPID7_REGION    (optional) Region code, default: us3

            Examples:
              python check_vulns.py --app "My App"
              python check_vulns.py --app "My App" --fail-on CRITICAL
              python check_vulns.py --app "My App" --fail-on NONE --json
              python check_vulns.py --app "My App" --all-vulns
        """),
    )
    p.add_argument(
        "--app", required=True,
        help="Exact application name in InsightAppSec",
    )
    p.add_argument(
        "--region", default=os.environ.get("RAPID7_REGION", "us3"),
        choices=sorted(REGION_BASE_URLS),
        help="Rapid7 region (default: us3, or RAPID7_REGION env var)",
    )
    p.add_argument(
        "--fail-on", dest="fail_on", default="HIGH",
        choices=[*SEVERITY_ORDER, "NONE"],
        help="Exit non-zero if vulns at this severity or above exist (default: HIGH). "
             "Use NONE for informational-only.",
    )
    p.add_argument(
        "--all-vulns", action="store_true",
        help="Report all app vulns instead of just the latest scan",
    )
    p.add_argument(
        "--include-dismissed", action="store_true",
        help="Include FALSE_POSITIVE, REMEDIATED, DUPLICATE, IGNORED vulns",
    )
    p.add_argument(
        "--json", dest="json_output", action="store_true",
        help="Output raw JSON instead of formatted table",
    )
    p.add_argument(
        "--no-tc", action="store_true",
        help="Suppress TeamCity service messages (for local testing)",
    )
    p.add_argument(
        "--api-key",
        default=os.environ.get("RAPID7_API_KEY", ""),
        help="API key (prefer RAPID7_API_KEY env var over this flag)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    api_key = args.api_key
    if not api_key:
        print("ERROR: No API key. Set RAPID7_API_KEY or use --api-key.", file=sys.stderr)
        return 1

    client = InsightAppSecClient(api_key, region=args.region)
    use_tc = not args.no_tc

    # -- Step 1: Find the app ------------------------------------------------
    print(f"Looking up application: {args.app}")
    app = client.find_app(args.app)
    app_id = app["id"]
    print(f"Found app: {app.get('name')} (id: {app_id})")

    # -- Step 2: Find latest scan (unless --all-vulns) -----------------------
    scan = None
    scan_mode = "latest"
    if args.all_vulns:
        scan_mode = "all"
        print("Mode: all vulnerabilities (no scan filter)")
    else:
        print("Searching for latest completed scan...")
        scan = client.find_latest_scan(app_id)
        if scan:
            print(
                f"Latest scan: {scan['id']} "
                f"(completed: {scan.get('completion_time', '?')})"
            )
        else:
            print("WARNING: No completed scans found. Falling back to all vulns.")
            scan_mode = "all"

    # -- Step 3: Fetch vulnerabilities ---------------------------------------
    print("Fetching vulnerabilities...")
    if scan and scan_mode == "latest":
        vulns = client.get_vulns_for_scan(app_id, scan["id"])
    else:
        vulns = client.get_vulns_for_app(app_id)

    if args.include_dismissed:
        global EXCLUDED_STATUSES
        EXCLUDED_STATUSES = set()

    print(f"Retrieved {len(vulns)} total vulnerabilities.")

    # -- Step 4: Report ------------------------------------------------------
    if args.json_output:
        filtered = filter_vulns(vulns)
        output = {
            "app": {"id": app_id, "name": app.get("name")},
            "scan": {"id": scan["id"], "completion_time": scan.get("completion_time")} if scan else None,
            "scan_mode": scan_mode,
            "summary": severity_counts(filtered),
            "total": len(filtered),
            "fail_on": args.fail_on,
            "vulnerabilities": filtered,
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        report = format_report(app, scan, vulns, scan_mode)
        print(report)

    # -- Step 5: TC service messages -----------------------------------------
    filtered = filter_vulns(vulns)
    counts = severity_counts(filtered)

    if use_tc:
        for sev, count in counts.items():
            tc_statistic(f"insightappsec.vulns.{sev.lower()}", count)
        tc_statistic("insightappsec.vulns.total", len(filtered))

    # -- Step 6: Threshold gate ----------------------------------------------
    should_fail, reason = check_threshold(vulns, args.fail_on)

    if should_fail:
        msg = f"FAILED: {reason}"
        print(f"\n{msg}")
        if use_tc:
            tc_build_problem(reason)
        return 1

    print(f"\nPASSED: No vulnerabilities at or above {args.fail_on}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
