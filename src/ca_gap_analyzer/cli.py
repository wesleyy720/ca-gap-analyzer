"""Command-line interface.

Usage:
    ca-gap-analyzer analyze samples/lab_snapshot.json
    ca-gap-analyzer analyze samples/lab_snapshot.json --format json
"""

import argparse
import json
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .checks import ALL_CHECKS
from .findings import Finding, Severity
from .snapshot import Snapshot, load_snapshot

WIDTH = 100


@dataclass
class CheckResult:
    check_id: str
    title: str
    findings: list[Finding]

    @property
    def passed(self) -> bool:
        return not self.findings


def run_checks(snapshot: Snapshot) -> list[CheckResult]:
    return [CheckResult(c.CHECK_ID, c.TITLE, c.run(snapshot)) for c in ALL_CHECKS]


def print_text_report(snapshot: Snapshot, source: Path, results: list[CheckResult]) -> None:
    print(f"CA Gap Analyzer {__version__}")
    print(f"Snapshot: {source}")
    print(f"Tenant:   {snapshot.tenant}   (collected {snapshot.collected_at:%Y-%m-%d %H:%M} UTC)")
    print(f"Policies: {len(snapshot.policies)}   Named locations: {len(snapshot.named_locations)}")

    print("\nChecks")
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  {status}  {r.check_id}  {r.title}")

    findings = sorted(
        (f for r in results for f in r.findings),
        key=lambda f: (-f.severity, f.check_id),
    )
    print(f"\nFindings ({len(findings)})")
    if not findings:
        print("  None.")
    indent = " " * 14
    for f in findings:
        label = f"[{f.severity.name}]"
        print(f"\n  {label:<10}  {f.check_id}  {f.title}")
        print(textwrap.fill(f.detail, WIDTH, initial_indent=indent, subsequent_indent=indent))
        print(textwrap.fill("Fix: " + f.remediation, WIDTH, initial_indent=indent, subsequent_indent=indent))

    passed = sum(r.passed for r in results)
    counts = ", ".join(
        f"{sum(f.severity == s for f in findings)} {s.name.lower()}"
        for s in sorted(Severity, reverse=True)
        if any(f.severity == s for f in findings)
    )
    print(f"\nSummary: {passed} of {len(results)} checks passed." + (f" Findings: {counts}." if counts else ""))


def print_json_report(snapshot: Snapshot, results: list[CheckResult]) -> None:
    output = {
        "tool": "ca-gap-analyzer",
        "version": __version__,
        "tenant": snapshot.tenant,
        "collectedAt": snapshot.collected_at.isoformat(),
        "checks": [
            {
                "id": r.check_id,
                "title": r.title,
                "passed": r.passed,
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in results
        ],
    }
    print(json.dumps(output, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ca-gap-analyzer",
        description="Find security gaps in Entra ID Conditional Access configurations.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="run all checks against a snapshot file")
    analyze.add_argument("snapshot", type=Path, help="path to a snapshot JSON file")
    analyze.add_argument("--format", choices=["text", "json"], default="text", help="output format")

    args = parser.parse_args(argv)

    try:
        snapshot = load_snapshot(args.snapshot)
    except FileNotFoundError:
        print(f"error: snapshot file not found: {args.snapshot}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"error: {args.snapshot} is not valid JSON ({e})", file=sys.stderr)
        return 2

    results = run_checks(snapshot)
    if args.format == "json":
        print_json_report(snapshot, results)
    else:
        print_text_report(snapshot, args.snapshot, results)
    return 0
