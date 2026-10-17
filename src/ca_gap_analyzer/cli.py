"""Command-line interface.

Usage:
    ca-gap-analyzer analyze samples/lab_snapshot.json
    ca-gap-analyzer analyze samples/lab_snapshot.json --format json
    ca-gap-analyzer policies samples/lab_snapshot.json   # each policy in plain English
    ca-gap-analyzer collect                 # sign in, save a snapshot to exports/
    ca-gap-analyzer collect --analyze       # ...and analyze it straight away
"""

import argparse
import json
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

from . import __version__, auth, collect, graph
from .checks import ALL_CHECKS
from .config import ConfigError, load_settings
from .findings import Finding, Severity
from .snapshot import Snapshot, load_snapshot, snapshot_from_dict
from .summary import print_policy_summary

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
    d = snapshot.directory
    if d.is_empty:
        print("Directory: not collected (older snapshot), so identity checks have less to go on")
    else:
        print(f"Directory: {len(d.objects)} users/groups/apps resolved, "
              f"{len(d.role_assignments)} active and {len(d.role_eligibilities)} eligible role assignments")
    for warning in snapshot.warnings:
        print(f"Warning:  {warning}")

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

    policies_cmd = commands.add_parser("policies", help="describe each policy in plain English")
    policies_cmd.add_argument("snapshot", type=Path, help="path to a snapshot JSON file")

    collect_cmd = commands.add_parser("collect", help="sign in and save a snapshot of a live tenant")
    collect_cmd.add_argument("--output", type=Path, help="where to save (default: exports/snapshot-<time>.json)")
    collect_cmd.add_argument("--env-file", type=Path, default=Path(".env"), help="settings file (default: .env)")
    collect_cmd.add_argument("--analyze", action="store_true", help="analyze the snapshot right after collecting")

    args = parser.parse_args(argv)
    if args.command == "collect":
        return run_collect(args)
    if args.command == "policies":
        return run_policies(args)
    return run_analyze(args)


def open_snapshot(path: Path) -> Snapshot | None:
    """Load a snapshot, printing a friendly error (and returning None) if it can't be read."""
    try:
        return load_snapshot(path)
    except FileNotFoundError:
        print(f"error: snapshot file not found: {path}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"error: {path} is not valid JSON ({e})", file=sys.stderr)
    return None


def run_policies(args) -> int:
    snapshot = open_snapshot(args.snapshot)
    if snapshot is None:
        return 2
    print_policy_summary(snapshot)
    return 0


def run_analyze(args) -> int:
    snapshot = open_snapshot(args.snapshot)
    if snapshot is None:
        return 2

    results = run_checks(snapshot)
    if args.format == "json":
        print_json_report(snapshot, results)
    else:
        print_text_report(snapshot, args.snapshot, results)
    return 0


def run_collect(args) -> int:
    try:
        settings = load_settings(args.env_file)
        signed_in = auth.sign_in(settings.tenant_id, settings.client_id)
        print(f"Signed in as {signed_in.username}. Reading Conditional Access configuration...")
        client = graph.GraphClient(signed_in.access_token)
        data = collect.collect_snapshot(client, signed_in.username, signed_in.tenant_id)
    except (ConfigError, auth.AuthError, graph.GraphError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    output = args.output or collect.default_output_path()
    collect.save_snapshot(data, output)
    print(
        f"Saved {len(data['conditionalAccessPolicies'])} policies and "
        f"{len(data['namedLocations'])} named locations to {output}"
    )

    if args.analyze:
        print()
        snapshot = snapshot_from_dict(data)
        print_text_report(snapshot, output, run_checks(snapshot))
    else:
        print(f"Next: ca-gap-analyzer analyze {output}")
    return 0
