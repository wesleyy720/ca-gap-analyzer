"""Command-line interface.

Usage:
    ca-gap-analyzer analyze samples/lab_snapshot.json
    ca-gap-analyzer analyze samples/lab_snapshot.json --format json
    ca-gap-analyzer policies samples/lab_snapshot.json   # each policy in plain English
    ca-gap-analyzer collect                 # sign in, save a snapshot to exports/
    ca-gap-analyzer collect --analyze       # ...and analyze it straight away
    ca-gap-analyzer report --open           # HTML report for the newest snapshot
"""

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

from . import __version__, auth, breakglass, collect, graph, report
from .config import ConfigError, load_break_glass, load_settings
from .findings import Severity
from .runner import CheckResult, all_findings, run_checks
from .snapshot import Snapshot, load_snapshot, snapshot_from_dict
from .summary import print_policy_summary

WIDTH = 100


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
        print(f"Break-glass: {breakglass.resolve(snapshot).note(snapshot)}")
    for warning in snapshot.warnings:
        print(f"Warning:  {warning}")

    print("\nChecks")
    for r in results:
        print(f"  {r.status}  {r.check_id}  {r.title}")

    findings = all_findings(results)
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
    skipped = sum(r.skipped for r in results)
    counts = ", ".join(
        f"{sum(f.severity == s for f in findings)} {s.name.lower()}"
        for s in sorted(Severity, reverse=True)
        if any(f.severity == s for f in findings)
    )
    summary = f"\nSummary: {passed} of {len(results)} checks passed"
    summary += f" ({skipped} skipped: re-run collect for identity data)." if skipped else "."
    print(summary + (f" Findings: {counts}." if counts else ""))


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
                "skipped": r.skipped,
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

    snapshot_help = "path to a snapshot JSON file (default: the newest one in exports/)"

    analyze = commands.add_parser("analyze", help="run all checks against a snapshot file")
    analyze.add_argument("snapshot", type=Path, nargs="?", help=snapshot_help)
    analyze.add_argument("--format", choices=["text", "json"], default="text", help="output format")
    analyze.add_argument("--env-file", type=Path, default=Path(".env"),
                         help="settings file to read CA_BREAK_GLASS from (default: .env)")

    policies_cmd = commands.add_parser("policies", help="describe each policy in plain English")
    policies_cmd.add_argument("snapshot", type=Path, nargs="?", help=snapshot_help)

    report_cmd = commands.add_parser("report", help="write an HTML report for a snapshot")
    report_cmd.add_argument("snapshot", type=Path, nargs="?", help=snapshot_help)
    report_cmd.add_argument("--output", type=Path, help="where to save (default: reports/report-<time>.html)")
    report_cmd.add_argument("--env-file", type=Path, default=Path(".env"),
                            help="settings file to read CA_BREAK_GLASS from (default: .env)")
    report_cmd.add_argument("--open", action="store_true", help="open the report in your browser")

    collect_cmd = commands.add_parser("collect", help="sign in and save a snapshot of a live tenant")
    collect_cmd.add_argument("--output", type=Path, help="where to save (default: exports/snapshot-<time>.json)")
    collect_cmd.add_argument("--env-file", type=Path, default=Path(".env"), help="settings file (default: .env)")
    collect_cmd.add_argument("--analyze", action="store_true", help="analyze the snapshot right after collecting")
    collect_cmd.add_argument("--report", action="store_true", help="also write an HTML report")

    args = parser.parse_args(argv)
    if args.command == "collect":
        return run_collect(args)
    if args.command == "policies":
        return run_policies(args)
    if args.command == "report":
        return run_report(args)
    return run_analyze(args)


def save_report(snapshot: Snapshot, snapshot_path: Path | None, output: Path | None, open_it: bool) -> Path:
    path = output or report.default_report_path(snapshot_path)
    report.write_report(report.render_report(snapshot, run_checks(snapshot)), path)
    print(f"Report saved to {path}")
    if open_it:
        os.startfile(path.resolve())  # Windows: opens in the default browser
    return path


def run_report(args) -> int:
    snapshot, path = open_snapshot(args.snapshot)
    if snapshot is None:
        return 2
    snapshot.break_glass_entries = load_break_glass(args.env_file)
    save_report(snapshot, path, args.output, args.open)
    return 0


def newest_snapshot(folder: Path = collect.EXPORTS_DIR) -> Path | None:
    # Names are snapshot-YYYYMMDD-HHMMSS.json, so sorting by name sorts by time.
    found = sorted(folder.glob("snapshot-*.json"))
    return found[-1] if found else None


def open_snapshot(path: Path | None) -> tuple[Snapshot | None, Path | None]:
    """Load a snapshot (the newest in exports/ if no path given).

    Prints a friendly error and returns (None, path) if it can't be read.
    """
    if path is None:
        path = newest_snapshot()
        if path is None:
            print(f"error: no snapshots in {collect.EXPORTS_DIR}/. Run `ca-gap-analyzer collect` "
                  "first, or give a snapshot path.", file=sys.stderr)
            return None, None
        print(f"Using newest snapshot: {path}\n", file=sys.stderr)
    try:
        return load_snapshot(path), path
    except FileNotFoundError:
        print(f"error: snapshot file not found: {path}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"error: {path} is not valid JSON ({e})", file=sys.stderr)
    except OSError as e:
        # e.g. a path with characters Windows doesn't allow, like < >
        print(f"error: can't open {path}: {e.strerror or e}", file=sys.stderr)
    return None, path


def run_policies(args) -> int:
    snapshot, _ = open_snapshot(args.snapshot)
    if snapshot is None:
        return 2
    print_policy_summary(snapshot)
    return 0


def run_analyze(args) -> int:
    snapshot, path = open_snapshot(args.snapshot)
    if snapshot is None:
        return 2
    snapshot.break_glass_entries = load_break_glass(args.env_file)

    results = run_checks(snapshot)
    if args.format == "json":
        print_json_report(snapshot, results)
    else:
        print_text_report(snapshot, path, results)
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

    snapshot = snapshot_from_dict(data)
    snapshot.break_glass_entries = load_break_glass(args.env_file)
    if args.analyze:
        print()
        print_text_report(snapshot, output, run_checks(snapshot))
    if args.report:
        save_report(snapshot, output, None, open_it=False)
    if not (args.analyze or args.report):
        print(f"Next: ca-gap-analyzer analyze {output}")
    return 0
