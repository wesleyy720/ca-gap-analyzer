"""Runs every check against a snapshot."""

from dataclasses import dataclass

from .checks import ALL_CHECKS
from .findings import Finding
from .snapshot import Snapshot


@dataclass
class CheckResult:
    check_id: str
    title: str
    findings: list[Finding]
    skipped: bool = False   # needed directory data the snapshot doesn't have

    @property
    def passed(self) -> bool:
        return not self.skipped and not self.findings

    @property
    def status(self) -> str:
        return "SKIP" if self.skipped else ("PASS" if self.passed else "FAIL")


def run_checks(snapshot: Snapshot) -> list[CheckResult]:
    results = []
    for check in ALL_CHECKS:
        if getattr(check, "REQUIRES_DIRECTORY", False) and snapshot.directory.is_empty:
            results.append(CheckResult(check.CHECK_ID, check.TITLE, [], skipped=True))
        else:
            results.append(CheckResult(check.CHECK_ID, check.TITLE, check.run(snapshot)))
    return results


def all_findings(results: list[CheckResult]) -> list[Finding]:
    """Every finding, worst first."""
    return sorted((f for r in results for f in r.findings), key=lambda f: (-f.severity, f.check_id))
