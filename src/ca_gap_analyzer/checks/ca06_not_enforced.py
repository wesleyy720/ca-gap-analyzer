"""CA-06: Are any policies sitting in Report-only or Off?

These look like protection in a quick portal review but enforce nothing. A policy that's been
left that way for a long time is more likely forgotten than mid-rollout, so it rates higher.
"""

from ..findings import Finding, Severity
from ..snapshot import Snapshot

CHECK_ID = "CA-06"
TITLE = "All policies are enforced"

STALE_AFTER_DAYS = 30


def run(snapshot: Snapshot) -> list[Finding]:
    findings = []
    for p in snapshot.policies:
        if p.is_enforced:
            continue

        modified = p.modified_at
        age_days = (snapshot.collected_at - modified).days if modified else None
        stale = age_days is not None and age_days >= STALE_AFTER_DAYS

        if age_days is None:
            age_text = "Last-modified date unknown."
        else:
            age_text = f"Last modified {age_days} day(s) ago."

        findings.append(Finding(
            check_id=CHECK_ID,
            title=f"Policy not enforced ({p.state_label}): {p.name}",
            severity=Severity.MEDIUM if stale else Severity.LOW,
            detail=(
                f"'{p.name}' is {p.state_label}, so it doesn't block or require anything. {age_text}"
                + (f" Unchanged for {STALE_AFTER_DAYS}+ days, so it's likely forgotten." if stale else "")
            ),
            remediation=(
                "If it's mid-rollout, check its Report-only results in the sign-in logs and then "
                "turn it On. If it's no longer needed, delete it so reviewers don't mistake it for "
                "protection."
            ),
            affected=[p.name],
        ))
    return findings
