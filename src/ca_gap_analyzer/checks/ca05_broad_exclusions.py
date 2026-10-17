"""CA-05: Does any "all users" policy exclude a large share of users?

A policy that says "All users" but excludes most of them gives false assurance in a review.
"""

from ..coverage import excluded_users
from ..findings import Finding, Severity
from ..policy import DISABLED
from ..snapshot import Snapshot

CHECK_ID = "CA-05"
TITLE = "No broad exclusions from all-user policies"
REQUIRES_DIRECTORY = True

MIN_EXCLUDED = 5      # ignore a handful of exclusions, whatever the tenant size
MAX_SHARE = 0.25      # flag when more than this share of all users is excluded


def run(snapshot: Snapshot) -> list[Finding]:
    d = snapshot.directory
    findings = []
    for p in snapshot.policies:
        if p.state == DISABLED or not p.targets_all_users:
            continue
        excluded = excluded_users(p, d)
        count = len(excluded)
        if count < MIN_EXCLUDED:
            continue

        if snapshot.user_count:
            share = count / snapshot.user_count
            if share <= MAX_SHARE:
                continue
            size = f"{count} of {snapshot.user_count} users ({share:.0%})"
        else:
            size = f"{count} users (tenant user count unknown)"

        groups = [f"{d.name(g)} ({len(d.members(g))} members)" for g in p.exclude_groups]
        detail = f"'{p.name}' ({p.state_label}) targets all users but excludes {size}."
        if groups:
            detail += f" Excluded groups: {', '.join(groups)}."

        findings.append(Finding(
            check_id=CHECK_ID,
            title=f"Policy '{p.name}' excludes a large share of users",
            severity=Severity.MEDIUM,
            detail=detail,
            remediation=(
                "Narrow the exclusions to small, named exception groups that are reviewed "
                "regularly. If the policy is only meant for some users, target them directly "
                "instead of 'All users' minus everyone else."
            ),
            affected=[p.name],
        ))
    return findings
