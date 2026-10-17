"""CA-11: Does the all-users MFA policy also cover guests and external users?

A guest account from a weakly secured partner tenant is an easy way in. Excluding guests from
MFA is a common shortcut when partners complain about prompts.
"""

from ..coverage import is_unconditional
from ..findings import Finding, Severity
from ..snapshot import Snapshot

CHECK_ID = "CA-11"
TITLE = "Guests and external users must use MFA"


def run(snapshot: Snapshot) -> list[Finding]:
    baseline = [p for p in snapshot.policies
                if p.is_enforced and p.targets_all_users and p.requires_mfa and is_unconditional(p)]
    if not baseline:
        return []  # no all-user MFA policy at all; CA-01 reports that
    if any(not p.excludes_guests for p in baseline):
        return []

    names = ", ".join(f"'{p.name}'" for p in baseline)
    return [Finding(
        check_id=CHECK_ID,
        title="Guests and external users are excluded from MFA",
        severity=Severity.MEDIUM,
        detail=f"Every all-user MFA policy excludes guests and external users: {names}.",
        remediation=(
            "Remove the guest exclusion. If partners object to double prompts, trust their MFA "
            "through cross-tenant access settings instead of skipping MFA."
        ),
        affected=[p.name for p in baseline],
    )]
