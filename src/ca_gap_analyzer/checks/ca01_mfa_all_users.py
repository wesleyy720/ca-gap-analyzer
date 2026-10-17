"""CA-01: Is there an enforced policy requiring MFA for every user, on every app?"""

from ..findings import Finding, Severity
from ..snapshot import Snapshot

CHECK_ID = "CA-01"
TITLE = "MFA is required for all users"


def run(snapshot: Snapshot) -> list[Finding]:
    # Every policy that *would* give blanket MFA coverage if it were on and unconditional.
    candidates = [
        p for p in snapshot.policies
        if p.targets_all_users and p.targets_all_apps and p.requires_mfa
    ]

    # The ones that actually do: enforced, every client app, no narrowing conditions.
    for p in candidates:
        if p.is_enforced and p.applies_to_all_client_apps and not p.narrowing_conditions:
            return []  # pass

    # Explain why each near-miss doesn't count, so the reader can fix the right thing.
    reasons = []
    for p in candidates:
        why = []
        if not p.is_enforced:
            why.append(f"state is {p.state_label}")
        if not p.applies_to_all_client_apps:
            why.append(f"only applies to client apps: {', '.join(p.client_app_types)}")
        if p.narrowing_conditions:
            why.append(f"limited by {', '.join(p.narrowing_conditions)}")
        reasons.append(f"'{p.name}' would qualify, but {'; '.join(why)}.")

    detail = "No enforced policy requires MFA for all users on all apps."
    if reasons:
        detail += " " + " ".join(reasons)

    return [Finding(
        check_id=CHECK_ID,
        title="No enforced policy requires MFA for all users",
        severity=Severity.HIGH,
        detail=detail,
        remediation=(
            "Create an enabled policy: Users = All users (exclude only break-glass accounts), "
            "Target resources = All resources, Grant = Require multifactor authentication."
        ),
        affected=[p.name for p in candidates],
    )]
