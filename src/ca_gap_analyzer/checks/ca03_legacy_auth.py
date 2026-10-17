"""CA-03: Is legacy authentication blocked for everyone?

Legacy clients can't do MFA, so if they aren't blocked, a stolen password is enough.
In Graph, legacy clients are the clientAppTypes "exchangeActiveSync" and "other".
"""

from ..findings import Finding, Severity
from ..snapshot import Snapshot

CHECK_ID = "CA-03"
TITLE = "Legacy authentication is blocked"

LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}


def run(snapshot: Snapshot) -> list[Finding]:
    # Policies that block at least one legacy client type, for everyone, on every app.
    legacy_blockers = [
        p for p in snapshot.policies
        if p.blocks
        and p.targets_all_users
        and p.targets_all_apps
        and not p.narrowing_conditions
        and LEGACY_CLIENT_TYPES & set(p.client_app_types)
    ]

    # Which legacy types are actually covered by an enforced policy?
    covered = set()
    for p in legacy_blockers:
        if p.is_enforced:
            covered |= LEGACY_CLIENT_TYPES & set(p.client_app_types)

    missing = LEGACY_CLIENT_TYPES - covered
    if not missing:
        return []  # pass

    detail = f"Legacy client types not blocked by any enforced policy: {', '.join(sorted(missing))}."
    not_enforced = [p for p in legacy_blockers if not p.is_enforced]
    if not_enforced:
        names = ", ".join(f"'{p.name}' ({p.state_label})" for p in not_enforced)
        detail += f" A blocking policy exists but isn't enforced: {names}."

    return [Finding(
        check_id=CHECK_ID,
        title="Legacy authentication is not fully blocked",
        severity=Severity.HIGH,
        detail=detail,
        remediation=(
            "Create an enabled policy: Users = All users (exclude break-glass), Target resources = "
            "All resources, Conditions > Client apps = Exchange ActiveSync clients + Other clients, "
            "Grant = Block access. Run it in Report-only first and review sign-in logs."
        ),
        affected=[p.name for p in legacy_blockers],
    )]
