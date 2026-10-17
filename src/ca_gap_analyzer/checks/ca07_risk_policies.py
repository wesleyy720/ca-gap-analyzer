"""CA-07: Does any enforced policy act on sign-in risk or user risk?

Entra ID Protection scores sign-ins (anonymous IPs, impossible travel, leaked credentials). Those
scores do nothing unless a Conditional Access policy acts on them. Requires Entra ID P2.
"""

from ..findings import Finding, Severity
from ..snapshot import Snapshot

CHECK_ID = "CA-07"
TITLE = "Risky sign-ins and users are acted on"


def run(snapshot: Snapshot) -> list[Finding]:
    risk_policies = [p for p in snapshot.policies if p.risk_levels]
    acting = [p for p in risk_policies
              if p.is_enforced and (p.blocks or p.requires_mfa or "passwordChange" in p.grant_controls)]
    if acting:
        return []

    detail = "No enforced policy blocks or challenges sign-ins flagged as risky by Entra ID Protection."
    if risk_policies:
        names = ", ".join(f"'{p.name}' ({p.state_label})" for p in risk_policies)
        detail += f" Risk-based policies exist but aren't enforced: {names}."

    return [Finding(
        check_id=CHECK_ID,
        title="No enforced risk-based policy",
        severity=Severity.MEDIUM,
        detail=detail,
        remediation=(
            "With Entra ID P2: require MFA for medium and high sign-in risk, and require a secure "
            "password change for high user risk. Run them in Report-only first to gauge volume."
        ),
        affected=[p.name for p in risk_policies],
    )]
