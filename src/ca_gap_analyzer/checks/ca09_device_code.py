"""CA-09: Is device code sign-in blocked?

Device code phishing tricks a user into entering a code on the real microsoft.com/devicelogin
page, handing the attacker a token for their account. Most users never need this flow, so
blocking it removes a widely abused attack with little impact.
"""

from ..findings import Finding, Severity
from ..snapshot import Snapshot

CHECK_ID = "CA-09"
TITLE = "Device code flow is blocked"


def run(snapshot: Snapshot) -> list[Finding]:
    restricting = [p for p in snapshot.policies if "deviceCodeFlow" in p.authentication_flows and p.blocks]
    if any(p.is_enforced and p.targets_all_users for p in restricting):
        return []

    detail = "No enforced policy blocks the device code authentication flow for all users."
    not_effective = [p for p in restricting if not (p.is_enforced and p.targets_all_users)]
    if not_effective:
        names = ", ".join(f"'{p.name}' ({p.state_label})" for p in not_effective)
        detail += f" Device code policies exist but are not enforced for everyone: {names}."

    return [Finding(
        check_id=CHECK_ID,
        title="Device code flow is not blocked",
        severity=Severity.MEDIUM,
        detail=detail,
        remediation=(
            "Create a policy: Users = All users (exclude break-glass and any accounts that "
            "really need it, such as meeting-room devices), Target resources = All resources, "
            "Conditions > Authentication flows = Device code flow, Grant = Block access."
        ),
        affected=[p.name for p in restricting],
    )]
