"""CA-12: Do admin sessions have to re-authenticate regularly?

Without a sign-in frequency, an admin's session can last for days or weeks. A stolen session
token stays useful for that whole time.
"""

from ..findings import Finding, Severity
from ..privileged import is_privileged_role
from ..snapshot import Snapshot

CHECK_ID = "CA-12"
TITLE = "Admin sessions have a sign-in frequency"


def run(snapshot: Snapshot) -> list[Finding]:
    d = snapshot.directory

    def covers_admins(p):
        return p.targets_all_users or any(is_privileged_role(r, d) for r in p.include_roles)

    with_frequency = [p for p in snapshot.policies if p.sign_in_frequency and covers_admins(p)]
    if any(p.is_enforced for p in with_frequency):
        return []

    detail = "No enforced policy sets a sign-in frequency for privileged roles."
    if with_frequency:
        names = ", ".join(f"'{p.name}' ({p.state_label})" for p in with_frequency)
        detail += f" Sign-in frequency is configured but not enforced in: {names}."

    return [Finding(
        check_id=CHECK_ID,
        title="No sign-in frequency for admin sessions",
        severity=Severity.LOW,
        detail=detail,
        remediation=(
            "Add a session control to the admin policy: Sign-in frequency = 4 to 12 hours, and "
            "Persistent browser session = Never persistent."
        ),
        affected=[p.name for p in with_frequency],
    )]
