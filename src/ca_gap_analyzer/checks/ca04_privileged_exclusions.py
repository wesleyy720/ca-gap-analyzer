"""CA-04: Is any privileged user excluded from an enforced security policy?

An exclusion is a silent hole. One "temporary" exclusion group can leave an admin without MFA
for years, and nobody sees it in the portal unless they open the group. Break-glass accounts
are the one legitimate exception.
"""

from ..breakglass import resolve
from ..coverage import excluded_users, is_security_control
from ..findings import Finding, Severity
from ..privileged import describe_user, privileged_users, user_roles
from ..snapshot import Snapshot

CHECK_ID = "CA-04"
TITLE = "No privileged users excluded from enforced policies"
REQUIRES_DIRECTORY = True


def run(snapshot: Snapshot) -> list[Finding]:
    d = snapshot.directory
    roles_by_user = user_roles(d)
    break_glass = resolve(snapshot)

    policies = [p for p in snapshot.policies if p.is_enforced and is_security_control(p)]
    # A list, not a dict keyed by name: two policies can share a display name.
    exclusions = [(p, excluded_users(p, d, roles_by_user)) for p in policies]

    findings = []
    for user_id, grants in sorted(privileged_users(d).items(), key=lambda x: d.name(x[0])):
        if user_id in break_glass.ids:
            continue
        hits = [f"'{p.name}' ({', '.join(reasons[user_id])})"
                for p, reasons in exclusions if user_id in reasons]
        if not hits:
            continue

        detail = (f"{describe_user(user_id, grants, d)} is excluded from {len(hits)} enforced "
                  f"policy(ies): {'; '.join(hits)}. None of those policies apply to this account.")
        if not break_glass.designated:
            detail += f" Break-glass accounts were {break_glass.note(snapshot)}."

        findings.append(Finding(
            check_id=CHECK_ID,
            title=f"Privileged user '{d.name(user_id)}' is excluded from enforced policies",
            severity=Severity.HIGH,
            detail=detail,
            remediation=(
                "Remove the exclusion (take the user out of the exclusion group, or off the "
                "policy's exclude list). If it's a break-glass account, add it to CA_BREAK_GLASS "
                "in .env. If an exception is truly needed, document why and when it expires."
            ),
            affected=[d.name(user_id)],
        ))
    return findings
