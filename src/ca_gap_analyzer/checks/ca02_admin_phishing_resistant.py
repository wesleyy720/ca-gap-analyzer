"""CA-02: Must every privileged user sign in with phishing-resistant MFA?

Standard MFA (push, SMS, codes) can be relayed by adversary-in-the-middle phishing kits that
steal the session token. FIDO2 keys, passkeys, and Windows Hello can't be relayed, which is why
admins should be required to use them.
"""

from ..breakglass import resolve
from ..coverage import covers, is_unconditional
from ..findings import Finding, Severity
from ..privileged import describe_user, privileged_users, user_roles
from ..snapshot import Snapshot

CHECK_ID = "CA-02"
TITLE = "Admins must use phishing-resistant MFA"
REQUIRES_DIRECTORY = True


def run(snapshot: Snapshot) -> list[Finding]:
    d = snapshot.directory
    roles_by_user = user_roles(d)
    break_glass = resolve(snapshot)

    strong = [p for p in snapshot.policies if p.requires_phishing_resistant_mfa]
    effective = [p for p in strong if p.is_enforced and is_unconditional(p)]

    uncovered = {
        user_id: grants for user_id, grants in privileged_users(d).items()
        if user_id not in break_glass.ids
        and not any(covers(p, user_id, d, roles_by_user) for p in effective)
    }
    if not uncovered:
        return []

    people = sorted(describe_user(u, g, d) for u, g in uncovered.items())
    detail = (f"{len(uncovered)} privileged user(s) can sign in without phishing-resistant MFA: "
              + "; ".join(people) + ".")

    near_misses = []
    for p in strong:
        if p in effective:
            continue
        why = []
        if not p.is_enforced:
            why.append(p.state_label)
        if not p.targets_all_apps:
            why.append("not all resources")
        if p.narrowing_conditions:
            why.append("limited by " + ", ".join(p.narrowing_conditions))
        if why:
            near_misses.append(f"'{p.name}' requires it but is {', '.join(why)}")
    if near_misses:
        detail += " " + "; ".join(near_misses) + "."
    if effective:
        detail += (" Enforced phishing-resistant policies exist but don't cover these users "
                   "(they target other roles, or exclude these users).")

    return [Finding(
        check_id=CHECK_ID,
        title="Privileged users aren't required to use phishing-resistant MFA",
        severity=Severity.CRITICAL,
        detail=detail,
        remediation=(
            "Make sure every admin has a passkey, FIDO2 key, or Windows Hello registered, then "
            "enforce a policy: Users = Directory roles (all privileged roles, exclude break-glass), "
            "Target resources = All resources, Grant = Require authentication strength "
            "'Phishing-resistant MFA'."
        ),
        affected=sorted(d.name(u) for u in uncovered),
    )]
