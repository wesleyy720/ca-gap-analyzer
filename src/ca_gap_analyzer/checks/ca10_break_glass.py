"""CA-10: Are break-glass accounts set up so they can always get in?

Microsoft recommends two emergency-access accounts, excluded from every Conditional Access
policy, so a broken policy (or an outage of an MFA method) can't lock out every admin.
"""

from ..breakglass import resolve
from ..coverage import excluded_users
from ..findings import Finding, Severity
from ..policy import DISABLED
from ..snapshot import Snapshot

CHECK_ID = "CA-10"
TITLE = "Break-glass accounts are excluded everywhere"
REQUIRES_DIRECTORY = True

RECOMMENDED_COUNT = 2


def run(snapshot: Snapshot) -> list[Finding]:
    d = snapshot.directory
    break_glass = resolve(snapshot)
    source = break_glass.note(snapshot)
    findings = []

    for entry in break_glass.unresolved:
        findings.append(Finding(
            check_id=CHECK_ID,
            title=f"Designated break-glass account not found: {entry}",
            severity=Severity.LOW,
            detail=f"'{entry}' is listed in CA_BREAK_GLASS but isn't in this snapshot's directory data.",
            remediation="Check the spelling in CA_BREAK_GLASS (use the full UPN or the object ID).",
            affected=[entry],
        ))

    if not break_glass.ids:
        findings.append(Finding(
            check_id=CHECK_ID,
            title="No break-glass account found",
            severity=Severity.MEDIUM,
            detail=("No account is excluded from every enforced policy, so a misconfigured policy "
                     "could lock out every administrator."),
            remediation=(
                "Create two cloud-only emergency-access accounts with phishing-resistant MFA, "
                "exclude them from all Conditional Access policies, alert on every sign-in, and "
                "list them in CA_BREAK_GLASS."
            ),
        ))
        return findings

    active = [p for p in snapshot.policies if p.state != DISABLED]
    for account in sorted(break_glass.ids, key=d.name):
        missing = [p for p in active if account not in excluded_users(p, d)]
        if missing:
            names = ", ".join(f"'{p.name}' ({p.state_label})" for p in missing)
            findings.append(Finding(
                check_id=CHECK_ID,
                title=f"Break-glass account '{d.name(account)}' isn't excluded from every policy",
                severity=Severity.MEDIUM,
                detail=(f"'{d.name(account)}' ({source}) isn't excluded from: {names}. If one of "
                        "these policies blocks it, the emergency account won't work when needed."),
                remediation="Exclude the break-glass account from every Conditional Access policy.",
                affected=[d.name(account)] + [p.name for p in missing],
            ))

    if len(break_glass.ids) < RECOMMENDED_COUNT:
        findings.append(Finding(
            check_id=CHECK_ID,
            title=f"Only {len(break_glass.ids)} break-glass account",
            severity=Severity.LOW,
            detail=(f"Break-glass accounts, {source}. Microsoft recommends {RECOMMENDED_COUNT}, "
                    "so one lost key or locked account doesn't leave you without a way in."),
            remediation="Add a second emergency-access account with its own phishing-resistant credential.",
        ))
    return findings
