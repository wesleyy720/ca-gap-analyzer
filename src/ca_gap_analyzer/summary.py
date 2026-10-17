"""Describes each policy in plain English, with names instead of GUIDs.

This is what you'd want to read before an audit: who a policy really covers (group exclusions
expanded to their members), what it targets, and what it requires.
"""

from .policy import Policy
from .snapshot import Snapshot

CONTROL_LABELS = {
    "block": "Block access",
    "mfa": "Require MFA",
    "compliantDevice": "Require compliant device",
    "domainJoinedDevice": "Require hybrid joined device",
    "approvedApplication": "Require approved client app",
    "compliantApplication": "Require app protection policy",
    "passwordChange": "Require password change",
}
LABEL_WIDTH = 12


def _people(ids: list[str], snapshot: Snapshot) -> list[str]:
    """Names for users/groups, with each group's members shown in brackets."""
    d = snapshot.directory
    out = []
    for object_id in ids:
        label = d.name(object_id)
        if d.kind(object_id) == "group":
            members = [d.name(m["id"]) for m in d.members(object_id)]
            label += f" (group: {', '.join(members) if members else 'no members'})"
        out.append(label)
    return out


def _roles(ids: list[str], snapshot: Snapshot) -> list[str]:
    d = snapshot.directory
    out = []
    for role_id in ids:
        holders = d.role_holders(role_id)
        names = sorted({d.name(h.principal_id) + (" [eligible]" if h.kind == "eligible" else "")
                        for h in holders})
        held_by = f"held by: {', '.join(names)}" if names else "no holders"
        out.append(f"{d.role_name(role_id)} role ({held_by})")
    return out


def _location_name(location_id: str, snapshot: Snapshot) -> str:
    if location_id in ("All", "AllTrusted"):
        return {"All": "Any location", "AllTrusted": "All trusted locations"}[location_id]
    for loc in snapshot.named_locations:
        if loc.get("id") == location_id:
            return loc.get("displayName", location_id)
    return location_id


def _conditions(policy: Policy, snapshot: Snapshot) -> list[str]:
    c = policy.raw.get("conditions") or {}
    out = []
    if not policy.applies_to_all_client_apps:
        out.append("client apps: " + ", ".join(policy.client_app_types))
    if c.get("signInRiskLevels"):
        out.append("sign-in risk: " + ", ".join(c["signInRiskLevels"]))
    if c.get("userRiskLevels"):
        out.append("user risk: " + ", ".join(c["userRiskLevels"]))
    platforms = c.get("platforms") or {}
    if platforms.get("includePlatforms"):
        out.append("platforms: " + ", ".join(platforms["includePlatforms"]))
    locations = c.get("locations") or {}
    if locations.get("includeLocations"):
        out.append("from: " + ", ".join(_location_name(i, snapshot) for i in locations["includeLocations"]))
    if locations.get("excludeLocations"):
        out.append("except from: " + ", ".join(_location_name(i, snapshot) for i in locations["excludeLocations"]))
    flows = (c.get("authenticationFlows") or {}).get("transferMethods")
    if flows:
        out.append("authentication flows: " + flows)
    return out


def _grant(policy: Policy) -> str:
    parts = [CONTROL_LABELS.get(c, c) for c in policy.grant_controls]
    if policy.authentication_strength:
        parts.append(f"Require authentication strength '{policy.authentication_strength}'")
    if not parts:
        return "none"
    joiner = " OR " if (policy.raw.get("grantControls") or {}).get("operator", "OR") == "OR" else " AND "
    return joiner.join(parts)


def _session(policy: Policy) -> str | None:
    session = policy.raw.get("sessionControls") or {}
    freq = session.get("signInFrequency") or {}
    if freq.get("isEnabled"):
        return f"sign-in frequency every {freq.get('value')} {freq.get('type')}"
    return None


def describe_policy(policy: Policy, snapshot: Snapshot) -> list[str]:
    d = snapshot.directory
    rows = []

    include = _people(policy.include_users + policy.include_groups, snapshot)
    include += _roles(policy.include_roles, snapshot)
    rows.append(("Users", "; ".join(include) or "none"))

    exclude = _people(policy.exclude_users + policy.exclude_groups, snapshot)
    exclude += _roles(policy.exclude_roles, snapshot)
    if exclude:
        rows.append(("Excluding", "; ".join(exclude)))

    rows.append(("Resources", ", ".join(d.app_name(a) for a in policy.include_applications) or "none"))
    if policy.exclude_applications:
        rows.append(("Except", ", ".join(d.app_name(a) for a in policy.exclude_applications)))

    rows.append(("Conditions", "; ".join(_conditions(policy, snapshot)) or "none"))
    rows.append(("Grant", _grant(policy)))
    session = _session(policy)
    if session:
        rows.append(("Session", session))

    lines = [f"{policy.name}  [{policy.state_label}]"]
    lines += [f"  {label + ':':<{LABEL_WIDTH}}{value}" for label, value in rows]
    return lines


def print_policy_summary(snapshot: Snapshot) -> None:
    print(f"Conditional Access policies in {snapshot.tenant} ({len(snapshot.policies)})")
    if snapshot.directory.is_empty:
        print("Note: this snapshot has no directory data, so IDs can't be resolved to names. "
              "Re-run `collect` to refresh it.")
    for policy in sorted(snapshot.policies, key=lambda p: p.name):
        print()
        print("\n".join(describe_policy(policy, snapshot)))
