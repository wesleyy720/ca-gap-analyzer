"""Shared test helpers: build small fake policies and snapshots in Graph's JSON shape."""

import copy

from ca_gap_analyzer.snapshot import Snapshot, snapshot_from_dict

COLLECTED_AT = "2026-10-17T18:00:00Z"

BASE_POLICY = {
    "id": "test-policy",
    "displayName": "Test policy",
    "createdDateTime": "2026-10-17T00:00:00Z",
    "modifiedDateTime": "2026-10-17T00:00:00Z",
    "state": "enabled",
    "conditions": {
        "userRiskLevels": [],
        "signInRiskLevels": [],
        "clientAppTypes": ["all"],
        "platforms": None,
        "locations": None,
        "devices": None,
        "applications": {"includeApplications": ["All"], "excludeApplications": []},
        "users": {
            "includeUsers": ["All"],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": [],
        },
    },
    "grantControls": {"operator": "OR", "builtInControls": ["mfa"], "authenticationStrength": None},
    "sessionControls": None,
}


def make_policy(name="Test policy", state="enabled", users=None, apps=None,
                client_apps=None, grant=None, operator="OR", modified=None, **conditions):
    """Start from an enabled 'MFA for all users, all apps' policy and override what a test needs."""
    p = copy.deepcopy(BASE_POLICY)
    p["displayName"] = name
    p["state"] = state
    if users is not None:
        p["conditions"]["users"]["includeUsers"] = users
    if apps is not None:
        p["conditions"]["applications"]["includeApplications"] = apps
    if client_apps is not None:
        p["conditions"]["clientAppTypes"] = client_apps
    if grant is not None:
        p["grantControls"]["builtInControls"] = grant
    p["grantControls"]["operator"] = operator
    if modified is not None:
        p["modifiedDateTime"] = modified
    p["conditions"].update(conditions)
    return p


def make_location(name="Office", cidrs=("203.0.113.0/29",), trusted=True):
    return {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "id": f"loc-{name}",
        "displayName": name,
        "isTrusted": trusted,
        "ipRanges": [{"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": c} for c in cidrs],
    }


def make_snapshot(policies=(), locations=(), users=(), groups=None, roles=None,
                  eligible=None, user_count=None, break_glass=None) -> Snapshot:
    """Build a snapshot. For identity tests:
        users=["alice", ...]             user objects with id == name
        groups={"g-admins": ["alice"]}   group id -> member user ids
        roles={"alice": GA}              user/group id -> role template ID (active)
        eligible={"bob": GA}             same, but PIM eligible
        break_glass=["bg"]               like CA_BREAK_GLASS
    """
    groups = groups or {}
    objects = [{"@odata.type": "#microsoft.graph.user", "id": u, "displayName": u,
                "userPrincipalName": f"{u}@test.onmicrosoft.com"} for u in users]
    objects += [{"@odata.type": "#microsoft.graph.group", "id": g, "displayName": g} for g in groups]
    snapshot = snapshot_from_dict({
        "metadata": {"tenant": "test.onmicrosoft.com", "collectedAt": COLLECTED_AT, "userCount": user_count},
        "conditionalAccessPolicies": list(policies),
        "namedLocations": list(locations),
        "roleDefinitions": [{"id": r, "templateId": r, "displayName": n} for r, n in ROLE_NAMES.items()],
        "roleAssignments": [{"principalId": p, "roleDefinitionId": r} for p, r in (roles or {}).items()],
        "roleEligibilities": [{"principalId": p, "roleDefinitionId": r} for p, r in (eligible or {}).items()],
        "groupMembers": groups,
        "directoryObjects": objects,
    })
    snapshot.break_glass_entries = break_glass
    return snapshot


GA = "62e90394-69f5-4237-9190-012177145e10"
HELPDESK = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
GLOBAL_READER = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
ROLE_NAMES = {GA: "Global Administrator", HELPDESK: "Helpdesk Administrator", GLOBAL_READER: "Global Reader"}
PHISHING_RESISTANT = {"id": "00000000-0000-0000-0000-000000000004", "displayName": "Phishing-resistant MFA"}
