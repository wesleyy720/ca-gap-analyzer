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


def make_snapshot(policies=(), locations=()) -> Snapshot:
    return snapshot_from_dict({
        "metadata": {"tenant": "test.onmicrosoft.com", "collectedAt": COLLECTED_AT},
        "conditionalAccessPolicies": list(policies),
        "namedLocations": list(locations),
    })
