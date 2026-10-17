"""Pulls Conditional Access data from Graph and saves it as a snapshot file.

The snapshot keeps Graph's JSON as returned, so `analyze` treats a live export and the
synthetic samples the same way. Snapshots go in exports/, which is git-ignored: they describe
a real tenant's defenses and shouldn't end up on GitHub.

Collection order matters:
  1. Policies and named locations (the thing being audited)
  2. Role definitions and assignments (who is privileged)
  3. Names for every user/group a policy or role assignment mentions
  4. Members of those groups, including nested groups
  5. Names for the apps policies target
Only objects that policies or roles reference are collected, not the whole directory.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .graph import GraphError
from .policy import Policy

POLICIES_PATH = "/identity/conditionalAccess/policies"
NAMED_LOCATIONS_PATH = "/identity/conditionalAccess/namedLocations"
ROLE_DEFINITIONS_PATH = "/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn"
ROLE_ASSIGNMENTS_PATH = "/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId"
ROLE_ELIGIBILITIES_PATH = (
    "/roleManagement/directory/roleEligibilityScheduleInstances"
    "?$select=id,principalId,roleDefinitionId,directoryScopeId,startDateTime,endDateTime"
)
MEMBER_FIELDS = "id,displayName,userPrincipalName,userType,accountEnabled"
EXPORTS_DIR = Path("exports")

# Values that appear in policy user/app lists but aren't object IDs.
SPECIAL_VALUES = {"All", "None", "GuestsOrExternalUsers", "Office365", "MicrosoftAdminPortals"}

# The only fields kept for each directory object. Enough to name it and reason about it;
# nothing more (no phone numbers, managers, etc.).
KEEP_FIELDS = {
    "@odata.type", "id", "displayName", "userPrincipalName", "userType", "accountEnabled",
    "appId", "securityEnabled", "isAssignableToRole",
}


def slim(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k in KEEP_FIELDS}


def is_group(obj: dict) -> bool:
    return obj.get("@odata.type") == "#microsoft.graph.group"


def referenced_object_ids(policies: list[Policy]) -> set[str]:
    ids = set()
    for p in policies:
        ids.update(p.include_users, p.exclude_users, p.include_groups, p.exclude_groups)
    return ids - SPECIAL_VALUES


def referenced_app_ids(policies: list[Policy]) -> set[str]:
    ids = set()
    for p in policies:
        ids.update(p.include_applications, p.exclude_applications)
    return ids - SPECIAL_VALUES


def collect_role_assignments(client, role_definitions: list[dict]) -> list[dict]:
    try:
        return client.get_all(ROLE_ASSIGNMENTS_PATH)
    except GraphError as e:
        if e.status != 400:
            raise
    # Some tenants require a filter on this endpoint. Fall back to asking role by role.
    assignments = []
    for role in role_definitions:
        assignments.extend(client.get_all(
            f"/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{role['id']}'"
        ))
    return assignments


def collect_snapshot(client, username: str, tenant_id: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    warnings = []

    # 1. The policies themselves
    raw_policies = client.get_all(POLICIES_PATH)
    named_locations = client.get_all(NAMED_LOCATIONS_PATH)
    policies = [Policy(p) for p in raw_policies]

    # 2. Roles
    role_definitions = client.get_all(ROLE_DEFINITIONS_PATH)
    role_assignments = collect_role_assignments(client, role_definitions)
    try:
        role_eligibilities = client.get_all(ROLE_ELIGIBILITIES_PATH)
    except GraphError as e:
        # PIM needs Entra ID P2. Without it, carry on with active assignments only.
        role_eligibilities = []
        warnings.append(f"Couldn't read PIM eligible role assignments (HTTP {e.status}). "
                        "Only active assignments were collected.")

    # 3. Names for everything policies and role assignments point at
    ids = referenced_object_ids(policies)
    ids.update(a["principalId"] for a in role_assignments + role_eligibilities)
    objects = {}
    if ids:
        found = client.get_by_ids(sorted(ids), ["user", "group", "servicePrincipal"])
        objects = {o["id"]: slim(o) for o in found}
        missing = ids - objects.keys()
        if missing:
            warnings.append(f"{len(missing)} referenced object(s) no longer exist in the directory "
                            "(deleted users or groups still listed in a policy or role).")

    # 4. Expand every group we found, including nested membership
    group_members = {}
    for group_id in sorted(i for i, o in objects.items() if is_group(o)):
        members = client.get_all(f"/groups/{group_id}/transitiveMembers?$select={MEMBER_FIELDS}")
        group_members[group_id] = [m["id"] for m in members]
        for m in members:
            objects.setdefault(m["id"], slim(m))

    # 5. App names (policies store appId, not object ID, so getByIds can't resolve them)
    for app_id in sorted(referenced_app_ids(policies)):
        for sp in client.get_all(f"/servicePrincipals?$filter=appId eq '{app_id}'&$select=id,appId,displayName"):
            objects.setdefault(sp["id"], slim(sp))

    # Show the tenant's domain (from ca-auditor@contoso.onmicrosoft.com) rather than a bare GUID.
    tenant = username.split("@", 1)[1] if "@" in username else tenant_id
    return {
        "metadata": {
            "tenant": tenant,
            "tenantId": tenant_id,
            "collectedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "collectedBy": username,
            "source": "Microsoft Graph v1.0",
            "tool": f"ca-gap-analyzer {__version__}",
            "warnings": warnings,
        },
        "conditionalAccessPolicies": raw_policies,
        "namedLocations": named_locations,
        "roleDefinitions": role_definitions,
        "roleAssignments": role_assignments,
        "roleEligibilities": role_eligibilities,
        "groupMembers": group_members,
        "directoryObjects": sorted(objects.values(), key=lambda o: o["id"]),
    }


def default_output_path(now: datetime | None = None) -> Path:
    now = now or datetime.now(timezone.utc)
    return EXPORTS_DIR / f"snapshot-{now:%Y%m%d-%H%M%S}.json"


def save_snapshot(snapshot: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
