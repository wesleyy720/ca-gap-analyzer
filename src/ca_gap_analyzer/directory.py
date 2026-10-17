"""Answers "who is this GUID?" questions about the snapshot's directory data.

Policies, role assignments, and group memberships all refer to things by ID. This class
indexes the collected objects so checks and reports can ask:
    directory.name(id)            -> "carol" / "CA-Exclusions-Temp" / the ID if unknown
    directory.members(group_id)   -> everyone in the group, including nested groups
    directory.role_name(role_id)  -> "Privileged Role Administrator"
    directory.role_holders(role)  -> who holds a role, and whether it's active or PIM eligible
"""

from dataclasses import dataclass

SPECIAL_USERS = {
    "All": "All users",
    "None": "No one",
    "GuestsOrExternalUsers": "Guests and external users",
}
SPECIAL_APPS = {
    "All": "All resources",
    "None": "No resources",
    "Office365": "Office 365",
    "MicrosoftAdminPortals": "Microsoft Admin Portals",
}
TYPE_LABELS = {
    "#microsoft.graph.user": "user",
    "#microsoft.graph.group": "group",
    "#microsoft.graph.servicePrincipal": "app",
}


@dataclass
class RoleHolder:
    principal_id: str
    role_id: str
    kind: str  # "active" or "eligible"


class Directory:
    def __init__(self, objects=(), role_definitions=(), role_assignments=(),
                 role_eligibilities=(), group_members=None):
        self.objects = {o["id"]: o for o in objects}
        self.apps = {o["appId"]: o for o in objects if o.get("appId")}
        # Built-in roles are referenced by templateId in policies but by id in assignments.
        # For built-ins the two are the same; index both so either lookup works.
        self.roles = {}
        for role in role_definitions:
            self.roles[role["id"]] = role
            if role.get("templateId"):
                self.roles[role["templateId"]] = role
        self.role_assignments = list(role_assignments)
        self.role_eligibilities = list(role_eligibilities)
        self.group_members = group_members or {}

    @property
    def is_empty(self) -> bool:
        """True for snapshots collected before identity enrichment existed."""
        return not self.objects and not self.roles

    # --- Names ---------------------------------------------------------------

    def name(self, object_id: str) -> str:
        if object_id in SPECIAL_USERS:
            return SPECIAL_USERS[object_id]
        obj = self.objects.get(object_id)
        if not obj:
            return object_id
        upn = obj.get("userPrincipalName")
        if upn:
            # Show the short part of a UPN (carol, not carol@contoso.onmicrosoft.com).
            return upn.split("@")[0]
        return obj.get("displayName") or object_id

    def kind(self, object_id: str) -> str | None:
        obj = self.objects.get(object_id)
        return TYPE_LABELS.get(obj.get("@odata.type")) if obj else None

    def role_name(self, role_id: str) -> str:
        role = self.roles.get(role_id)
        return role["displayName"] if role else role_id

    def app_name(self, app_id: str) -> str:
        if app_id in SPECIAL_APPS:
            return SPECIAL_APPS[app_id]
        app = self.apps.get(app_id)
        return app["displayName"] if app else app_id

    # --- Relationships --------------------------------------------------------

    def members(self, group_id: str) -> list[dict]:
        """Everyone in a group, including members of nested groups."""
        return [self.objects.get(m, {"id": m}) for m in self.group_members.get(group_id, [])]

    def role_holders(self, role_id: str) -> list[RoleHolder]:
        """Who holds a role directly (users, groups, or apps), active or PIM eligible."""
        role = self.roles.get(role_id)
        ids = {role_id} | ({role["id"], role.get("templateId")} if role else set())
        holders = [RoleHolder(a["principalId"], a["roleDefinitionId"], "active")
                   for a in self.role_assignments if a["roleDefinitionId"] in ids]
        holders += [RoleHolder(e["principalId"], e["roleDefinitionId"], "eligible")
                    for e in self.role_eligibilities if e["roleDefinitionId"] in ids]
        return holders
