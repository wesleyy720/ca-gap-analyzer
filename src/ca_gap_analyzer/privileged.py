"""Which admin roles count as privileged, and which users hold them.

A user is privileged if they hold one of these roles in any way: assigned directly, through a
role-assignable group, or PIM eligible (they can activate it whenever they like, so an attacker
who takes over the account can too).
"""

from dataclasses import dataclass

from .directory import Directory

# Built-in roles that can take over the tenant, its identities, or its security settings.
# Matched by template ID (the same in every tenant) or, as a fallback, by display name.
PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
}
PRIVILEGED_NAMES = set(PRIVILEGED_ROLES.values())


def is_privileged_role(role_id: str, directory: Directory) -> bool:
    if role_id in PRIVILEGED_ROLES:
        return True
    role = directory.roles.get(role_id)
    return bool(role) and (role.get("templateId") in PRIVILEGED_ROLES
                           or role.get("displayName") in PRIVILEGED_NAMES)


@dataclass
class RoleGrant:
    role_id: str
    role_name: str
    kind: str              # "active" or "eligible"
    via_group: str | None  # group name if the role comes through a group

    def label(self) -> str:
        extras = []
        if self.kind == "eligible":
            extras.append("PIM eligible")
        if self.via_group:
            extras.append(f"via group {self.via_group}")
        return self.role_name + (f" ({', '.join(extras)})" if extras else "")


def user_roles(directory: Directory) -> dict[str, list[RoleGrant]]:
    """Every user's role grants, with role-assignable groups expanded to their members."""
    grants: dict[str, list[RoleGrant]] = {}
    pairs = [(a, "active") for a in directory.role_assignments]
    pairs += [(e, "eligible") for e in directory.role_eligibilities]
    for assignment, kind in pairs:
        role_id = assignment["roleDefinitionId"]
        role_name = directory.role_name(role_id)
        principal = assignment["principalId"]
        if directory.kind(principal) == "group":
            group_name = directory.name(principal)
            for member in directory.members(principal):
                if directory.kind(member["id"]) == "user":
                    grants.setdefault(member["id"], []).append(RoleGrant(role_id, role_name, kind, group_name))
        elif directory.kind(principal) == "user":
            grants.setdefault(principal, []).append(RoleGrant(role_id, role_name, kind, None))
    return grants


def privileged_users(directory: Directory) -> dict[str, list[RoleGrant]]:
    """Only the users holding at least one privileged role, with just those roles."""
    result = {}
    for user_id, grants in user_roles(directory).items():
        privileged = [g for g in grants if is_privileged_role(g.role_id, directory)]
        if privileged:
            result[user_id] = privileged
    return result


def describe_user(user_id: str, grants: list[RoleGrant], directory: Directory) -> str:
    return f"{directory.name(user_id)} ({'; '.join(sorted({g.label() for g in grants}))})"
