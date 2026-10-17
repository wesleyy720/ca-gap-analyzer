"""Who does a policy *really* apply to?

The portal shows a policy's include/exclude lists, but the real question is per person:
"does this policy apply to carol?" Answering that means expanding groups (including nested
ones) and role assignments, the way Entra does at sign-in.
"""

from .directory import Directory
from .policy import Policy
from .privileged import user_roles

SPECIAL = {"All", "None", "GuestsOrExternalUsers"}


def _role_holders(role_id: str, directory: Directory, roles_by_user) -> set[str]:
    role = directory.roles.get(role_id)
    ids = {role_id} | ({role["id"], role.get("templateId")} if role else set())
    return {u for u, grants in roles_by_user.items() if any(g.role_id in ids for g in grants)}


def excluded_users(policy: Policy, directory: Directory, roles_by_user=None) -> dict[str, list[str]]:
    """Every user a policy excludes, with how: directly, via a group, or via a role."""
    roles_by_user = roles_by_user if roles_by_user is not None else user_roles(directory)
    reasons: dict[str, list[str]] = {}
    for user_id in policy.exclude_users:
        if user_id not in SPECIAL:
            reasons.setdefault(user_id, []).append("directly")
    for group_id in policy.exclude_groups:
        for member in directory.members(group_id):
            if directory.kind(member["id"]) != "group":
                reasons.setdefault(member["id"], []).append(f"via group {directory.name(group_id)}")
    for role_id in policy.exclude_roles:
        for user_id in _role_holders(role_id, directory, roles_by_user):
            reasons.setdefault(user_id, []).append(f"via role {directory.role_name(role_id)}")
    return reasons


def includes_user(policy: Policy, user_id: str, directory: Directory, roles_by_user=None) -> bool:
    """Is the user in the policy's include list (before exclusions)?"""
    if "All" in policy.include_users or user_id in policy.include_users:
        return True
    for group_id in policy.include_groups:
        if any(m["id"] == user_id for m in directory.members(group_id)):
            return True
    roles_by_user = roles_by_user if roles_by_user is not None else user_roles(directory)
    return any(user_id in _role_holders(r, directory, roles_by_user) for r in policy.include_roles)


def covers(policy: Policy, user_id: str, directory: Directory, roles_by_user=None) -> bool:
    """Does the policy apply to this user (included and not excluded)?"""
    roles_by_user = roles_by_user if roles_by_user is not None else user_roles(directory)
    return (includes_user(policy, user_id, directory, roles_by_user)
            and user_id not in excluded_users(policy, directory, roles_by_user))


def is_unconditional(policy: Policy) -> bool:
    """Applies to every app, every client type, with no narrowing conditions."""
    return policy.targets_all_apps and policy.applies_to_all_client_apps and not policy.narrowing_conditions


def is_security_control(policy: Policy) -> bool:
    """Policies whose exclusions matter: they block, or require MFA or an auth strength."""
    return policy.blocks or policy.requires_mfa
