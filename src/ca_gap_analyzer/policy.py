"""A thin, readable wrapper around one Conditional Access policy's Graph JSON.

Graph JSON is deeply nested and full of nulls, e.g.
    policy["conditions"]["users"]["includeUsers"]
This class turns those lookups into plain-English properties like `policy.targets_all_users`,
so the checks read almost like the rules in docs/CHECKS.md.
"""

from datetime import datetime

from .graphtime import parse_graph_datetime

# Graph's three possible values for a policy's "state"
ENABLED = "enabled"
REPORT_ONLY = "enabledForReportingButNotEnforced"
DISABLED = "disabled"

# Built-in "Phishing-resistant MFA" authentication strength (same ID in every tenant)
PHISHING_RESISTANT_STRENGTH_ID = "00000000-0000-0000-0000-000000000004"


class Policy:
    def __init__(self, raw: dict):
        self.raw = raw

    # --- Basics ----------------------------------------------------------------

    @property
    def id(self) -> str:
        return self.raw.get("id", "")

    @property
    def name(self) -> str:
        return self.raw.get("displayName", "(unnamed policy)")

    @property
    def state(self) -> str:
        return self.raw.get("state", "")

    @property
    def is_enforced(self) -> bool:
        """Only 'enabled' policies actually protect anything."""
        return self.state == ENABLED

    @property
    def state_label(self) -> str:
        return {ENABLED: "On", REPORT_ONLY: "Report-only", DISABLED: "Off"}.get(self.state, self.state)

    @property
    def modified_at(self) -> datetime | None:
        return parse_graph_datetime(self.raw.get("modifiedDateTime") or self.raw.get("createdDateTime"))

    # --- Assignments: who and what -----------------------------------------------

    @property
    def _conditions(self) -> dict:
        return self.raw.get("conditions") or {}

    @property
    def _users(self) -> dict:
        return self._conditions.get("users") or {}

    @property
    def include_users(self) -> list[str]:
        return self._users.get("includeUsers") or []

    @property
    def exclude_users(self) -> list[str]:
        return self._users.get("excludeUsers") or []

    @property
    def include_groups(self) -> list[str]:
        return self._users.get("includeGroups") or []

    @property
    def exclude_groups(self) -> list[str]:
        return self._users.get("excludeGroups") or []

    @property
    def include_roles(self) -> list[str]:
        return self._users.get("includeRoles") or []

    @property
    def exclude_roles(self) -> list[str]:
        return self._users.get("excludeRoles") or []

    @property
    def targets_all_users(self) -> bool:
        return "All" in self.include_users

    @property
    def include_applications(self) -> list[str]:
        apps = self._conditions.get("applications") or {}
        return apps.get("includeApplications") or []

    @property
    def exclude_applications(self) -> list[str]:
        apps = self._conditions.get("applications") or {}
        return apps.get("excludeApplications") or []

    @property
    def targets_all_apps(self) -> bool:
        return "All" in self.include_applications

    # --- Conditions: extra filters on the sign-in ------------------------------------

    @property
    def client_app_types(self) -> list[str]:
        # An empty or missing list means the condition isn't configured, which Graph treats as "all".
        return self._conditions.get("clientAppTypes") or ["all"]

    @property
    def applies_to_all_client_apps(self) -> bool:
        return "all" in self.client_app_types

    @property
    def risk_levels(self) -> list[str]:
        c = self._conditions
        return (c.get("signInRiskLevels") or []) + (c.get("userRiskLevels") or [])

    @property
    def authentication_flows(self) -> list[str]:
        """e.g. ["deviceCodeFlow", "authenticationTransfer"]. Graph sends a comma-separated string."""
        flows = (self._conditions.get("authenticationFlows") or {}).get("transferMethods") or ""
        return [f.strip() for f in flows.split(",") if f.strip()]

    @property
    def excludes_guests(self) -> bool:
        return ("GuestsOrExternalUsers" in self.exclude_users
                or bool(self._users.get("excludeGuestsOrExternalUsers")))

    @property
    def narrowing_conditions(self) -> list[str]:
        """Conditions that make the policy apply to only *some* sign-ins.

        A policy with any of these set doesn't give blanket coverage. For example, "require MFA,
        but only on Android" is not "require MFA for everyone."
        """
        c = self._conditions
        found = []
        if self._limits(c.get("platforms"), "includePlatforms", "excludePlatforms"):
            found.append("device platforms")
        if self._limits(c.get("locations"), "includeLocations", "excludeLocations"):
            found.append("locations")
        if c.get("signInRiskLevels"):
            found.append("sign-in risk")
        if c.get("userRiskLevels"):
            found.append("user risk")
        if c.get("devices"):
            found.append("device filter")
        return found

    @staticmethod
    def _limits(condition: dict | None, include_key: str, exclude_key: str) -> bool:
        """Does this platform/location condition actually rule anything out?

        "Any device" (includePlatforms: ["all"]) or "Any location" (includeLocations: ["All"])
        with nothing excluded is configured, but covers everything.
        """
        if not condition:
            return False
        include = [v.lower() for v in condition.get(include_key) or []]
        excluded = condition.get(exclude_key) or []
        return bool(excluded) or include != ["all"]

    # --- Access controls: what happens ---------------------------------------------

    @property
    def _grant(self) -> dict:
        return self.raw.get("grantControls") or {}

    @property
    def grant_controls(self) -> list[str]:
        return self._grant.get("builtInControls") or []

    @property
    def authentication_strength(self) -> str | None:
        strength = self._grant.get("authenticationStrength")
        return strength.get("displayName") if strength else None

    @property
    def requires_phishing_resistant_mfa(self) -> bool:
        strength = self._grant.get("authenticationStrength") or {}
        return (strength.get("id") == PHISHING_RESISTANT_STRENGTH_ID
                or "phishing" in (strength.get("displayName") or "").lower())

    @property
    def sign_in_frequency(self) -> dict | None:
        freq = (self.raw.get("sessionControls") or {}).get("signInFrequency") or {}
        return freq if freq.get("isEnabled") else None

    @property
    def blocks(self) -> bool:
        return "block" in self.grant_controls

    @property
    def requires_mfa(self) -> bool:
        """True only if MFA can't be skipped by satisfying some other control instead.

        With operator "OR", a user can pick any one control. "MFA OR compliant device" lets a
        user on a compliant device sign in without MFA, so it doesn't count.
        """
        has_mfa = "mfa" in self.grant_controls or self.authentication_strength is not None
        if not has_mfa:
            return False
        other_controls = [c for c in self.grant_controls if c != "mfa"]
        if self._grant.get("operator", "OR") == "OR" and other_controls:
            return False
        return True
