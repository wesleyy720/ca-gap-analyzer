"""Signing in to Entra ID with MSAL (the Microsoft Authentication Library).

The tool is a *public client*: it has no secret of its own. A person signs in through the
browser, and Entra issues a token that lets the tool act as that person, limited to SCOPES.

We deliberately don't offer device code sign-in. Device code phishing is what check CA-09
warns about, and a tenant that blocks it (as it should) would break the tool.
"""

from dataclasses import dataclass

import msal

GRAPH = "https://graph.microsoft.com/"

# Only what the collector reads. Least privilege means adding scopes only when a feature needs them.
SCOPES = [
    GRAPH + "Policy.Read.All",                 # CA policies and named locations
    GRAPH + "Directory.Read.All",              # names of users, groups, apps; group memberships
    GRAPH + "RoleManagement.Read.Directory",   # who holds which admin role (active and PIM eligible)
]


class AuthError(Exception):
    pass


# Common AADSTS error codes, translated into what to actually fix.
KNOWN_ERRORS = {
    "AADSTS7000218": (
        "The app registration is set up as a web app, so Entra expects a client secret. In the "
        "Entra admin center: App registrations > CA Gap Analyzer (local) > Authentication. Make sure "
        "http://localhost is listed under 'Mobile and desktop applications', not under 'Web'."
    ),
    "AADSTS50011": (
        "Redirect URI mismatch. Under App registrations > CA Gap Analyzer (local) > Authentication, "
        "add a 'Mobile and desktop applications' platform with redirect URI http://localhost."
    ),
    "AADSTS700016": "App not found in this tenant. Check CA_CLIENT_ID and CA_TENANT_ID in .env.",
    "AADSTS90002": "Tenant not found. Check CA_TENANT_ID in .env.",
    "AADSTS65001": (
        "Permissions haven't been consented. App registrations > CA Gap Analyzer (local) > "
        "API permissions > Grant admin consent."
    ),
    "AADSTS50105": "The signed-in account isn't allowed to use this app (it may require user assignment).",
}


def explain(result: dict) -> str:
    """Turn an MSAL error result into a readable message with a fix."""
    description = result.get("error_description") or result.get("error") or "unknown error"
    first_line = description.splitlines()[0]
    for code, hint in KNOWN_ERRORS.items():
        if code in description:
            return f"{hint}\n(Entra said: {first_line})"
    return f"Sign-in failed: {first_line}"


@dataclass
class SignIn:
    access_token: str
    username: str       # e.g. ca-auditor@contoso.onmicrosoft.com
    tenant_id: str


def sign_in(tenant_id: str, client_id: str) -> SignIn:
    app = msal.PublicClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )
    print("Opening your browser to sign in. Choose the ca-auditor account.", flush=True)
    # prompt="select_account" always shows the account picker, so you don't silently
    # sign in as whoever the browser last used (like your admin account).
    result = app.acquire_token_interactive(scopes=SCOPES, prompt="select_account")

    if "access_token" not in result:
        raise AuthError(explain(result))

    claims = result.get("id_token_claims") or {}
    return SignIn(
        access_token=result["access_token"],
        username=claims.get("preferred_username", "unknown"),
        tenant_id=claims.get("tid", tenant_id),
    )
