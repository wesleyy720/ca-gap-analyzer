# CA Gap Analyzer

Finds security gaps in Microsoft Entra ID Conditional Access configurations.

The tool reads a tenant's Conditional Access policies, named locations, directory roles, and
group memberships (read-only, through Microsoft Graph or from an exported JSON snapshot). It
reports where the configuration leaves identities exposed, such as admins without strong MFA,
unblocked legacy authentication, or broad exclusions. Each finding includes a severity, the
attack it enables, and a recommended fix.

> **Status:** early development. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Why

Most Conditional Access reviews are done by hand, in the portal, one policy at a time. Gaps
hide in the interactions *between* policies: an exclusion group in one policy, a report-only
policy that was never switched on, or a trusted location that covers half the internet. This
tool makes that review repeatable.

## Quickstart (sample data, no tenant needed)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\ca-gap-analyzer.exe analyze samples\lab_snapshot.json
```

Add `--format json` for machine-readable output. Run the tests with
`.\.venv\Scripts\python.exe -m pytest`.

## Analyze a live tenant

1. Create the read-only app registration ([docs/SETUP.md](docs/SETUP.md), Phase 2).
2. Copy `.env.example` to `.env` and fill in your tenant ID and client ID.
3. Collect and analyze:

```powershell
.\.venv\Scripts\ca-gap-analyzer.exe collect --analyze
```

A browser window opens for sign-in. Use a Global Reader or Security Reader account. The snapshot
is saved to `exports/` (git-ignored), and you can re-analyze it later without signing in again.

## Docs

- [Tenant setup guide](docs/SETUP.md): build a safe lab tenant and a read-only app registration
- [Check catalog](docs/CHECKS.md): every check, why it matters, and how it's detected
- [Roadmap](docs/ROADMAP.md): milestones and status

## Security model

- **Read-only.** Uses delegated Microsoft Graph read permissions only.
- **No secrets.** Public client, interactive browser sign-in, with no client secret to leak. No
  device code flow, so it works in tenants that block device code phishing.
- **Least privilege.** Intended to run as a Global Reader or Security Reader account.
- **No tenant data in git.** Exports and reports are git-ignored; sample data is synthetic.
