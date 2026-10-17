# Roadmap

Build in small milestones. Each one should end with something that runs, has tests, and is
committed.

**Stack:** Python 3.12 · `msal` (sign-in) · `requests` (Graph calls) · `jinja2` (HTML report) · `pytest`

## M1: Offline analyzer (no tenant needed) ✅
- [x] Project skeleton (`pyproject.toml`, `src/` layout, virtual environment)
- [x] Synthetic sample snapshot in `samples/`, in the same JSON shape Graph returns
- [x] Snapshot loader
- [x] First checks from [CHECKS.md](CHECKS.md): CA-01, CA-03, CA-06, CA-08
- [x] Console output (text and JSON) with severity
- [x] Unit tests for every check (each check gets "passes" and "fails" cases)

## M2: Live collection from Graph ✅
- [x] Sign-in with MSAL (interactive browser only; no device code, per CA-09)
- [x] `.env` settings with clear errors for missing or placeholder values
- [x] Graph client with paging and throttling (429) retries
- [x] `collect` command: pull policies and named locations, then save a snapshot to `exports/`
- [x] `analyze` command runs against any snapshot, live or sample (`collect --analyze` does both)
- [x] First run against the live lab tenant (2026-10-17: found every planted CA-06 and CA-08 gap)
- Roles and groups move to M3, which needs them (and their extra read scopes) for enrichment

## M3: Identity enrichment ✅
**Part A: collect and resolve identities**
- [x] Collect role definitions, active role assignments, and PIM eligible assignments
- [x] Resolve GUIDs to names (users, groups, roles, apps), for referenced objects only
- [x] Expand referenced groups to their transitive (nested) members
- [x] `policies` command: each policy in plain English, exclusion groups shown with members
- [x] Live run against the lab tenant (revealed a Global Admin excluded from MFA and legacy-auth blocking)

**Part B: identity checks**
- [x] CA-02 (admins without phishing-resistant MFA), CA-04 (privileged users excluded), CA-05 (broad exclusions)
- [x] CA-07, CA-09, CA-10, CA-11, CA-12: all 12 catalog checks implemented
- [x] Break-glass accounts: designated via `CA_BREAK_GLASS`, or guessed (and labeled as a guess)
- [x] Older snapshots without directory data still run; identity checks show as SKIP
- [ ] Live run against the lab tenant with `CA_BREAK_GLASS` set

## M4: Report ✅
- [x] HTML report: executive summary, severity counts, per-finding detail and fix
- [x] Self-contained (no external resources), light and dark mode, phone-friendly, print-friendly
- [x] All tenant text HTML-escaped (display names are attacker-controllable)
- [x] Map each finding to MITRE ATT&CK
- [x] A KQL hunting query per finding ("has this gap been abused?"), pre-filled with the
      finding's users, policies, or IP ranges
- [x] `report` command and `collect --report`
- [ ] Live check that the tenant user count now collects (fixed in this milestone)

## M5: Portfolio polish
- [x] README with a screenshot of the report and a sample-data quickstart
- [x] GitHub Actions CI (tests and lint on Linux and Windows) with a badge
- [x] MIT license and project metadata
- [ ] Short write-up: "What I found reviewing Conditional Access gaps" (blog or LinkedIn post)

## Ideas for later
- Scheduled scan from GitHub Actions using workload identity federation (no stored secrets)
- `diff` command: what changed between two snapshots (new exclusions, policies switched off)
- Suggested remediation commands (Microsoft Graph PowerShell) per finding, never auto-applied

## Resume bullet (once M4 is done)
> Designed and built a Python tool that audits Microsoft Entra ID Conditional Access via
> Microsoft Graph, detecting 12+ identity security gaps (unprotected privileged roles, legacy auth,
> over-broad trusted locations) and generating remediation reports with KQL hunting queries.
