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

## M3: Identity enrichment
- [ ] Resolve GUIDs to names (users, groups, roles, apps)
- [ ] Expand exclusion groups to find privileged users hiding in them (CA-02, CA-04)
- [ ] Remaining checks from the catalog

## M4: Report
- [ ] HTML report: executive summary, severity counts, per-finding detail and fix
- [ ] Map each finding to Microsoft's CA baseline guidance and MITRE ATT&CK
- [ ] A KQL hunting query per finding ("has this gap been abused?") for Sentinel / Log Analytics

## M5: Portfolio polish
- [ ] README with a screenshot of the report and a sample-data quickstart
- [ ] GitHub Actions CI (tests and lint) with a badge
- [ ] Short write-up: "What I found reviewing Conditional Access gaps" (blog or LinkedIn post)

## Resume bullet (once M4 is done)
> Designed and built a Python tool that audits Microsoft Entra ID Conditional Access via
> Microsoft Graph, detecting 12+ identity security gaps (unprotected privileged roles, legacy auth,
> over-broad trusted locations) and generating remediation reports with KQL hunting queries.
