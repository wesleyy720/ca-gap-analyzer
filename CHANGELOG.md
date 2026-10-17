# Changelog

## 1.0.0 (2026-10-17)

First stable release. Audits Microsoft Entra ID Conditional Access for identity security gaps
using read-only Microsoft Graph access.

### Highlights
- **12 checks:** MFA for all users, phishing-resistant MFA for admins, legacy authentication,
  privileged users in exclusions, broad exclusions, unenforced policies, risk-based policies,
  over-broad trusted locations, device code flow, break-glass setup, guest MFA, and admin
  sign-in frequency
- **Identity-aware analysis:** expands nested groups, role-assignable groups, and PIM-eligible
  roles to the real people each policy covers
- **Break-glass handling:** designate accounts with `CA_BREAK_GLASS`, or let the tool make a
  clearly labeled guess
- **`policies` command:** every policy in plain English, with exclusion groups shown with members
- **HTML report:** executive summary, per-finding fixes, MITRE ATT&CK mappings, and KQL queries
  pre-filled with the affected users, policies, or IP ranges
- **Offline-friendly:** analyze saved snapshots; a synthetic sample tenant is included

### Install
```
pip install git+https://github.com/wesleyy720/ca-gap-analyzer.git@v1.0.0
```

### Security model
Delegated read-only scopes; public client with no secrets; no device code flow; collected
directory data trimmed to names and types; HTML-escaped, self-contained reports.

### Known limitations
- Only built-in roles count as privileged; custom roles aren't evaluated yet
- Delegated (interactive) sign-in only; no unattended app-only mode
- CA-05 thresholds (5+ users and more than 25% of the tenant) are fixed

### Tested
141 tests on Linux (Python 3.11 to 3.13) and Windows; verified against a live lab tenant.
