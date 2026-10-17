# Check Catalog

This is the heart of the tool, and it's the part **you** own as the domain expert. Edit freely:
change severities, add checks, or reword the reasoning. The code implements whatever this file
says.

"Enforcing policy" means a policy with `state: enabled`. Report-only (`enabledForReportingButNotEnforced`)
and disabled policies don't protect anything.

| ID | Check | Severity | Lab policy that should trigger it |
|----|-------|----------|-----------------------------------|
| CA-01 | No enforcing policy requires MFA for all users | High | (passes thanks to CA001) |
| CA-02 | Privileged roles not covered by phishing-resistant MFA | Critical | CA100 |
| CA-03 | Legacy authentication not blocked | High | (passes thanks to CA002) |
| CA-04 | Privileged users excluded from enforcing policies | High | CA001 excludes `CA-Exclusions-Temp` (carol) |
| CA-05 | Broad exclusions that cover most users | Medium | CA102 |
| CA-06 | Policies stuck in report-only or disabled | Low / Medium | CA100–CA103 |
| CA-07 | No sign-in risk or user risk policy enforced | Medium | CA101 |
| CA-08 | Trusted named location with an over-broad IP range | High | `Office-HQ` |
| CA-09 | Device code flow not restricted | Medium | (no policy, so it triggers) |
| CA-10 | No break-glass account consistently excluded | Medium | (passes) |
| CA-11 | Guests and external users not covered by MFA | Medium | depends on CA001 scope |
| CA-12 | No sign-in frequency or session controls for admins | Low | (triggers) |

---

### CA-01: No enforcing policy requires MFA for all users
- **Why it matters:** Password spray and credential stuffing succeed against any account without MFA (MITRE T1110).
- **Detection:** No enabled policy with `users.includeUsers = ["All"]`, `applications.includeApplications = ["All"]`, and `grantControls.builtInControls` containing `mfa` (or an `authenticationStrength`).
- **Fix:** Create an enabled "Require MFA for all users" policy that excludes only break-glass accounts.

### CA-02: Privileged roles not covered by phishing-resistant MFA
- **Why it matters:** Admin accounts are the top target for AiTM phishing (Evilginx-style token theft). Standard MFA can be phished. FIDO2 and passkeys can't.
- **Detection:** For each high-privilege role (Global Admin, Privileged Role Admin, Security Admin, Exchange Admin, SharePoint Admin, Conditional Access Admin, Helpdesk Admin, User Admin, Application Admin, Cloud App Admin, Authentication Admin, Billing Admin), check whether an enabled policy targets it via `users.includeRoles` with the phishing-resistant authentication strength.
- **Fix:** One enabled policy covering all privileged roles and requiring the built-in "Phishing-resistant MFA" authentication strength.

### CA-03: Legacy authentication not blocked
- **Why it matters:** Legacy protocols (IMAP, POP, SMTP AUTH, ActiveSync basic auth) can't do MFA, so they're the classic MFA bypass for password spray.
- **Detection:** No enabled policy with `conditions.clientAppTypes` including `exchangeActiveSync` and `other`, targeting all users, with grant `block`.
- **Fix:** Enabled "Block legacy authentication" policy for all users.

### CA-04: Privileged users excluded from enforcing policies
- **Why it matters:** An exclusion group is a silent hole. One "temporary" exclusion can leave a Global Admin without MFA for years.
- **Detection:** Expand `excludeUsers` and `excludeGroups` (including nested groups) on every enabled policy. Flag any member who holds a privileged role and isn't a designated break-glass account.
- **Fix:** Remove the user from the exclusion, or justify and document it with an expiry date.

### CA-05: Broad exclusions that cover most users
- **Why it matters:** A policy that excludes most of its targets gives false assurance.
- **Detection:** Excluded groups or users make up more than X% (default 25%) of the included population, or an exclusion is a large catch-all group.
- **Fix:** Narrow the exclusions. Prefer small, reviewed, named exception groups.

### CA-06: Policies stuck in report-only or disabled
- **Why it matters:** Report-only policies look like protection in a quick review, but they enforce nothing.
- **Detection:** `state` is `enabledForReportingButNotEnforced` or `disabled`. Low severity if recently changed (possibly mid-rollout), Medium if `modifiedDateTime` is 30+ days ago (likely forgotten).
- **Fix:** Review the report-only impact in sign-in logs, then enable the policy or delete it.

### CA-07: No sign-in risk or user risk policy enforced
- **Why it matters:** Without one, Entra ID Protection detects risky sign-ins (leaked credentials, anonymous IPs) but nothing acts on them.
- **Detection:** No enabled policy with `conditions.signInRiskLevels` or `conditions.userRiskLevels` set. Requires P2.
- **Fix:** Enforce MFA for medium/high sign-in risk, and require a secure password change for high user risk.

### CA-08: Trusted named location with an over-broad IP range
- **Why it matters:** Trusted locations are often used to skip MFA or lower risk scoring. A /1 or /8 "office" range trusts a huge chunk of the internet.
- **Detection:** An `ipNamedLocation` with `isTrusted: true` and any range broader than /16 for IPv4 (or /48 for IPv6), or one that includes `0.0.0.0/0`.
- **Fix:** Limit to real egress IPs, and don't use location as a substitute for MFA.

### CA-09: Device code flow not restricted
- **Why it matters:** Device code phishing is an active, widely abused technique (it's been used by state actors since 2024). Most users never need this flow.
- **Detection:** No enabled policy with `conditions.authenticationFlows.transferMethods` containing `deviceCodeFlow` and grant `block`.
- **Fix:** Block device code flow for all users, with exceptions only for devices that actually need it, such as conference room systems.

### CA-10: No break-glass account consistently excluded
- **Why it matters:** Without an emergency account excluded everywhere, a bad policy can lock out every admin.
- **Detection:** Find users excluded from *all* enabled policies. Flag if there are none, or if a likely break-glass account is excluded from some policies but not others.
- **Fix:** Two cloud-only emergency accounts with phishing-resistant MFA, excluded from all policies and monitored with alerts.

### CA-11: Guests and external users not covered by MFA
- **Why it matters:** A guest from a weakly secured partner tenant is an easy way in.
- **Detection:** The MFA policies exclude `GuestsOrExternalUsers`, or scope to internal groups only.
- **Fix:** Include guests in MFA policies, and use cross-tenant access settings to trust partner MFA where appropriate.

### CA-12: No sign-in frequency or session controls for admins
- **Why it matters:** Long-lived admin sessions widen the window for token theft and replay.
- **Detection:** No enabled policy targeting privileged roles with `sessionControls.signInFrequency` set.
- **Fix:** Set an admin sign-in frequency (for example, 4–12 hours) and don't use persistent browser sessions for admins.
