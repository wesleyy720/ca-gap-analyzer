# Lab Tenant Setup Guide

This guide turns a fresh Azure trial tenant into a lab for the CA Gap Analyzer. You'll set up
a working Conditional Access baseline, add a few *deliberately flawed* policies for the tool to
find, and create a read-only app registration the tool can sign in with.

**Use a lab tenant only.** Never point a personal project at your employer's tenant, and never
commit real tenant exports to GitHub.

Work through the phases in order. Check boxes as you go.

---

## Phase 0: Your PC

- [x] Python 3.12 (already installed)
- [x] Git (already installed)
- [ ] A [GitHub](https://github.com) account. Use a professional username, because recruiters will see it.
- [ ] Optional: [VS Code](https://code.visualstudio.com/) for browsing the code

---

## Phase 1: Tenant basics

All Entra steps happen in the **Microsoft Entra admin center**: https://entra.microsoft.com

### 1.1 Note your tenant details
- [ ] Sign in with the trial's admin account.
- [ ] Go to **Identity > Overview** and copy the **Tenant ID** and **Primary domain**
      (`something.onmicrosoft.com`). Save them somewhere private. You'll need them in Phase 3.

### 1.2 Get Conditional Access licensing
Conditional Access requires **Entra ID P1**. Risk-based policies need **P2**. A new Azure trial
tenant comes with **Entra ID Free**, so you need to start a free trial:

- [ ] Go to **Identity > Billing > Licenses > All products > + Try / Buy**, then activate
      the **Microsoft Entra ID P2** free trial (30 days).
      - If that option isn't shown, use the Microsoft 365 admin center
        (https://admin.microsoft.com) **> Billing > Purchase services** and start a trial that
        includes Entra ID P2 (for example, Microsoft 365 E5 or EMS E5).
- [ ] Assign the license to your admin account and the test users you create in step 1.4.

> The tool also runs fully offline against synthetic sample data, so when the trial ends you
> can keep developing.

### 1.3 Create a break-glass (emergency access) account
This account keeps you from locking yourself out while you experiment with Conditional Access.

- [ ] **Identity > Users > New user**: `breakglass01@<yourdomain>.onmicrosoft.com`
- [ ] Use a long random password and store it offline, such as in a password manager. Don't reuse it.
- [ ] Assign the **Global Administrator** role.
- [ ] Register a strong MFA method for it. A passkey or FIDO2 key is best. Microsoft now enforces
      MFA for admin portals, so this account needs a method too.
- [ ] **Exclude this account from every Conditional Access policy you create.**

### 1.4 Create test users, groups, and roles
These give the analyzer realistic data, including some deliberate mistakes.

| User | Purpose | Role |
|------|---------|------|
| `alice` | Regular employee (Finance) | none |
| `bob` | Helpdesk admin | Helpdesk Administrator |
| `carol` | Privileged admin | Privileged Role Administrator |
| `dave` | Regular employee (Sales) | none |
| `erin` | Exchange admin | Exchange Administrator |
| `svc-legacy-scanner` | Old service account | none |
| `ca-auditor` | **Account the tool signs in as** | **Global Reader** |

| Group | Members | Purpose |
|-------|---------|---------|
| `All-Staff` | alice, bob, carol, dave, erin | Normal targeting group |
| `CA-Exclusions-Temp` | **carol, svc-legacy-scanner** | Deliberate gap: privileged user and service account in an exclusion group |

**Fast way: run the script** [scripts/New-LabUsers.ps1](../scripts/New-LabUsers.ps1). It creates
all of the above and assigns the P2 license.

- [ ] One-time: install the Microsoft Graph PowerShell modules:
  ```powershell
  Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Users.Actions, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.Governance -Scope CurrentUser
  ```
- [ ] From the project folder, run:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\New-LabUsers.ps1
  ```
  Sign in as your **admin** in the browser window, accept the permissions prompt, and type `YES`
  once you've confirmed the tenant name is your lab.
- [ ] Save the `ca-auditor` temporary password it prints.
- [ ] To undo everything later: add `-Remove` to the end of the same command.

**Manual way:** create the users (**Identity > Users > New user**), assign roles (**Identity >
Roles & admins**, select the role, then **Add assignments**), and create the groups
(**Identity > Groups > New group**, type *Security*).

### 1.5 Turn off security defaults
Security defaults and Conditional Access can't both be on. New tenants have security defaults
enabled, and you must disable them before you can create CA policies.

> Do this only in your lab tenant. Then create policy **CA001** (next step) right away so the
> tenant isn't left without MFA.

- [ ] **Identity > Overview > Properties > Manage security defaults**, then select **Disabled**.

### 1.6 Create the Conditional Access test policies
Go to **Protection > Conditional Access > Policies > + New policy**.

**Good baseline policies (set to *On*):**

| Name | Users | Target resources | Conditions | Grant |
|------|-------|------------------|-----------|-------|
| `CA001 - Require MFA - All users` | All users, **exclude breakglass01** and the `CA-Exclusions-Temp` group (deliberate gap: carol, a privileged admin, skips MFA) | All resources | none | Require MFA |
| `CA002 - Block legacy authentication` | All users, exclude breakglass01 | All resources | Client apps: Exchange ActiveSync + Other clients | Block |

**Deliberately flawed policies (set to *Report-only*, so they can't lock anything):**

| Name | The flaw the tool should catch |
|------|-------------------------------|
| `CA100 - Phishing-resistant MFA - Admins` | Includes only *Global Administrator*, and excludes the `CA-Exclusions-Temp` group (which contains carol) |
| `CA101 - Block high-risk sign-ins` | Left in report-only, so it never enforces |
| `CA102 - Require compliant device` | Targets one app only and excludes `All-Staff`, so it covers almost no one |
| `CA103 - Old pilot policy` | Set to **Off** (disabled) |

Also create one bad **named location** (**Protection > Conditional Access > Named locations
> + IP ranges location**):

- [ ] `Office-HQ`, marked **trusted**, with range `20.0.0.0/8`. That's 16 million addresses,
      much of it Azure public IP space, so anyone who rents an Azure VM is "in the office."
      Real tenants have this kind of mistake. (Entra rejects ranges broader than /8.)

> Use the **What If** tool (Conditional Access > Policies > What If) to sanity-check policies
> before turning any of them on.

---

## Phase 2: App registration for the tool (read-only, no secrets)

The tool signs in as a **public client** with **delegated** permissions. There's no client
secret to leak, and the tool can only read what the signed-in user (`ca-auditor`, a Global
Reader) is allowed to read.

- [ ] **Identity > Applications > App registrations > + New registration**
  - Name: `CA Gap Analyzer (local)`
  - Supported account types: **Single tenant**
  - Redirect URI: platform **Public client/native (mobile & desktop)**, value `http://localhost`
- [ ] On the app's **Overview** page, copy the **Application (client) ID**.
- [ ] **Authentication**: set **Allow public client flows** to **Yes** (enables device code sign-in).
- [ ] **API permissions > + Add a permission > Microsoft Graph > Delegated permissions**, add:
  - `Policy.Read.All` (Conditional Access policies and named locations)
  - `Directory.Read.All` (users, groups, and memberships)
  - `RoleManagement.Read.Directory` (directory role assignments)
- [ ] Remove the default `User.Read` only if you want. It's harmless.
- [ ] Click **Grant admin consent for \<tenant\>**.

> **Interview talking point:** "I used delegated read-only scopes with a public client and no
> secret, so the tool can't exceed the signed-in auditor's own rights."

---

## Phase 3: Verify you can read the data

Before writing any code, confirm the data is reachable:

- [ ] Open **Graph Explorer**: https://developer.microsoft.com/graph/graph-explorer
- [ ] Sign in as `ca-auditor` and consent if prompted.
- [ ] Run `GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`
- [ ] You should see JSON for CA001–CA103. That's exactly what the tool will analyze.

Then create a local `.env` file in the project folder (it's git-ignored):

```
CA_TENANT_ID=<your tenant id>
CA_CLIENT_ID=<your application (client) id>
```

These IDs aren't secrets, but keeping them out of git is good practice.

---

## Phase 4: GitHub

- [ ] Create an **empty public repository** named `ca-gap-analyzer` (no README, no .gitignore,
      since the project already has both).
- [ ] Tell Claude Code the repo URL. It will connect the remote and push.

---

## Phase 5: Build

Return to Claude Code and work through [ROADMAP.md](ROADMAP.md) one milestone at a time.
