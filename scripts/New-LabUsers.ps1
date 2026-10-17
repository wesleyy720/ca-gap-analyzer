<#
.SYNOPSIS
    Creates (or removes) the lab users, groups, role assignments, and licenses for CA Gap Analyzer.

.DESCRIPTION
    LAB TENANTS ONLY. Signs in to Microsoft Graph as you (an admin), shows which tenant it's
    connected to, and asks you to confirm before changing anything. Safe to re-run: anything
    that already exists is skipped.

    Every account gets a random password. Only the ca-auditor password is shown, because it's
    the only account you'll sign in with. Everyone else is just a target for the policies.

    The break-glass account is NOT created here on purpose. Create it by hand (SETUP.md step 1.3)
    so you control its password and MFA method.

.PARAMETER Remove
    Deletes the lab users and groups instead. Deleted users go to the recycle bin for 30 days.

.PARAMETER UsageLocation
    Two-letter country code. Required before a license can be assigned. Default: US.

.EXAMPLE
    .\scripts\New-LabUsers.ps1

.EXAMPLE
    .\scripts\New-LabUsers.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [string]$UsageLocation = 'US'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Lab data -- edit freely. The deliberate gaps are noted so you know what the
# analyzer should find later.
# ---------------------------------------------------------------------------
$LabUsers = @(
    @{ Nick = 'alice';              Name = 'Alice Anders';            Dept = 'Finance';  Role = $null }
    @{ Nick = 'bob';                Name = 'Bob Brooks';              Dept = 'IT';       Role = 'Helpdesk Administrator' }
    @{ Nick = 'carol';              Name = 'Carol Chen';              Dept = 'IT';       Role = 'Privileged Role Administrator' }   # gap: also in CA-Exclusions-Temp
    @{ Nick = 'dave';               Name = 'Dave Diaz';               Dept = 'Sales';    Role = $null }
    @{ Nick = 'erin';               Name = 'Erin Evans';              Dept = 'IT';       Role = 'Exchange Administrator' }          # gap: not covered by CA100 (Global Admin only)
    @{ Nick = 'svc-legacy-scanner'; Name = 'Legacy Scanner Service';  Dept = 'IT';       Role = $null }                             # gap: service account in exclusions
    @{ Nick = 'ca-auditor';         Name = 'CA Auditor (tool)';       Dept = 'Security'; Role = 'Global Reader'; ShowPassword = $true }
)

$LabGroups = @(
    @{ Name = 'All-Staff';          Members = @('alice', 'bob', 'carol', 'dave', 'erin') }
    @{ Name = 'CA-Exclusions-Temp'; Members = @('carol', 'svc-legacy-scanner') }
)

# Licenses that include Entra ID P2, in order of preference.
$P2Skus = @('AAD_PREMIUM_P2', 'EMSPREMIUM', 'SPE_E5', 'ENTERPRISEPREMIUM')

# ---------------------------------------------------------------------------

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Users.Actions',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Identity.Governance'
)
$missing = @($RequiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
if ($missing.Count -gt 0) {
    Write-Host "Missing PowerShell modules. Install them with:" -ForegroundColor Yellow
    Write-Host "  Install-Module $($missing -join ', ') -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}

function New-RandomPassword {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_=+'
    $bytes = New-Object byte[] 20
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    # The fixed suffix guarantees every complexity category is present.
    return (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })) + 'aZ7!'
}

function Get-LabUser([string]$Upn) {
    Get-MgUser -Filter "userPrincipalName eq '$Upn'" -Property Id, UserPrincipalName, AssignedLicenses
}

# --- Connect and confirm the tenant -----------------------------------------
$scopes = @(
    'User.ReadWrite.All',
    'Group.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory',
    'Organization.Read.All'
)
Connect-MgGraph -Scopes $scopes -NoWelcome

$org = Get-MgOrganization
$domain = ($org.VerifiedDomains | Where-Object { $_.IsInitial }).Name

Write-Host ""
Write-Host "Connected to tenant: $($org.DisplayName)  ($domain)" -ForegroundColor Cyan
Write-Host "Signed in as:        $((Get-MgContext).Account)" -ForegroundColor Cyan
if ($Remove) {
    Write-Host "This will DELETE the lab users and groups listed in this script." -ForegroundColor Red
} else {
    Write-Host "This will create $($LabUsers.Count) users and $($LabGroups.Count) groups, and assign roles and licenses." -ForegroundColor Yellow
}
$answer = Read-Host "Is this your LAB tenant? Type YES to continue"
if ($answer -cne 'YES') {
    Write-Host "Cancelled. Nothing was changed."
    exit 0
}

# --- Remove mode --------------------------------------------------------------
if ($Remove) {
    foreach ($g in $LabGroups) {
        $existing = Get-MgGroup -Filter "displayName eq '$($g.Name)'"
        foreach ($item in @($existing)) {
            if ($item) { Remove-MgGroup -GroupId $item.Id; Write-Host "  removed group  $($g.Name)" }
        }
    }
    foreach ($u in $LabUsers) {
        $existing = Get-LabUser "$($u.Nick)@$domain"
        if ($existing) { Remove-MgUser -UserId $existing.Id; Write-Host "  removed user   $($existing.UserPrincipalName)" }
    }
    Write-Host "Done. Deleted users stay in Entra > Users > Deleted users for 30 days."
    exit 0
}

# --- Users --------------------------------------------------------------------
Write-Host ""
Write-Host "Users"
$userIds = @{}
$auditorPassword = $null
$createdAny = $false

foreach ($u in $LabUsers) {
    $upn = "$($u.Nick)@$domain"
    $existing = Get-LabUser $upn
    if ($existing) {
        $userIds[$u.Nick] = $existing.Id
        Write-Host "  exists   $upn"
        continue
    }

    $password = New-RandomPassword
    $params = @{
        AccountEnabled    = $true
        DisplayName       = $u.Name
        MailNickname      = $u.Nick
        UserPrincipalName = $upn
        Department        = $u.Dept
        UsageLocation     = $UsageLocation
        PasswordProfile   = @{ Password = $password; ForceChangePasswordNextSignIn = $true }
    }
    $new = New-MgUser @params
    $userIds[$u.Nick] = $new.Id
    $createdAny = $true
    Write-Host "  created  $upn" -ForegroundColor Green

    if ($u.ShowPassword) { $auditorPassword = "$upn  ->  $password" }
    $password = $null
}

# New accounts can take a few seconds to show up everywhere in the directory.
if ($createdAny) {
    Write-Host "  waiting 15s for the new accounts to replicate..."
    Start-Sleep -Seconds 15
}

# --- Roles --------------------------------------------------------------------
Write-Host ""
Write-Host "Roles"
foreach ($u in ($LabUsers | Where-Object { $_.Role })) {
    $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$($u.Role)'"
    if (-not $roleDef) { Write-Warning "Role not found: $($u.Role)"; continue }

    $principalId = $userIds[$u.Nick]
    $assigned = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$principalId'" |
        Where-Object { $_.RoleDefinitionId -eq $roleDef.Id }
    if ($assigned) {
        Write-Host "  exists   $($u.Nick) -> $($u.Role)"
        continue
    }
    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $principalId -RoleDefinitionId $roleDef.Id -DirectoryScopeId '/' | Out-Null
    Write-Host "  assigned $($u.Nick) -> $($u.Role)" -ForegroundColor Green
}

# --- Groups -------------------------------------------------------------------
Write-Host ""
Write-Host "Groups"
foreach ($g in $LabGroups) {
    $group = Get-MgGroup -Filter "displayName eq '$($g.Name)'" | Select-Object -First 1
    if ($group) {
        Write-Host "  exists   $($g.Name)"
    } else {
        $group = New-MgGroup -DisplayName $g.Name -MailEnabled:$false -SecurityEnabled `
            -MailNickname ($g.Name -replace '[^a-zA-Z0-9]', '') -Description 'CA Gap Analyzer lab group'
        Write-Host "  created  $($g.Name)" -ForegroundColor Green
    }

    $currentMembers = @(Get-MgGroupMember -GroupId $group.Id -All | ForEach-Object { $_.Id })
    foreach ($nick in $g.Members) {
        $memberId = $userIds[$nick]
        if ($currentMembers -contains $memberId) { continue }
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $memberId
        Write-Host "           + $nick"
    }
}

# --- Licenses -----------------------------------------------------------------
Write-Host ""
Write-Host "Licenses"
$skus = Get-MgSubscribedSku -All
$sku = $null
foreach ($part in $P2Skus) {
    $sku = $skus | Where-Object { $_.SkuPartNumber -eq $part } | Select-Object -First 1
    if ($sku) { break }
}

if (-not $sku) {
    Write-Warning "No Entra ID P2 license found in this tenant. Assign licenses by hand (Billing > Licenses)."
} else {
    Write-Host "  using $($sku.SkuPartNumber)"
    foreach ($u in $LabUsers) {
        $user = Get-LabUser "$($u.Nick)@$domain"
        if ($user.AssignedLicenses.SkuId -contains $sku.SkuId) {
            Write-Host "  exists   $($u.Nick)"
            continue
        }
        try {
            Set-MgUserLicense -UserId $user.Id -AddLicenses @(@{ SkuId = $sku.SkuId }) -RemoveLicenses @() | Out-Null
            Write-Host "  assigned $($u.Nick)" -ForegroundColor Green
        } catch {
            Write-Warning "Could not license $($u.Nick): $($_.Exception.Message)"
        }
    }
}

# --- Summary ------------------------------------------------------------------
Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
if ($auditorPassword) {
    Write-Host ""
    Write-Host "Temporary password for the tool account (shown once; you'll change it at first sign-in):" -ForegroundColor Yellow
    Write-Host "  $auditorPassword"
    Write-Host "Save it in your password manager, then clear this window."
}
Write-Host ""
Write-Host "Next: SETUP.md step 1.5 (security defaults) and 1.6 (Conditional Access policies)."

Disconnect-MgGraph | Out-Null
