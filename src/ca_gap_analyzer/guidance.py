"""Threat context for each check: MITRE ATT&CK techniques and a KQL hunting query.

A finding says "this gap exists." The KQL query answers the next question a SOC analyst asks:
"has anyone already used it?" Queries run against the SigninLogs table in Log Analytics or
Microsoft Sentinel (Entra ID > Diagnostic settings must be sending sign-in logs there).

Where a finding names specific users, policies, or IP ranges, the query is filled in with
them, so it can be pasted and run as-is.
"""

from dataclasses import dataclass, field

from .breakglass import resolve
from .findings import Finding
from .privileged import privileged_users
from .snapshot import Snapshot

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


@dataclass
class Guidance:
    techniques: list[tuple[str, str]] = field(default_factory=list)  # (ID, name)
    kql: str = ""  # may contain {users}, {policies}, {cidrs} placeholders


def technique_url(technique_id: str) -> str:
    return ATTACK_URL.format(technique_id.replace(".", "/"))


VALID_CLOUD = ("T1078.004", "Valid Accounts: Cloud Accounts")
SPRAY = ("T1110.003", "Brute Force: Password Spraying")

GUIDANCE = {
    "CA-01": Guidance([SPRAY, VALID_CLOUD], """\
// Successful sign-ins that needed only a password
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication"
| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10), IPs = make_set(IPAddress, 10)
    by UserPrincipalName
| sort by SignIns desc"""),

    "CA-02": Guidance([("T1557", "Adversary-in-the-Middle"), ("T1539", "Steal Web Session Cookie")], """\
// Which MFA methods these admins actually use. Anything other than FIDO2, passkeys,
// or Windows Hello for Business can be relayed by a phishing proxy.
let admins = dynamic([{users}]);
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName in~ (admins) and ResultType == 0
| mv-expand Detail = todynamic(AuthenticationDetails)
| extend Method = tostring(Detail.authenticationMethod), Succeeded = tobool(Detail.succeeded)
| where Succeeded and Method != "Password"
| summarize SignIns = count() by UserPrincipalName, Method
| sort by UserPrincipalName asc, SignIns desc"""),

    "CA-03": Guidance([SPRAY, VALID_CLOUD], """\
// Legacy-protocol sign-in attempts (these can't do MFA)
SigninLogs
| where TimeGenerated > ago(30d)
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP",
    "Other clients", "Exchange Web Services", "MAPI Over HTTP", "AutoDiscover")
| summarize Attempts = count(), Successes = countif(ResultType == 0), IPs = make_set(IPAddress, 10)
    by UserPrincipalName, ClientAppUsed
| sort by Successes desc, Attempts desc"""),

    "CA-04": Guidance([VALID_CLOUD], """\
// Sign-ins by excluded admins: where from, and how many needed only a password
let users = dynamic([{users}]);
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName in~ (users)
| summarize SignIns = count(), Failures = countif(ResultType != 0),
    SingleFactor = countif(ResultType == 0 and AuthenticationRequirement == "singleFactorAuthentication"),
    Countries = make_set(tostring(LocationDetails.countryOrRegion)), IPs = make_set(IPAddress, 20)
    by UserPrincipalName"""),

    "CA-05": Guidance([VALID_CLOUD], """\
// Successful sign-ins where no Conditional Access policy applied at all
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0 and ConditionalAccessStatus == "notApplied"
| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10) by UserPrincipalName
| sort by SignIns desc"""),

    "CA-06": Guidance([], """\
// What these policies would have done if they were on
let policies = dynamic([{policies}]);
SigninLogs
| where TimeGenerated > ago(14d)
| mv-expand Policy = todynamic(ConditionalAccessPolicies)
| where tostring(Policy.displayName) in (policies)
| summarize SignIns = count() by PolicyName = tostring(Policy.displayName), Result = tostring(Policy.result)
| sort by PolicyName asc, SignIns desc"""),

    "CA-07": Guidance([VALID_CLOUD], """\
// Successful sign-ins Entra ID Protection rated medium or high risk
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0 and RiskLevelDuringSignIn in ("medium", "high")
| project TimeGenerated, UserPrincipalName, RiskLevelDuringSignIn, RiskEventTypes_V2, IPAddress,
    Country = tostring(LocationDetails.countryOrRegion), AppDisplayName
| sort by TimeGenerated desc"""),

    "CA-08": Guidance([VALID_CLOUD], """\
// Sign-ins from the over-broad "trusted" range
SigninLogs
| where TimeGenerated > ago(30d)
| where ipv4_is_in_any_range(IPAddress, dynamic([{cidrs}]))
| summarize SignIns = count(), Users = dcount(UserPrincipalName),
    Countries = make_set(tostring(LocationDetails.countryOrRegion)) by IPAddress
| sort by SignIns desc"""),

    "CA-09": Guidance([("T1528", "Steal Application Access Token"), ("T1566", "Phishing")], """\
// Device code sign-ins (a common phishing technique)
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationProtocol == "deviceCode"
| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10), IPs = make_set(IPAddress, 10),
    Countries = make_set(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName
| sort by SignIns desc"""),

    "CA-10": Guidance([], """\
// Every break-glass sign-in. Turn this into an alert rule: any result is worth a look.
let breakglass = dynamic([{users}]);
SigninLogs
| where TimeGenerated > ago(90d)
| where UserPrincipalName in~ (breakglass)
| project TimeGenerated, UserPrincipalName, ResultType, IPAddress,
    Country = tostring(LocationDetails.countryOrRegion), AppDisplayName
| sort by TimeGenerated desc"""),

    "CA-11": Guidance([("T1199", "Trusted Relationship")], """\
// Guest sign-ins, and how many used only a password
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0 and UserType == "Guest"
| summarize SignIns = count(),
    SingleFactor = countif(AuthenticationRequirement == "singleFactorAuthentication")
    by UserPrincipalName, HomeTenantId
| sort by SingleFactor desc"""),

    "CA-12": Guidance([("T1550.001", "Use Alternate Authentication Material: Application Access Token"),
                       ("T1539", "Steal Web Session Cookie")], """\
// How long admins go between interactive sign-ins (long gaps = long-lived sessions)
let admins = dynamic([{users}]);
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName in~ (admins) and ResultType == 0
| summarize Interactive = countif(IsInteractive == true), NonInteractive = countif(IsInteractive == false),
    LastInteractive = maxif(TimeGenerated, IsInteractive == true) by UserPrincipalName
| sort by LastInteractive asc"""),
}


def _quoted(values) -> str:
    return ", ".join('"' + v.replace('"', '\\"') + '"' for v in sorted(set(values)))


def _upns(user_ids, snapshot: Snapshot) -> list[str]:
    objects = snapshot.directory.objects
    return [objects[u].get("userPrincipalName") for u in user_ids if objects.get(u, {}).get("userPrincipalName")]


def _ids_by_name(names, snapshot: Snapshot) -> list[str]:
    d = snapshot.directory
    return [oid for oid in d.objects if d.name(oid) in set(names)]


def kql_for(finding: Finding, snapshot: Snapshot) -> str:
    """The check's hunting query, filled in with this finding's users, policies, or ranges."""
    guidance = GUIDANCE.get(finding.check_id)
    if not guidance or not guidance.kql:
        return ""

    users = []
    if finding.check_id in ("CA-02", "CA-04"):
        users = _upns(_ids_by_name(finding.affected, snapshot), snapshot)
    elif finding.check_id == "CA-10":
        users = _upns(resolve(snapshot).ids, snapshot)
    elif finding.check_id == "CA-12":
        users = _upns(privileged_users(snapshot.directory), snapshot)

    cidrs = [r.get("cidrAddress", "")
             for loc in snapshot.named_locations if loc.get("displayName") in finding.affected
             for r in loc.get("ipRanges") or []]
    policies = [p.name for p in snapshot.policies if p.name in finding.affected]

    # Plain replace (not str.format), because KQL itself uses braces.
    return (guidance.kql
            .replace("{users}", _quoted(users) or '"user@contoso.com"')
            .replace("{policies}", _quoted(policies) or '"Policy name"')
            .replace("{cidrs}", _quoted(cidrs) or '"203.0.113.0/24"'))
