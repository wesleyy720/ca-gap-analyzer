"""Tests for the identity checks: CA-02, CA-04, CA-05, CA-10."""

from ca_gap_analyzer.checks import (
    ca02_admin_phishing_resistant as ca02,
    ca04_privileged_exclusions as ca04,
    ca05_broad_exclusions as ca05,
    ca10_break_glass as ca10,
)
from ca_gap_analyzer.findings import Severity
from conftest import GA, HELPDESK, PHISHING_RESISTANT, make_policy, make_snapshot


def admin_policy(roles=(GA,), state="enabled", exclude=()):
    p = make_policy(name="Admins phishing-resistant", state=state, users=[], grant=[])
    p["conditions"]["users"]["includeRoles"] = list(roles)
    p["conditions"]["users"]["excludeUsers"] = list(exclude)
    p["grantControls"]["authenticationStrength"] = PHISHING_RESISTANT
    return p


def mfa_policy(exclude_users=(), exclude_groups=(), state="enabled"):
    p = make_policy(name="MFA all users", state=state)
    p["conditions"]["users"]["excludeUsers"] = list(exclude_users)
    p["conditions"]["users"]["excludeGroups"] = list(exclude_groups)
    return p


# --- CA-02 ---------------------------------------------------------------------

def test_ca02_passes_when_all_admin_roles_covered():
    snap = make_snapshot([admin_policy(roles=[GA, HELPDESK])], users=["alice", "bob"],
                         roles={"alice": GA, "bob": HELPDESK})
    assert ca02.run(snap) == []


def test_ca02_flags_admins_in_roles_the_policy_misses():
    snap = make_snapshot([admin_policy(roles=[GA])], users=["alice", "bob"],
                         roles={"alice": GA, "bob": HELPDESK})
    findings = ca02.run(snap)
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].affected == ["bob"]


def test_ca02_report_only_policy_does_not_count():
    snap = make_snapshot([admin_policy(state="enabledForReportingButNotEnforced")],
                         users=["alice"], roles={"alice": GA})
    findings = ca02.run(snap)
    assert "Report-only" in findings[0].detail


def test_ca02_plain_mfa_is_not_enough():
    snap = make_snapshot([mfa_policy()], users=["alice"], roles={"alice": GA})
    assert ca02.run(snap)[0].affected == ["alice"]


def test_ca02_eligible_admins_count():
    snap = make_snapshot([], users=["bob"], eligible={"bob": GA})
    assert "PIM eligible" in ca02.run(snap)[0].detail


def test_ca02_skips_break_glass():
    snap = make_snapshot([admin_policy(exclude=["bg"])], users=["alice", "bg"],
                         roles={"alice": GA, "bg": GA}, break_glass=["bg"])
    assert ca02.run(snap) == []


# --- CA-04 ---------------------------------------------------------------------

def test_ca04_flags_admin_excluded_via_group():
    snap = make_snapshot([mfa_policy(exclude_groups=["g-temp"])], users=["carol"],
                         groups={"g-temp": ["carol"]}, roles={"carol": HELPDESK})
    findings = ca04.run(snap)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "via group g-temp" in findings[0].detail


def test_ca04_ignores_non_admins_and_break_glass():
    snap = make_snapshot([mfa_policy(exclude_users=["alice", "bg"])], users=["alice", "bg"],
                         roles={"bg": GA}, break_glass=["bg"])
    assert ca04.run(snap) == []


def test_ca04_ignores_report_only_policies():
    snap = make_snapshot([mfa_policy(exclude_users=["boss"], state="enabledForReportingButNotEnforced")],
                         users=["boss"], roles={"boss": GA})
    assert ca04.run(snap) == []


def test_ca04_catches_admin_when_break_glass_is_designated():
    # Your lab: both accounts excluded everywhere; only the designated one is legitimate.
    snap = make_snapshot([mfa_policy(exclude_users=["breakglass", "wesley"])],
                         users=["breakglass", "wesley"], roles={"breakglass": GA, "wesley": GA},
                         break_glass=["breakglass"])
    assert [f.affected for f in ca04.run(snap)] == [["wesley"]]


def test_ca04_mentions_guess_when_not_designated():
    snap = make_snapshot([mfa_policy(exclude_users=["breakglass", "wesley"]),
                          mfa_policy(exclude_users=["breakglass"])],
                         users=["breakglass", "wesley"], roles={"wesley": GA})
    findings = ca04.run(snap)
    assert findings[0].affected == ["wesley"]
    assert "guessed: breakglass" in findings[0].detail


# --- CA-05 ---------------------------------------------------------------------

STAFF = [f"u{i}" for i in range(6)]


def test_ca05_flags_large_share():
    snap = make_snapshot([mfa_policy(exclude_groups=["g-staff"])], users=STAFF,
                         groups={"g-staff": STAFF}, user_count=10)
    findings = ca05.run(snap)
    assert "6 of 10 users (60%)" in findings[0].detail
    assert "g-staff (6 members)" in findings[0].detail


def test_ca05_small_share_passes():
    snap = make_snapshot([mfa_policy(exclude_groups=["g-staff"])], users=STAFF,
                         groups={"g-staff": STAFF}, user_count=1000)
    assert ca05.run(snap) == []


def test_ca05_a_few_exclusions_pass_even_in_tiny_tenants():
    snap = make_snapshot([mfa_policy(exclude_users=["a", "b", "c"])], users=["a", "b", "c"], user_count=4)
    assert ca05.run(snap) == []


# --- CA-10 ---------------------------------------------------------------------

def test_ca10_two_break_glass_excluded_everywhere_passes():
    snap = make_snapshot([mfa_policy(exclude_users=["bg1", "bg2"])], users=["bg1", "bg2"],
                         break_glass=["bg1", "bg2"])
    assert ca10.run(snap) == []


def test_ca10_flags_policy_missing_the_exclusion():
    snap = make_snapshot([mfa_policy(exclude_users=["bg1", "bg2"]), admin_policy(state="enabledForReportingButNotEnforced")],
                         users=["bg1", "bg2"], break_glass=["bg1", "bg2"])
    findings = ca10.run(snap)
    assert len(findings) == 2  # one per break-glass account
    assert all("Admins phishing-resistant" in f.detail for f in findings)


def test_ca10_flags_single_account_and_unknown_entries():
    snap = make_snapshot([mfa_policy(exclude_users=["bg1"])], users=["bg1"], break_glass=["bg1", "typo@x.com"])
    titles = [f.title for f in ca10.run(snap)]
    assert "Designated break-glass account not found: typo@x.com" in titles
    assert "Only 1 break-glass account" in titles


def test_ca10_no_break_glass_at_all():
    snap = make_snapshot([mfa_policy()], users=["alice"])
    assert ca10.run(snap)[0].title == "No break-glass account found"
