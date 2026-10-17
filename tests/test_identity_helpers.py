"""Tests for privileged.py, coverage.py and breakglass.py."""

from ca_gap_analyzer import breakglass
from ca_gap_analyzer.coverage import covers, excluded_users
from ca_gap_analyzer.privileged import privileged_users
from conftest import GA, GLOBAL_READER, HELPDESK, make_policy, make_snapshot


def test_privileged_users_direct_group_and_eligible():
    snap = make_snapshot(
        users=["alice", "bob", "carol", "dan"],
        groups={"g-admins": ["carol"]},
        roles={"alice": GA, "g-admins": HELPDESK, "dan": GLOBAL_READER},
        eligible={"bob": GA},
    )
    admins = privileged_users(snap.directory)
    assert set(admins) == {"alice", "bob", "carol"}  # dan's Global Reader isn't privileged
    assert admins["bob"][0].label() == "Global Administrator (PIM eligible)"
    assert admins["carol"][0].label() == "Helpdesk Administrator (via group g-admins)"


def test_excluded_users_reports_how():
    policy = make_policy()
    policy["conditions"]["users"]["excludeUsers"] = ["alice"]
    policy["conditions"]["users"]["excludeGroups"] = ["g-x"]
    policy["conditions"]["users"]["excludeRoles"] = [HELPDESK]
    snap = make_snapshot([policy], users=["alice", "bob", "carol"],
                         groups={"g-x": ["alice", "bob"]}, roles={"carol": HELPDESK})
    reasons = excluded_users(snap.policies[0], snap.directory)
    assert reasons == {
        "alice": ["directly", "via group g-x"],
        "bob": ["via group g-x"],
        "carol": ["via role Helpdesk Administrator"],
    }


def test_covers_by_role_and_group():
    by_role = make_policy(users=[])
    by_role["conditions"]["users"]["includeRoles"] = [GA]
    by_group = make_policy(users=[])
    by_group["conditions"]["users"]["includeGroups"] = ["g-staff"]
    snap = make_snapshot([by_role, by_group], users=["alice", "bob"],
                         groups={"g-staff": ["bob"]}, roles={"alice": GA})
    role_policy, group_policy = snap.policies
    assert covers(role_policy, "alice", snap.directory)
    assert not covers(role_policy, "bob", snap.directory)
    assert covers(group_policy, "bob", snap.directory)
    assert not covers(group_policy, "alice", snap.directory)


def test_break_glass_designated_by_upn_or_id():
    snap = make_snapshot(users=["bg1", "bg2"], break_glass=["BG1@test.onmicrosoft.com", "bg2", "ghost@x.com"])
    result = breakglass.resolve(snap)
    assert result.designated
    assert result.ids == {"bg1", "bg2"}
    assert result.unresolved == ["ghost@x.com"]


def test_break_glass_guess_prefers_break_glass_names():
    policy = make_policy()
    policy["conditions"]["users"]["excludeUsers"] = ["emergency-admin", "wesley"]
    snap = make_snapshot([policy], users=["emergency-admin", "wesley"])
    result = breakglass.resolve(snap)
    assert not result.designated
    assert result.ids == {"emergency-admin"}
    assert "guessed" in result.note(snap)


def test_break_glass_guess_falls_back_to_everyone_excluded_everywhere():
    policy = make_policy()
    policy["conditions"]["users"]["excludeUsers"] = ["admin1"]
    snap = make_snapshot([policy], users=["admin1"])
    assert breakglass.resolve(snap).ids == {"admin1"}


def test_break_glass_guess_ignores_group_exclusions():
    policy = make_policy()
    policy["conditions"]["users"]["excludeGroups"] = ["g-temp"]
    snap = make_snapshot([policy], users=["carol"], groups={"g-temp": ["carol"]})
    assert breakglass.resolve(snap).ids == set()
