import json
from datetime import datetime, timezone

import pytest

from ca_gap_analyzer import auth, cli, graph
from ca_gap_analyzer.collect import (
    NAMED_LOCATIONS_PATH,
    POLICIES_PATH,
    ROLE_ASSIGNMENTS_PATH,
    ROLE_DEFINITIONS_PATH,
    ROLE_ELIGIBILITIES_PATH,
    collect_snapshot,
    default_output_path,
    save_snapshot,
)
from ca_gap_analyzer.graph import GraphError
from ca_gap_analyzer.snapshot import load_snapshot, snapshot_from_dict
from conftest import make_location, make_policy

NOW = datetime(2026, 10, 17, 18, 30, 0, tzinfo=timezone.utc)
TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

BREAKGLASS = "u-breakglass"
CAROL = "u-carol"
SVC = "u-svc"
EXCLUSION_GROUP = "g-exclusions"
PRA_ROLE = "e8611ab8-c189-46e8-94e1-60213ab1f814"
SHAREPOINT = "00000003-0000-0ff1-ce00-000000000000"


def user(object_id, upn, display):
    return {"@odata.type": "#microsoft.graph.user", "id": object_id, "displayName": display,
            "userPrincipalName": upn, "mobilePhone": "555-0100"}


def lab_policy():
    p = make_policy(name="CA001")
    p["conditions"]["users"]["excludeUsers"] = [BREAKGLASS]
    p["conditions"]["users"]["excludeGroups"] = [EXCLUSION_GROUP]
    return p


class FakeGraphClient:
    """Answers the collector's calls from canned data. Paths not listed raise, like a real 404."""

    def __init__(self, fail=None):
        self.fail = fail or {}  # path -> GraphError to raise
        self.objects = {
            BREAKGLASS: user(BREAKGLASS, "breakglass01@lab.onmicrosoft.com", "Break Glass"),
            CAROL: user(CAROL, "carol@lab.onmicrosoft.com", "Carol Chen"),
            EXCLUSION_GROUP: {"@odata.type": "#microsoft.graph.group", "id": EXCLUSION_GROUP,
                              "displayName": "CA-Exclusions-Temp"},
        }
        self.data = {
            POLICIES_PATH: [lab_policy(), make_policy(name="CA102", apps=[SHAREPOINT])],
            NAMED_LOCATIONS_PATH: [make_location(name="Office-HQ", cidrs=["20.0.0.0/8"])],
            ROLE_DEFINITIONS_PATH: [{"id": PRA_ROLE, "templateId": PRA_ROLE,
                                     "displayName": "Privileged Role Administrator"}],
            ROLE_ASSIGNMENTS_PATH: [{"id": "ra1", "principalId": CAROL, "roleDefinitionId": PRA_ROLE,
                                     "directoryScopeId": "/"}],
            ROLE_ELIGIBILITIES_PATH: [],
        }
        self.calls = []

    def get_all(self, path):
        self.calls.append(path)
        if path in self.fail:
            raise self.fail[path]
        if path.startswith(f"/groups/{EXCLUSION_GROUP}/transitiveMembers"):
            return [user(CAROL, "carol@lab.onmicrosoft.com", "Carol Chen"),
                    user(SVC, "svc-legacy-scanner@lab.onmicrosoft.com", "Legacy Scanner")]
        if path.startswith("/servicePrincipals?$filter=appId eq"):
            return [{"id": "sp-1", "appId": SHAREPOINT, "displayName": "Office 365 SharePoint Online"}]
        if path.startswith("/roleManagement/directory/roleAssignments?$filter="):
            return self.data[ROLE_ASSIGNMENTS_PATH]
        return self.data[path]

    def get_by_ids(self, ids, types):
        return [self.objects[i] for i in ids if i in self.objects]


def collect(client=None):
    return collect_snapshot(client or FakeGraphClient(), "ca-auditor@lab.onmicrosoft.com", TENANT, now=NOW)


def test_snapshot_shape_and_metadata():
    snap = collect()
    assert snap["metadata"]["tenant"] == "lab.onmicrosoft.com"
    assert snap["metadata"]["collectedAt"] == "2026-10-17T18:30:00Z"
    assert snap["metadata"]["collectedBy"] == "ca-auditor@lab.onmicrosoft.com"
    assert [p["displayName"] for p in snap["conditionalAccessPolicies"]] == ["CA001", "CA102"]
    assert len(snap["namedLocations"]) == 1
    assert snap["metadata"]["warnings"] == []


def test_resolves_names_and_expands_groups():
    snapshot = snapshot_from_dict(collect())
    d = snapshot.directory
    assert d.name(BREAKGLASS) == "breakglass01"
    assert d.name(EXCLUSION_GROUP) == "CA-Exclusions-Temp"
    assert [m["id"] for m in d.members(EXCLUSION_GROUP)] == [CAROL, SVC]
    assert d.name(SVC) == "svc-legacy-scanner"  # learned from the group expansion
    assert d.app_name(SHAREPOINT) == "Office 365 SharePoint Online"
    assert [h.principal_id for h in d.role_holders(PRA_ROLE)] == [CAROL]


def test_keeps_only_needed_fields():
    objects = collect()["directoryObjects"]
    assert all("mobilePhone" not in o for o in objects)


def test_missing_pim_access_becomes_a_warning():
    client = FakeGraphClient(fail={ROLE_ELIGIBILITIES_PATH: GraphError("forbidden", status=403)})
    snap = collect(client)
    assert snap["roleEligibilities"] == []
    assert "PIM" in snap["metadata"]["warnings"][0]


def test_falls_back_to_per_role_queries_when_unfiltered_list_is_rejected():
    client = FakeGraphClient(fail={ROLE_ASSIGNMENTS_PATH: GraphError("needs filter", status=400)})
    snap = collect(client)
    assert [a["principalId"] for a in snap["roleAssignments"]] == [CAROL]
    assert any("$filter=roleDefinitionId eq" in c for c in client.calls)


def test_other_role_errors_are_not_swallowed():
    client = FakeGraphClient(fail={ROLE_ASSIGNMENTS_PATH: GraphError("forbidden", status=403)})
    with pytest.raises(GraphError):
        collect(client)


def test_warns_about_deleted_objects_still_in_policies():
    client = FakeGraphClient()
    del client.objects[BREAKGLASS]
    assert "no longer exist" in collect(client)["metadata"]["warnings"][0]


def test_saved_snapshot_round_trips_through_loader(tmp_path):
    path = tmp_path / "nested" / "snap.json"
    save_snapshot(collect(), path)
    loaded = load_snapshot(path)
    assert loaded.tenant == "lab.onmicrosoft.com"
    assert loaded.policies[0].name == "CA001"
    assert loaded.directory.name(CAROL) == "carol"


def test_default_output_path_is_in_exports():
    path = default_output_path(NOW)
    assert path.parts[0] == "exports"
    assert path.name == "snapshot-20261017-183000.json"


def test_cli_collect_end_to_end(tmp_path, monkeypatch, capsys):
    """Run `collect --analyze` with sign-in and Graph swapped for fakes."""
    env = tmp_path / ".env"
    env.write_text(f"CA_TENANT_ID={TENANT}\nCA_CLIENT_ID={CLIENT}\n", encoding="utf-8")
    monkeypatch.setattr(auth, "sign_in", lambda tenant_id, client_id: auth.SignIn(
        access_token="fake", username="ca-auditor@lab.onmicrosoft.com", tenant_id=tenant_id))
    monkeypatch.setattr(graph, "GraphClient", lambda token: FakeGraphClient())

    output = tmp_path / "snap.json"
    code = cli.main(["collect", "--env-file", str(env), "--output", str(output), "--analyze"])

    assert code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["metadata"]["collectedBy"].startswith("ca-auditor")
    out = capsys.readouterr().out
    assert "Saved 2 policies and 1 named locations" in out
    assert "1 active and 0 eligible role assignments" in out
    assert "FAIL  CA-08" in out


def test_cli_collect_reports_config_error(tmp_path, capsys):
    code = cli.main(["collect", "--env-file", str(tmp_path / "missing.env")])
    assert code == 1
    assert ".env.example" in capsys.readouterr().err
