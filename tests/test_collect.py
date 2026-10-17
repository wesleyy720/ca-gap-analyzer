import json
from datetime import datetime, timezone

from ca_gap_analyzer import auth, cli, graph
from ca_gap_analyzer.collect import (
    NAMED_LOCATIONS_PATH,
    POLICIES_PATH,
    collect_snapshot,
    default_output_path,
    save_snapshot,
)
from ca_gap_analyzer.snapshot import load_snapshot
from conftest import make_location, make_policy

NOW = datetime(2026, 10, 17, 18, 30, 0, tzinfo=timezone.utc)
TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class FakeGraphClient:
    def __init__(self, data):
        self.data = data

    def get_all(self, path):
        return self.data[path]


FAKE_DATA = {
    POLICIES_PATH: [make_policy(name="CA001")],
    NAMED_LOCATIONS_PATH: [make_location(name="Office-HQ", cidrs=["20.0.0.0/8"])],
}


def test_snapshot_shape_and_metadata():
    snap = collect_snapshot(FakeGraphClient(FAKE_DATA), "ca-auditor@lab.onmicrosoft.com", TENANT, now=NOW)
    assert snap["metadata"]["tenant"] == "lab.onmicrosoft.com"
    assert snap["metadata"]["collectedAt"] == "2026-10-17T18:30:00Z"
    assert snap["metadata"]["collectedBy"] == "ca-auditor@lab.onmicrosoft.com"
    assert [p["displayName"] for p in snap["conditionalAccessPolicies"]] == ["CA001"]
    assert len(snap["namedLocations"]) == 1


def test_saved_snapshot_round_trips_through_loader(tmp_path):
    snap = collect_snapshot(FakeGraphClient(FAKE_DATA), "ca-auditor@lab.onmicrosoft.com", TENANT, now=NOW)
    path = tmp_path / "nested" / "snap.json"
    save_snapshot(snap, path)
    loaded = load_snapshot(path)
    assert loaded.tenant == "lab.onmicrosoft.com"
    assert loaded.policies[0].name == "CA001"


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
    monkeypatch.setattr(graph, "GraphClient", lambda token: FakeGraphClient(FAKE_DATA))

    output = tmp_path / "snap.json"
    code = cli.main(["collect", "--env-file", str(env), "--output", str(output), "--analyze"])

    assert code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["metadata"]["collectedBy"].startswith("ca-auditor")
    out = capsys.readouterr().out
    assert "Saved 1 policies and 1 named locations" in out
    assert "FAIL  CA-08" in out


def test_cli_collect_reports_config_error(tmp_path, capsys):
    code = cli.main(["collect", "--env-file", str(tmp_path / "missing.env")])
    assert code == 1
    assert ".env.example" in capsys.readouterr().err
