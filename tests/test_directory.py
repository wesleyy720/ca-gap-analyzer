from ca_gap_analyzer.directory import Directory

GA = "62e90394-69f5-4237-9190-012177145e10"

DIRECTORY = Directory(
    objects=[
        {"@odata.type": "#microsoft.graph.user", "id": "u1", "displayName": "Carol Chen",
         "userPrincipalName": "carol@lab.onmicrosoft.com"},
        {"@odata.type": "#microsoft.graph.group", "id": "g1", "displayName": "Admins"},
        {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp1", "appId": "app-1",
         "displayName": "Payroll App"},
        {"@odata.type": "#microsoft.graph.user", "id": "u2", "displayName": None},
    ],
    role_definitions=[{"id": GA, "templateId": GA, "displayName": "Global Administrator"}],
    role_assignments=[{"principalId": "u1", "roleDefinitionId": GA}],
    role_eligibilities=[{"principalId": "g1", "roleDefinitionId": GA}],
    group_members={"g1": ["u1", "u-unknown"]},
)


def test_user_names_use_short_upn():
    assert DIRECTORY.name("u1") == "carol"


def test_group_and_special_names():
    assert DIRECTORY.name("g1") == "Admins"
    assert DIRECTORY.name("All") == "All users"
    assert DIRECTORY.name("GuestsOrExternalUsers") == "Guests and external users"


def test_unknown_ids_fall_back_to_the_id():
    assert DIRECTORY.name("nope") == "nope"
    assert DIRECTORY.name("u2") == "u2"  # object exists but has no name


def test_kinds():
    assert DIRECTORY.kind("u1") == "user"
    assert DIRECTORY.kind("g1") == "group"
    assert DIRECTORY.kind("sp1") == "app"
    assert DIRECTORY.kind("nope") is None


def test_app_and_role_names():
    assert DIRECTORY.app_name("app-1") == "Payroll App"
    assert DIRECTORY.app_name("Office365") == "Office 365"
    assert DIRECTORY.role_name(GA) == "Global Administrator"


def test_members_include_unknown_ids():
    assert [m["id"] for m in DIRECTORY.members("g1")] == ["u1", "u-unknown"]
    assert DIRECTORY.members("not-a-group") == []


def test_role_holders_active_and_eligible():
    holders = {(h.principal_id, h.kind) for h in DIRECTORY.role_holders(GA)}
    assert holders == {("u1", "active"), ("g1", "eligible")}


def test_empty_directory():
    assert Directory().is_empty
    assert not DIRECTORY.is_empty
