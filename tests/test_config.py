import pytest

from ca_gap_analyzer.config import ConfigError, load_settings

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def write_env(tmp_path, text):
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return path


def test_reads_env_file_with_comments_and_quotes(tmp_path):
    env = write_env(tmp_path, f'# comment\n\nCA_TENANT_ID={TENANT}\nCA_CLIENT_ID="{CLIENT}"\n')
    settings = load_settings(env, environ={})
    assert settings.tenant_id == TENANT
    assert settings.client_id == CLIENT


def test_environment_variables_override_file(tmp_path):
    other = "99999999-8888-7777-6666-555555555555"
    env = write_env(tmp_path, f"CA_TENANT_ID={TENANT}\nCA_CLIENT_ID={CLIENT}\n")
    assert load_settings(env, environ={"CA_TENANT_ID": other}).tenant_id == other


def test_missing_file_points_to_example(tmp_path):
    with pytest.raises(ConfigError, match=r"\.env\.example"):
        load_settings(tmp_path / ".env", environ={})


def test_placeholder_is_rejected(tmp_path):
    env = write_env(tmp_path, f"CA_TENANT_ID=00000000-0000-0000-0000-000000000000\nCA_CLIENT_ID={CLIENT}\n")
    with pytest.raises(ConfigError, match="placeholder"):
        load_settings(env, environ={})


def test_non_guid_is_rejected(tmp_path):
    env = write_env(tmp_path, f"CA_TENANT_ID=contoso.onmicrosoft.com\nCA_CLIENT_ID={CLIENT}\n")
    with pytest.raises(ConfigError, match="doesn't look like an ID"):
        load_settings(env, environ={})


def test_handles_notepad_byte_order_mark(tmp_path):
    path = tmp_path / ".env"
    path.write_text(f"CA_TENANT_ID={TENANT}\nCA_CLIENT_ID={CLIENT}\n", encoding="utf-8-sig")
    assert load_settings(path, environ={}).tenant_id == TENANT
