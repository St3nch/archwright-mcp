from __future__ import annotations

from archwright_mcp.config import load_settings


def test_load_settings(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
[target]
name = "test"
host = "127.0.0.1"
port = 2222
user = "bootstrap"
identity_file = "/tmp/key"
known_hosts_file = "/tmp/known"

[policy]
expected_target_serial = "ARCH"
protected_serials = ["WIN"]

[runtime]
state_dir = "{state}"
staging_dir = "{stage}"
""".format(state=tmp_path / "state", stage=tmp_path / "stage")
    )
    settings = load_settings(path)
    assert settings.target_name == "test"
    assert settings.endpoint.port == 2222
    assert settings.expected_target_serial == "ARCH"
    assert settings.protected_serials == ("WIN",)
