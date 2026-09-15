from __future__ import annotations

from pathlib import Path

import pytest

from archwright_mcp.config import load_config, parse_config
from archwright_mcp.errors import ValidationError


def valid_config() -> dict[str, object]:
    return {
        "target": {
            "name": "sager-arch",
            "host": "127.0.0.1",
            "port": 22022,
            "user": "arch-bootstrap",
            "controller_key": "/etc/archwright/keys/controller_ed25519",
            "known_hosts": "/etc/archwright/known_hosts",
            "expected_target_serial": "25044DB50A3B",
            "protected_serials": ["25044DB4D635"],
        },
        "policy": {
            "require_identity_for_mutation": True,
            "require_protected_disks_read_only": True,
            "receipt_dir": "/var/lib/archwright/receipts",
        },
    }


def test_parse_valid_sager_config() -> None:
    config = parse_config(valid_config())
    assert config.target.expected_target_serial == "25044DB50A3B"
    assert config.target.protected_serials == ("25044DB4D635",)
    assert config.target.endpoint.host == "127.0.0.1"


@pytest.mark.parametrize("host", ["192.168.1.4", "arch-laptop", "0.0.0.0"])
def test_target_endpoint_must_be_literal_loopback(host: str) -> None:
    data = valid_config()
    assert isinstance(data["target"], dict)
    data["target"]["host"] = host
    with pytest.raises(ValidationError, match="loopback"):
        parse_config(data)


def test_expected_target_cannot_be_protected() -> None:
    data = valid_config()
    assert isinstance(data["target"], dict)
    data["target"]["protected_serials"] = ["25044DB50A3B"]
    with pytest.raises(ValidationError, match="cannot also be protected"):
        parse_config(data)


@pytest.mark.parametrize(
    "key",
    ["require_identity_for_mutation", "require_protected_disks_read_only"],
)
def test_required_safety_policy_cannot_be_disabled(key: str) -> None:
    data = valid_config()
    assert isinstance(data["policy"], dict)
    data["policy"][key] = False
    with pytest.raises(ValidationError, match="cannot be disabled"):
        parse_config(data)


def test_load_config_requires_absolute_path() -> None:
    with pytest.raises(ValidationError, match="absolute"):
        load_config(Path("archwright.toml"))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("output_limit_bytes", 65_537),
        ("connect_timeout_seconds", 61),
        ("max_script_bytes", 1_048_577),
        ("max_retained_output_bytes", 8_388_609),
        ("max_runtime_seconds", 21_601),
        ("max_wait_seconds", 31),
    ],
)
def test_policy_limits_cannot_exceed_hard_ceiling(key: str, value: int) -> None:
    data = valid_config()
    assert isinstance(data["policy"], dict)
    data["policy"][key] = value
    with pytest.raises(ValidationError, match="ceiling"):
        parse_config(data)


def test_target_runtime_path_must_be_absolute() -> None:
    data = valid_config()
    assert isinstance(data["policy"], dict)
    data["policy"]["target_runtime_path"] = "relative/runtime.pyz"
    with pytest.raises(ValidationError, match="normalized absolute"):
        parse_config(data)
