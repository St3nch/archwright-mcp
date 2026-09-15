"""TOML configuration loading with fail-closed validation."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from archwright_mcp.errors import ValidationError
from archwright_mcp.models import TargetEndpoint


@dataclass(frozen=True, slots=True)
class TargetConfig:
    name: str
    endpoint: TargetEndpoint
    expected_target_serial: str
    protected_serials: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    require_identity_for_mutation: bool
    require_protected_disks_read_only: bool
    receipt_dir: Path
    output_limit_bytes: int = 65_536
    connect_timeout_seconds: int = 10
    max_script_bytes: int = 1_048_576
    max_transfer_bytes: int = 67_108_864
    max_retained_output_bytes: int = 8_388_608
    max_runtime_seconds: int = 21_600
    max_wait_seconds: int = 30
    target_runtime_path: str = "/usr/local/libexec/archwright-target.pyz"


@dataclass(frozen=True, slots=True)
class ArchwrightConfig:
    target: TargetConfig
    policy: PolicyConfig


def _table(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise ValidationError(f"missing or invalid [{key}] table")
    return value


def _string(table: dict[str, Any], key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("missing or invalid string configuration", details={"key": key})
    return value


def _boolean(table: dict[str, Any], key: str, *, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ValidationError("invalid boolean configuration", details={"key": key})
    return value


def _integer(table: dict[str, Any], key: str, *, default: int, minimum: int) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValidationError("invalid integer configuration", details={"key": key})
    return value


def _bounded_integer(
    table: dict[str, Any], key: str, *, default: int, minimum: int, maximum: int
) -> int:
    value = _integer(table, key, default=default, minimum=minimum)
    if value > maximum:
        raise ValidationError(
            "integer configuration exceeds the hard safety ceiling",
            details={"key": key, "maximum": maximum},
        )
    return value


def _string_tuple(table: dict[str, Any], key: str) -> tuple[str, ...]:
    value = table.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ValidationError("missing or invalid string-array configuration", details={"key": key})
    normalized = tuple(item.strip() for item in value)
    if any(not item for item in normalized) or len(set(normalized)) != len(normalized):
        raise ValidationError(
            "string-array entries must be nonempty and unique", details={"key": key}
        )
    return normalized


def _require_loopback(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValidationError(
            "target host must be a literal loopback address",
            details={"host": host},
        ) from exc
    if not address.is_loopback:
        raise ValidationError(
            "target host must be loopback; public or LAN target listeners are forbidden",
            details={"host": host},
        )


def parse_config(data: dict[str, Any]) -> ArchwrightConfig:
    """Validate parsed TOML and produce immutable runtime configuration."""

    target = _table(data, "target")
    policy = _table(data, "policy")
    host = _string(target, "host")
    _require_loopback(host)
    port = _integer(target, "port", default=22022, minimum=1)
    if port > 65535:
        raise ValidationError("target port must be between 1 and 65535")
    endpoint = TargetEndpoint(
        host=host,
        port=port,
        user=_string(target, "user"),
        controller_key=Path(_string(target, "controller_key")),
        known_hosts=Path(_string(target, "known_hosts")),
    )
    expected_target_serial = _string(target, "expected_target_serial")
    protected_serials = _string_tuple(target, "protected_serials")
    if expected_target_serial in protected_serials:
        raise ValidationError("target serial cannot also be protected")

    require_identity = _boolean(policy, "require_identity_for_mutation", default=True)
    require_read_only = _boolean(policy, "require_protected_disks_read_only", default=True)
    if not require_identity:
        raise ValidationError("identity verification cannot be disabled in Archwright v1")
    if not require_read_only:
        raise ValidationError(
            "protected-disk read-only enforcement cannot be disabled in Archwright v1"
        )

    receipt_dir = Path(_string(policy, "receipt_dir"))
    if not receipt_dir.is_absolute():
        raise ValidationError("receipt_dir must be an absolute path")
    return ArchwrightConfig(
        target=TargetConfig(
            name=_string(target, "name"),
            endpoint=endpoint,
            expected_target_serial=expected_target_serial,
            protected_serials=protected_serials,
        ),
        policy=PolicyConfig(
            require_identity_for_mutation=require_identity,
            require_protected_disks_read_only=require_read_only,
            receipt_dir=receipt_dir,
            output_limit_bytes=_bounded_integer(
                policy,
                "output_limit_bytes",
                default=65_536,
                minimum=1_024,
                maximum=65_536,
            ),
            connect_timeout_seconds=_bounded_integer(
                policy,
                "connect_timeout_seconds",
                default=10,
                minimum=1,
                maximum=60,
            ),
            max_script_bytes=_bounded_integer(
                policy,
                "max_script_bytes",
                default=1_048_576,
                minimum=1,
                maximum=1_048_576,
            ),
            max_transfer_bytes=_bounded_integer(
                policy,
                "max_transfer_bytes",
                default=67_108_864,
                minimum=1,
                maximum=1_073_741_824,
            ),
            max_retained_output_bytes=_bounded_integer(
                policy,
                "max_retained_output_bytes",
                default=8_388_608,
                minimum=1_024,
                maximum=8_388_608,
            ),
            max_runtime_seconds=_bounded_integer(
                policy,
                "max_runtime_seconds",
                default=21_600,
                minimum=1,
                maximum=21_600,
            ),
            max_wait_seconds=_bounded_integer(
                policy, "max_wait_seconds", default=30, minimum=1, maximum=30
            ),
            target_runtime_path=_target_runtime_path(policy),
        ),
    )


def _target_runtime_path(policy: dict[str, Any]) -> str:
    value = (
        _string(policy, "target_runtime_path")
        if "target_runtime_path" in policy
        else "/usr/local/libexec/archwright-target.pyz"
    )
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValidationError("target_runtime_path must be a normalized absolute path")
    return value


def load_config(path: Path) -> ArchwrightConfig:
    """Load an Archwright TOML file without following a directory default."""

    if not path.is_absolute():
        raise ValidationError("configuration path must be absolute")
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError("unable to load configuration", details={"path": str(path)}) from exc
    return parse_config(data)
