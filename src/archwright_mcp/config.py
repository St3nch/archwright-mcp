from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True, frozen=True)
class TargetEndpoint:
    host: str = "127.0.0.1"
    port: int = 2222
    user: str = "arch-bootstrap"
    identity_file: Path = Path("/etc/archwright/controller_ed25519")
    known_hosts_file: Path = Path("/etc/archwright/known_hosts")


@dataclass(slots=True)
class Settings:
    endpoint: TargetEndpoint = field(default_factory=TargetEndpoint)
    state_dir: Path = Path("/var/lib/archwright")
    staging_dir: Path = Path("/var/lib/archwright/staging")
    target_staging_dir: str = "/var/tmp/archwright"
    target_name: str = "sager-arch"
    connect_timeout: int = 10
    command_timeout: int = 120
    output_limit_bytes: int = 262144
    protected_serials: tuple[str, ...] = ()
    expected_target_serial: str | None = None

    @property
    def enrollment_path(self) -> Path:
        return self.state_dir / "state" / "enrollment.json"

    @property
    def receipts_dir(self) -> Path:
        return self.state_dir / "receipts"

    @property
    def outputs_dir(self) -> Path:
        return self.state_dir / "outputs"

    @property
    def jobs_dir(self) -> Path:
        return self.state_dir / "jobs"


def load_settings(path: str | Path | None = None) -> Settings:
    config_path = Path(path or os.getenv("ARCHWRIGHT_CONFIG", "/etc/archwright/config.toml"))
    data: dict[str, object] = {}
    if config_path.exists():
        with config_path.open("rb") as fh:
            data = tomllib.load(fh)

    endpoint_data = data.get("target", {}) if isinstance(data, dict) else {}
    if not isinstance(endpoint_data, dict):
        endpoint_data = {}

    policy_data = data.get("policy", {}) if isinstance(data, dict) else {}
    if not isinstance(policy_data, dict):
        policy_data = {}

    runtime_data = data.get("runtime", {}) if isinstance(data, dict) else {}
    if not isinstance(runtime_data, dict):
        runtime_data = {}

    endpoint = TargetEndpoint(
        host=str(endpoint_data.get("host", "127.0.0.1")),
        port=int(endpoint_data.get("port", 2222)),
        user=str(endpoint_data.get("user", "arch-bootstrap")),
        identity_file=Path(str(endpoint_data.get("identity_file", "/etc/archwright/controller_ed25519"))),
        known_hosts_file=Path(str(endpoint_data.get("known_hosts_file", "/etc/archwright/known_hosts"))),
    )
    protected = policy_data.get("protected_serials", [])
    if not isinstance(protected, list):
        protected = []

    settings = Settings(
        endpoint=endpoint,
        state_dir=Path(str(runtime_data.get("state_dir", "/var/lib/archwright"))),
        staging_dir=Path(str(runtime_data.get("staging_dir", "/var/lib/archwright/staging"))),
        target_staging_dir=str(runtime_data.get("target_staging_dir", "/var/tmp/archwright")),
        target_name=str(endpoint_data.get("name", "sager-arch")),
        connect_timeout=int(runtime_data.get("connect_timeout", 10)),
        command_timeout=int(runtime_data.get("command_timeout", 120)),
        output_limit_bytes=int(runtime_data.get("output_limit_bytes", 262144)),
        protected_serials=tuple(str(x) for x in protected),
        expected_target_serial=(
            str(policy_data["expected_target_serial"])
            if policy_data.get("expected_target_serial")
            else None
        ),
    )
    for p in (
        settings.state_dir / "state",
        settings.receipts_dir,
        settings.outputs_dir,
        settings.jobs_dir,
        settings.staging_dir,
    ):
        p.mkdir(parents=True, exist_ok=True)
    return settings
