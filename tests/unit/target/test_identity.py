from __future__ import annotations

import json
from pathlib import Path

import pytest

from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.target.identity import IdentityCollector, parse_lsblk_identity
from archwright_mcp.transport.ssh import ProcessOutput

FIXTURE = Path(__file__).parents[2] / "fixtures" / "lsblk-sager.json"


def test_parse_sager_identity_uses_serial_not_device_number() -> None:
    devices, root, parent = parse_lsblk_identity(FIXTURE.read_text())
    assert root.path == "/dev/nvme1n1p2"
    assert parent.serial == "25044DB50A3B"
    windows = next(device for device in devices if device.serial == "25044DB4D635")
    assert windows.path == "/dev/nvme0n1"
    assert windows.read_only is True


def test_parse_identity_survives_device_renumbering() -> None:
    payload = FIXTURE.read_text().replace("nvme1n1", "nvme9n1").replace("nvme0n1", "nvme8n1")
    devices, root, parent = parse_lsblk_identity(payload)
    assert root.path == "/dev/nvme9n1p2"
    assert parent.serial == "25044DB50A3B"
    assert any(device.path == "/dev/nvme8n1" for device in devices)


def test_parse_identity_requires_root_uuid() -> None:
    payload = FIXTURE.read_text().replace(
        '"uuid": "3040811e-143c-418c-870b-5fe57b05dac3"', '"uuid": null'
    )
    with pytest.raises(ValidationError, match="root filesystem has no UUID"):
        parse_lsblk_identity(payload)


class FakeRuntimeTransport:
    def __init__(self, payload: dict[str, str]) -> None:
        self.payload = payload
        self.command: list[str] | None = None

    async def run(
        self,
        remote_argv: list[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int | None = None,
    ) -> ProcessOutput:
        self.command = remote_argv
        return ProcessOutput(0, json.dumps(self.payload), "", False, False)


def runtime_payload() -> dict[str, str]:
    return {
        "machine_id": "machine-id",
        "dmi_product_uuid": "product-uuid",
        "dmi_product_name": "V54x_6x_TU",
        "dmi_board_name": "board",
        "hostname": "sager",
        "boot_id_before": "boot-id",
        "boot_id_after": "boot-id",
        "lsblk": FIXTURE.read_text(),
    }


@pytest.mark.asyncio
async def test_collector_uses_fixed_privileged_runtime_probe() -> None:
    fake = FakeRuntimeTransport(runtime_payload())
    collector = IdentityCollector(fake)  # type: ignore[arg-type]
    identity = await collector.collect()
    assert identity.dmi_product_uuid == "product-uuid"
    assert identity.boot_id == "boot-id"
    assert fake.command == [
        "/usr/bin/sudo",
        "-n",
        "/usr/local/libexec/archwright-target.pyz",
        "inspect",
    ]


@pytest.mark.asyncio
async def test_collector_refuses_evidence_spanning_two_boots() -> None:
    payload = runtime_payload()
    payload["boot_id_after"] = "new-boot"
    collector = IdentityCollector(FakeRuntimeTransport(payload))  # type: ignore[arg-type]
    with pytest.raises(ArchwrightError) as captured:
        await collector.collect()
    assert captured.value.code is ErrorCode.TARGET_IDENTITY_MISMATCH


def test_parse_identity_refuses_duplicate_major_minor() -> None:
    payload = FIXTURE.read_text().replace('"maj:min": "259:1"', '"maj:min": "259:0"')
    with pytest.raises(ValidationError, match="duplicate major:minor"):
        parse_lsblk_identity(payload)
