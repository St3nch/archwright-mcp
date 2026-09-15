from __future__ import annotations

from pathlib import Path

import pytest

from archwright_mcp.models import EnrolledIdentity
from archwright_mcp.policy.protected_storage import ProtectedStorageController
from archwright_mcp.target.identity import LiveIdentity, parse_lsblk_identity
from archwright_mcp.target.verification import verify_identity
from archwright_mcp.transport.ssh import ProcessOutput

FIXTURE = Path(__file__).parents[2] / "fixtures" / "lsblk-sager.json"


def enrollment() -> EnrolledIdentity:
    return EnrolledIdentity(
        target_name="sager-arch",
        machine_id="machine-id",
        dmi_product_uuid="product-uuid",
        dmi_product_name="V54x_6x_TU",
        dmi_board_name="board",
        root_filesystem_uuid="3040811e-143c-418c-870b-5fe57b05dac3",
        root_parent_serial="25044DB50A3B",
        expected_target_serial="25044DB50A3B",
        protected_serials=("25044DB4D635",),
        ssh_host_key_fingerprints=("SHA256:temporary",),
    )


def live(payload: str) -> LiveIdentity:
    devices, root, parent = parse_lsblk_identity(payload)
    return LiveIdentity(
        machine_id="machine-id",
        dmi_product_uuid="product-uuid",
        dmi_product_name="V54x_6x_TU",
        dmi_board_name="board",
        hostname="sager",
        boot_id="boot-id",
        root_filesystem_uuid=root.filesystem_uuid or "",
        root_parent_serial=parent.serial or "",
        root_device_path=root.path,
        block_devices=devices,
    )


class FakeTransport:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    async def run(
        self,
        remote_argv: list[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int | None = None,
    ) -> ProcessOutput:
        self.commands.append(remote_argv)
        return ProcessOutput(0, "", "", False, False)


class FakeCollector:
    def __init__(self, value: LiveIdentity) -> None:
        self.value = value

    async def collect(self) -> LiveIdentity:
        return self.value


@pytest.mark.asyncio
async def test_enforcement_uses_live_serial_resolution_after_renumbering() -> None:
    writable = (
        FIXTURE.read_text().replace("nvme0n1", "nvme8n1").replace('"ro": true', '"ro": false')
    )
    readonly = writable.replace('"ro": false', '"ro": true')
    preflight = verify_identity(enrollment(), live(writable), require_protected_read_only=False)
    transport = FakeTransport()
    controller = ProtectedStorageController(
        transport,  # type: ignore[arg-type]
        FakeCollector(live(readonly)),  # type: ignore[arg-type]
    )
    result = await controller.enforce(enrollment(), preflight)
    assert result.passed is True
    assert transport.commands == [
        [
            "/usr/bin/sudo",
            "-n",
            "/usr/local/libexec/archwright-target.pyz",
            "protect",
            enrollment().digest,
            "boot-id",
        ],
    ]
