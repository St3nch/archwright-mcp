from __future__ import annotations

import json
from pathlib import Path

import pytest

from archwright_mcp.errors import ValidationError
from archwright_mcp.models import EnrolledIdentity
from archwright_mcp.target.identity import LiveIdentity, parse_lsblk_identity
from archwright_mcp.target.verification import verify_identity

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


def live(payload: str | None = None, *, hostname: str = "sager") -> LiveIdentity:
    devices, root, parent = parse_lsblk_identity(payload or FIXTURE.read_text())
    return LiveIdentity(
        machine_id="machine-id",
        dmi_product_uuid="product-uuid",
        dmi_product_name="V54x_6x_TU",
        dmi_board_name="board",
        hostname=hostname,
        boot_id="boot-id",
        root_filesystem_uuid=root.filesystem_uuid or "",
        root_parent_serial=parent.serial or "",
        root_device_path=root.path,
        block_devices=devices,
    )


def test_exact_identity_and_read_only_windows_disk_pass() -> None:
    result = verify_identity(enrollment(), live())
    assert result.passed is True
    assert result.identity_digest == enrollment().digest


def test_hostname_is_advisory() -> None:
    assert verify_identity(enrollment(), live(hostname="renamed")).passed is True


def test_writable_windows_disk_fails_closed() -> None:
    payload = FIXTURE.read_text().replace('"ro": true', '"ro": false')
    result = verify_identity(enrollment(), live(payload))
    assert result.passed is False
    assert "protected serial 25044DB4D635 is writable" in result.mismatches


def test_recovery_preflight_allows_writable_protected_disk_only_for_enforcement() -> None:
    payload = FIXTURE.read_text().replace('"ro": true', '"ro": false')
    result = verify_identity(enrollment(), live(payload), require_protected_read_only=False)
    assert result.passed is True
    assert result.protected_storage[0].read_only is False


def test_missing_windows_disk_fails_closed() -> None:
    raw = json.loads(FIXTURE.read_text())
    raw["blockdevices"] = raw["blockdevices"][:1]
    result = verify_identity(enrollment(), live(json.dumps(raw)))
    assert result.passed is False
    assert "protected serial 25044DB4D635 is missing" in result.mismatches


def test_machine_id_mismatch_fails() -> None:
    actual = live()
    changed = LiveIdentity(
        machine_id="wrong-machine",
        dmi_product_uuid=actual.dmi_product_uuid,
        dmi_product_name=actual.dmi_product_name,
        dmi_board_name=actual.dmi_board_name,
        hostname=actual.hostname,
        boot_id=actual.boot_id,
        root_filesystem_uuid=actual.root_filesystem_uuid,
        root_parent_serial=actual.root_parent_serial,
        root_device_path=actual.root_device_path,
        block_devices=actual.block_devices,
    )
    assert verify_identity(enrollment(), changed).passed is False


def test_mounted_windows_descendant_fails_even_when_read_only() -> None:
    payload = FIXTURE.read_text().replace(
        '"mountpoints": [null],\n          "pkname": "nvme0n1"',
        '"mountpoints": ["/mnt/windows"],\n          "pkname": "nvme0n1"',
    )
    result = verify_identity(enrollment(), live(payload))
    assert result.passed is False
    assert "protected serial 25044DB4D635 has active consumers" in result.mismatches


def test_protected_disk_requires_corroborating_serial_evidence() -> None:
    payload = FIXTURE.read_text().replace('"sysfs_serial": "25044DB4D635"', '"sysfs_serial": null')
    result = verify_identity(enrollment(), live(payload))
    assert result.passed is False
    assert "lacks corroborating identity" in " ".join(result.mismatches)


def test_protected_child_missing_tree_parent_is_refused() -> None:
    payload = FIXTURE.read_text().replace(
        '"mountpoints": [null],\n          "pkname": "nvme0n1"',
        '"mountpoints": ["/mnt/windows"],\n          "pkname": null',
    )
    with pytest.raises(ValidationError, match="parent-name evidence"):
        live(payload)


def test_mountinfo_options_mark_protected_child_in_use() -> None:
    raw = json.loads(FIXTURE.read_text())
    raw["blockdevices"][1]["children"][0]["mount_options"] = ["rw", "relatime"]
    result = verify_identity(enrollment(), live(json.dumps(raw)))
    assert result.passed is False
    assert "active consumers" in " ".join(result.mismatches)


def test_malformed_swap_evidence_is_refused() -> None:
    payload = FIXTURE.read_text().replace('"swap_active": false', '"swap_active": "true"', 1)
    with pytest.raises(ValidationError, match="swap_active"):
        live(payload)
