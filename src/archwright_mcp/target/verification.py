"""Fail-closed comparison of live and enrolled target identity."""

from __future__ import annotations

from archwright_mcp.models import (
    EnrolledIdentity,
    JsonValue,
    ProtectedStorageStatus,
    VerificationResult,
    utc_now,
)
from archwright_mcp.target.identity import LiveIdentity


def verify_identity(
    enrolled: EnrolledIdentity,
    live: LiveIdentity,
    *,
    require_protected_read_only: bool = True,
) -> VerificationResult:
    mismatches: list[str] = []
    hard_fields = (
        ("machine-id", enrolled.machine_id, live.machine_id),
        ("DMI product UUID", enrolled.dmi_product_uuid, live.dmi_product_uuid),
        ("root filesystem UUID", enrolled.root_filesystem_uuid, live.root_filesystem_uuid),
        ("root parent serial", enrolled.root_parent_serial, live.root_parent_serial),
        ("expected target serial", enrolled.expected_target_serial, live.root_parent_serial),
    )
    for label, expected, actual in hard_fields:
        if expected != actual:
            mismatches.append(f"{label} mismatch")
    if not live.boot_consistent:
        mismatches.append("identity evidence spans multiple boots")

    protected: list[ProtectedStorageStatus] = []
    for serial in enrolled.protected_serials:
        matches = live.disks_for_serial(serial)
        if len(matches) == 0:
            mismatches.append(f"protected serial {serial} is missing")
            protected.append(
                ProtectedStorageStatus(
                    serial=serial,
                    device_path=None,
                    present=False,
                    read_only=None,
                )
            )
        elif len(matches) > 1:
            mismatches.append(f"protected serial {serial} resolves ambiguously")
            protected.append(
                ProtectedStorageStatus(
                    serial=serial,
                    device_path=None,
                    present=True,
                    read_only=None,
                    evidence={"match_count": len(matches)},
                )
            )
        else:
            device = matches[0]
            children = live.descendants_of(device.name)
            all_read_only = device.read_only and all(child.read_only for child in children)
            in_use = bool(
                device.mountpoints
                or device.mount_options
                or device.swap_active
                or device.holders
                or any(
                    child.mountpoints or child.mount_options or child.swap_active or child.holders
                    for child in children
                )
            )
            corroborated = (
                device.sysfs_serial == serial
                and bool(device.by_id_paths)
                and bool(device.major_minor)
            )
            if require_protected_read_only and not all_read_only:
                mismatches.append(f"protected serial {serial} is writable")
            if in_use:
                mismatches.append(f"protected serial {serial} has active consumers")
            if not corroborated:
                mismatches.append(f"protected serial {serial} lacks corroborating identity")
            protected.append(
                ProtectedStorageStatus(
                    serial=serial,
                    device_path=device.path,
                    present=True,
                    read_only=device.read_only,
                    descendants_read_only=all_read_only,
                    in_use=in_use,
                    evidence={
                        "model": device.model,
                        "wwn": device.wwn,
                        "major_minor": device.major_minor,
                        "by_id_paths": list(device.by_id_paths),
                        "namespace_id": device.namespace_id,
                    },
                )
            )

    target_matches = live.disks_for_serial(enrolled.expected_target_serial)
    if len(target_matches) != 1:
        mismatches.append("expected target serial does not resolve exactly once")
    else:
        target = target_matches[0]
        if (
            target.sysfs_serial != enrolled.expected_target_serial
            or not target.by_id_paths
            or not target.major_minor
        ):
            mismatches.append("expected target serial lacks corroborating identity")

    evidence: dict[str, JsonValue] = {
        "hostname": live.hostname,
        "boot_id": live.boot_id,
        "root_device_path": live.root_device_path,
        "root_parent_serial": live.root_parent_serial,
        "disk_serials": [
            device.serial
            for device in live.block_devices
            if device.device_type == "disk" and device.serial is not None
        ],
    }
    return VerificationResult(
        passed=not mismatches,
        checked_at=utc_now(),
        identity_digest=enrolled.digest if not mismatches else None,
        evidence=evidence,
        mismatches=tuple(mismatches),
        protected_storage=tuple(protected),
    )
