"""Collect and parse stable target identity evidence."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.transport.ssh import ProcessOutput, SshTransport


@dataclass(frozen=True, slots=True)
class BlockDevice:
    name: str
    path: str
    device_type: str
    serial: str | None
    model: str | None
    filesystem_type: str | None
    filesystem_uuid: str | None
    mountpoints: tuple[str, ...]
    read_only: bool
    parent_name: str | None
    wwn: str | None
    major_minor: str
    mount_options: tuple[str, ...]
    holders: tuple[str, ...]
    by_id_paths: tuple[str, ...]
    sysfs_serial: str | None
    namespace_id: str | None
    swap_active: bool


@dataclass(frozen=True, slots=True)
class LiveIdentity:
    machine_id: str
    dmi_product_uuid: str
    dmi_product_name: str
    dmi_board_name: str
    hostname: str
    boot_id: str
    root_filesystem_uuid: str
    root_parent_serial: str
    root_device_path: str
    block_devices: tuple[BlockDevice, ...]
    boot_consistent: bool = True

    def disks_for_serial(self, serial: str) -> tuple[BlockDevice, ...]:
        return tuple(
            device
            for device in self.block_devices
            if device.device_type == "disk" and device.serial == serial
        )

    def descendants_of(self, parent_name: str) -> tuple[BlockDevice, ...]:
        by_parent: dict[str, list[BlockDevice]] = {}
        for device in self.block_devices:
            if device.parent_name:
                by_parent.setdefault(device.parent_name, []).append(device)
        found: list[BlockDevice] = []
        pending = [parent_name]
        while pending:
            parent = pending.pop()
            for child in by_parent.get(parent, []):
                found.append(child)
                pending.append(child.name)
        return tuple(found)


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("lsblk text field has an invalid type")
    text = value.strip()
    return text or None


def _mountpoints(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, list):
        if not all(item is None or isinstance(item, str) for item in value):
            raise ValidationError("lsblk mountpoints field has an invalid item")
        return tuple(item for item in value if isinstance(item, str) and item)
    raise ValidationError("lsblk mountpoints field has an invalid type")


def _read_only(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str) and value in {"0", "1"}:
        return value == "1"
    raise ValidationError("lsblk read-only field has an invalid value")


def _string_sequence(value: Any, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"identity {field} field has an invalid type")
    return tuple(value)


def parse_lsblk_identity(payload: str) -> tuple[tuple[BlockDevice, ...], BlockDevice, BlockDevice]:
    """Parse lsblk JSON and return all devices, root node and root parent disk."""

    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValidationError("lsblk returned malformed JSON") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("blockdevices"), list):
        raise ValidationError("lsblk JSON has no blockdevices array")

    devices: list[BlockDevice] = []
    root: BlockDevice | None = None
    root_parent: BlockDevice | None = None

    def visit(raw_device: Any, ancestors: tuple[BlockDevice, ...]) -> None:
        nonlocal root, root_parent
        if not isinstance(raw_device, dict):
            raise ValidationError("lsblk block device is not an object")
        name = _optional_text(raw_device.get("name"))
        path = _optional_text(raw_device.get("path"))
        device_type = _optional_text(raw_device.get("type"))
        if not name or not path or not device_type:
            raise ValidationError("lsblk device is missing name, path or type")
        major_minor = _optional_text(raw_device.get("maj:min"))
        if not major_minor or re.fullmatch(r"[0-9]+:[0-9]+", major_minor) is None:
            raise ValidationError("lsblk device is missing major:minor identity")
        swap_active = raw_device.get("swap_active")
        if not isinstance(swap_active, bool):
            raise ValidationError("identity swap_active field has an invalid type")
        parent_name = _optional_text(raw_device.get("pkname"))
        expected_parent = ancestors[-1].name if ancestors else None
        if parent_name != expected_parent:
            raise ValidationError("lsblk tree and parent-name evidence disagree")
        device = BlockDevice(
            name=name,
            path=path,
            device_type=device_type,
            serial=_optional_text(raw_device.get("serial")),
            model=_optional_text(raw_device.get("model")),
            filesystem_type=_optional_text(raw_device.get("fstype")),
            filesystem_uuid=_optional_text(raw_device.get("uuid")),
            mountpoints=_mountpoints(raw_device.get("mountpoints")),
            read_only=_read_only(raw_device.get("ro", False)),
            parent_name=parent_name,
            wwn=_optional_text(raw_device.get("wwn")),
            major_minor=major_minor,
            mount_options=_string_sequence(raw_device.get("mount_options"), field="mount_options"),
            holders=_string_sequence(raw_device.get("holders"), field="holders"),
            by_id_paths=_string_sequence(raw_device.get("by_id_paths"), field="by_id_paths"),
            sysfs_serial=_optional_text(raw_device.get("sysfs_serial")),
            namespace_id=_optional_text(raw_device.get("namespace_id")),
            swap_active=swap_active,
        )
        devices.append(device)
        if "/" in device.mountpoints:
            if root is not None:
                raise ValidationError("lsblk reported multiple root-mounted devices")
            root = device
            disk_ancestors = tuple(item for item in ancestors if item.device_type == "disk")
            root_parent = (
                disk_ancestors[-1]
                if disk_ancestors
                else (device if device.device_type == "disk" else None)
            )
        children = raw_device.get("children", [])
        if not isinstance(children, list):
            raise ValidationError("lsblk children field is not an array")
        for child in children:
            visit(child, (*ancestors, device))

    for item in raw["blockdevices"]:
        visit(item, ())
    major_minors = [device.major_minor for device in devices]
    if len(set(major_minors)) != len(major_minors):
        raise ValidationError("lsblk reported duplicate major:minor identities")
    names = [device.name for device in devices]
    paths = [device.path for device in devices]
    if len(set(names)) != len(names) or len(set(paths)) != len(paths):
        raise ValidationError("lsblk reported duplicate device names or paths")
    if root is None:
        raise ValidationError("unable to identify the root-mounted block device")
    if root_parent is None or not root_parent.serial:
        raise ValidationError("unable to identify the root parent disk serial")
    if not root.filesystem_uuid:
        raise ValidationError("root filesystem has no UUID")
    return tuple(devices), root, root_parent


class IdentityCollector:
    """Collect identity through fixed read-only commands over pinned SSH."""

    def __init__(
        self,
        transport: SshTransport,
        *,
        timeout_seconds: float = 10,
        runtime_path: str = "/usr/local/libexec/archwright-target.pyz",
    ) -> None:
        self.transport = transport
        self.timeout_seconds = timeout_seconds
        self.runtime_path = runtime_path

    async def collect(self) -> LiveIdentity:
        result = await self.transport.run(
            ["/usr/bin/sudo", "-n", self.runtime_path, "inspect"],
            timeout_seconds=self.timeout_seconds,
        )
        payload = self._required_output("runtime_identity", result)
        try:
            values = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValidationError("target runtime returned malformed identity JSON") from exc
        if not isinstance(values, dict):
            raise ValidationError("target runtime identity is not an object")
        required = (
            "machine_id",
            "dmi_product_uuid",
            "dmi_product_name",
            "dmi_board_name",
            "hostname",
            "boot_id_before",
            "boot_id_after",
            "lsblk",
        )
        if any(not isinstance(values.get(key), str) for key in required):
            raise ValidationError("target runtime identity is missing required evidence")
        if values["boot_id_before"] != values["boot_id_after"]:
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "target rebooted during identity collection",
            )
        devices, root, root_parent = parse_lsblk_identity(values["lsblk"])
        return LiveIdentity(
            machine_id=values["machine_id"],
            dmi_product_uuid=values["dmi_product_uuid"],
            dmi_product_name=values["dmi_product_name"],
            dmi_board_name=values["dmi_board_name"],
            hostname=values["hostname"],
            boot_id=values["boot_id_before"],
            root_filesystem_uuid=root.filesystem_uuid or "",
            root_parent_serial=root_parent.serial or "",
            root_device_path=root.path,
            block_devices=devices,
            boot_consistent=True,
        )

    @staticmethod
    def _required_output(name: str, result: ProcessOutput) -> str:
        if not result.succeeded:
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "target identity probe failed",
                details={"probe": name, "exit_code": result.exit_code},
            )
        value = result.stdout.strip()
        if not value or result.stdout_truncated:
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "target identity probe returned incomplete evidence",
                details={"probe": name},
            )
        return value
