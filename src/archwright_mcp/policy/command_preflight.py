"""Best-effort detection of obvious protected-storage root commands."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class CommandPreflight:
    allowed: bool
    findings: tuple[str, ...]


_DESTRUCTIVE_COMMAND = re.compile(
    r"(?im)(?:^|[;&|])\s*(?:(?:/\S*/)?sudo(?:\s+-\S+)*\s+)?(?:/\S*/)?(?:"
    r"blkdiscard|dd|fdisk|gdisk|mkfs(?:\.\w+)?|parted|pvcreate|sgdisk|wipefs"
    r")\b|\bcryptsetup\s+luksFormat\b|\bblockdev\s+--setrw\b|\bmdadm\s+--create\b"
)


def preflight_root_script(
    script: str,
    *,
    protected_serials: tuple[str, ...],
    protected_paths: tuple[PurePosixPath, ...],
) -> CommandPreflight:
    """Flag obvious destructive commands that name protected storage.

    This deliberately does not claim to sandbox root. It catches accidents while
    the kernel read-only flag remains the stronger guardrail.
    """

    destructive = bool(_DESTRUCTIVE_COMMAND.search(script))
    if not destructive:
        return CommandPreflight(allowed=True, findings=())
    findings: list[str] = []
    for path in protected_paths:
        pattern = re.compile(rf"(?<![\w/]){re.escape(str(path))}(?:p?\d+)?(?![\w/])")
        if pattern.search(script):
            findings.append(f"destructive command references protected path {path}")
    for serial in protected_serials:
        if serial and serial in script:
            findings.append(f"destructive command references protected serial {serial}")
    return CommandPreflight(allowed=not findings, findings=tuple(dict.fromkeys(findings)))
