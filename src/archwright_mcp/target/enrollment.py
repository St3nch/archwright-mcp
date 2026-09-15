"""Atomic persistence for the single v1 enrolled target."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.models import EnrolledIdentity


def known_hosts_fingerprints(path: Path) -> frozenset[str]:
    """Calculate SHA256 fingerprints from a dedicated OpenSSH known-hosts file."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ArchwrightError(
            ErrorCode.TARGET_HOSTKEY_MISMATCH,
            "unable to read the dedicated known-hosts file",
        ) from exc
    fingerprints: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if fields[0].startswith("@"):
            fields = fields[1:]
        if len(fields) < 3:
            raise ArchwrightError(
                ErrorCode.TARGET_HOSTKEY_MISMATCH,
                "dedicated known-hosts file contains a malformed entry",
            )
        try:
            key = base64.b64decode(fields[2], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ArchwrightError(
                ErrorCode.TARGET_HOSTKEY_MISMATCH,
                "dedicated known-hosts file contains invalid key data",
            ) from exc
        encoded = base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
        fingerprints.add(f"SHA256:{encoded}")
    if not fingerprints:
        raise ArchwrightError(
            ErrorCode.TARGET_HOSTKEY_MISMATCH,
            "dedicated known-hosts file contains no host keys",
        )
    return frozenset(fingerprints)


class EnrollmentStore:
    SCHEMA_VERSION = 1

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValidationError("enrollment path must be absolute")
        self.path = path

    def read(self) -> EnrolledIdentity | None:
        if not self.path.exists():
            return None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchwrightError(
                ErrorCode.TARGET_NOT_ENROLLED,
                "unable to read target enrollment",
            ) from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != self.SCHEMA_VERSION:
            raise ArchwrightError(
                ErrorCode.TARGET_NOT_ENROLLED,
                "target enrollment has an unsupported schema",
            )
        identity = raw.get("identity")
        if not isinstance(identity, dict):
            raise ArchwrightError(
                ErrorCode.TARGET_NOT_ENROLLED,
                "target enrollment has no identity object",
            )
        parsed = self._parse_identity(identity)
        if raw.get("identity_digest") != parsed.digest:
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "stored target enrollment digest does not match its contents",
            )
        return parsed

    def write(self, identity: EnrolledIdentity, *, replace_existing: bool = False) -> None:
        if self.path.exists() and not replace_existing:
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "a target is already enrolled; replacement requires explicit intent",
            )
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "identity_digest": identity.digest,
            "identity": asdict(identity),
        }
        temporary: Path | None = None
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor, raw_path = tempfile.mkstemp(prefix=".enrollment-", dir=self.path.parent)
            temporary = Path(raw_path)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            if replace_existing:
                os.replace(temporary, self.path)
            else:
                os.link(temporary, self.path)
                temporary.unlink()
            temporary = None
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise ArchwrightError(
                ErrorCode.AUDIT_PERSISTENCE_FAILED,
                "unable to persist target enrollment",
            ) from exc
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _parse_identity(value: dict[str, Any]) -> EnrolledIdentity:
        required = (
            "target_name",
            "machine_id",
            "dmi_product_uuid",
            "dmi_product_name",
            "dmi_board_name",
            "root_filesystem_uuid",
            "root_parent_serial",
            "expected_target_serial",
        )
        if any(not isinstance(value.get(key), str) for key in required):
            raise ArchwrightError(
                ErrorCode.TARGET_NOT_ENROLLED,
                "target enrollment contains invalid string fields",
            )
        protected = value.get("protected_serials")
        fingerprints = value.get("ssh_host_key_fingerprints")
        if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
            raise ArchwrightError(
                ErrorCode.TARGET_NOT_ENROLLED,
                "target enrollment contains invalid protected serials",
            )
        if not isinstance(fingerprints, list) or not all(
            isinstance(item, str) for item in fingerprints
        ):
            raise ArchwrightError(
                ErrorCode.TARGET_NOT_ENROLLED,
                "target enrollment contains invalid SSH fingerprints",
            )
        try:
            return EnrolledIdentity(
                target_name=value["target_name"],
                machine_id=value["machine_id"],
                dmi_product_uuid=value["dmi_product_uuid"],
                dmi_product_name=value["dmi_product_name"],
                dmi_board_name=value["dmi_board_name"],
                root_filesystem_uuid=value["root_filesystem_uuid"],
                root_parent_serial=value["root_parent_serial"],
                expected_target_serial=value["expected_target_serial"],
                protected_serials=tuple(str(item) for item in protected),
                ssh_host_key_fingerprints=tuple(str(item) for item in fingerprints),
            )
        except ValidationError as exc:
            raise ArchwrightError(
                ErrorCode.TARGET_NOT_ENROLLED,
                "stored target enrollment failed validation",
            ) from exc
