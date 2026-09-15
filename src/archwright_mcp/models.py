"""Core immutable data models for Archwright v1."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from archwright_mcp.errors import ValidationError

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

_SSH_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(UTC)


def format_timestamp(value: datetime) -> str:
    """Render an aware timestamp in stable RFC 3339 form."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    """Parse an RFC 3339 timestamp and normalize it to UTC."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("invalid timestamp", details={"value": value}) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError("timestamps must include a UTC offset")
    return parsed.astimezone(UTC)


def _require_nonempty(label: str, value: str) -> None:
    if not value.strip():
        raise ValidationError(f"{label} must not be empty")


def _require_absolute(label: str, value: Path) -> None:
    if not value.is_absolute():
        raise ValidationError(f"{label} must be an absolute path", details={"value": str(value)})


class Privilege(StrEnum):
    USER = "user"
    ROOT = "root"


class OperationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNCERTAIN = "uncertain"


class JobState(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    EXITED = "exited"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    UNCERTAIN = "uncertain"
    UNKNOWN = "unknown"


class OutputPolicy(StrEnum):
    CAPTURE = "capture"
    DISCARD = "discard"


@dataclass(frozen=True, slots=True)
class TargetEndpoint:
    host: str
    port: int
    user: str
    controller_key: Path
    known_hosts: Path

    def __post_init__(self) -> None:
        _require_nonempty("target host", self.host)
        _require_nonempty("target user", self.user)
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValidationError("target host must be a literal loopback address") from exc
        if not address.is_loopback:
            raise ValidationError("target host must be loopback")
        if not _SSH_USER.fullmatch(self.user):
            raise ValidationError("target user is not a valid Linux account name")
        if not 1 <= self.port <= 65535:
            raise ValidationError("target port must be between 1 and 65535")
        _require_absolute("controller key", self.controller_key)
        _require_absolute("known-hosts file", self.known_hosts)


@dataclass(frozen=True, slots=True)
class EnrolledIdentity:
    target_name: str
    machine_id: str
    dmi_product_uuid: str
    dmi_product_name: str
    dmi_board_name: str
    root_filesystem_uuid: str
    root_parent_serial: str
    expected_target_serial: str
    protected_serials: tuple[str, ...]
    ssh_host_key_fingerprints: tuple[str, ...]

    def __post_init__(self) -> None:
        for label, value in (
            ("target name", self.target_name),
            ("machine-id", self.machine_id),
            ("DMI product UUID", self.dmi_product_uuid),
            ("root filesystem UUID", self.root_filesystem_uuid),
            ("root parent serial", self.root_parent_serial),
            ("expected target serial", self.expected_target_serial),
        ):
            _require_nonempty(label, value)
        if self.root_parent_serial != self.expected_target_serial:
            raise ValidationError("root parent serial does not match expected target serial")
        if not self.protected_serials:
            raise ValidationError("at least one protected serial is required")
        if len(set(self.protected_serials)) != len(self.protected_serials):
            raise ValidationError("protected serials must be unique")
        if self.expected_target_serial in self.protected_serials:
            raise ValidationError("target serial cannot also be protected")
        if not self.ssh_host_key_fingerprints:
            raise ValidationError("at least one SSH host-key fingerprint is required")

    @property
    def digest(self) -> str:
        """Return a deterministic digest of all hard enrollment evidence."""

        payload = asdict(self)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ProtectedStorageStatus:
    serial: str
    device_path: str | None
    present: bool
    read_only: bool | None
    descendants_read_only: bool | None = None
    in_use: bool | None = None
    evidence: dict[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    passed: bool
    checked_at: datetime
    identity_digest: str | None
    evidence: dict[str, JsonValue] = field(default_factory=dict)
    mismatches: tuple[str, ...] = ()
    protected_storage: tuple[ProtectedStorageStatus, ...] = ()

    def __post_init__(self) -> None:
        format_timestamp(self.checked_at)
        if self.passed and self.mismatches:
            raise ValidationError("a passing verification cannot contain mismatches")
        if self.passed and not self.identity_digest:
            raise ValidationError("a passing verification requires an identity digest")


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    remote_script_sha256: str
    receipt_id: str
    signal: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    uncertain: bool = False

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled


@dataclass(frozen=True, slots=True)
class ExecutionHandle:
    operation_id: str
    receipt_id: str
    job_id: str
    unit_name: str
    target_identity_digest: str
    boot_id: str


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    handle: ExecutionHandle
    state: JobState
    exit_code: int | None = None
    signal: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    uncertain: bool = False
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True, slots=True)
class JobRecord:
    job_id: str
    unit_name: str
    target_identity_digest: str
    privilege: Privilege
    script_sha256: str
    state: JobState
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    receipt_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OperationReceipt:
    receipt_id: str
    tool: str
    target_name: str
    target_identity_digest: str
    privilege: Privilege | None
    request: dict[str, JsonValue]
    started_at: datetime
    status: OperationStatus
    finished_at: datetime | None = None
    result: dict[str, JsonValue] = field(default_factory=dict)
    artifact_refs: tuple[str, ...] = ()
    job_id: str | None = None
    reboot_id: str | None = None
    operation_id: str | None = None
    request_id: str | None = None
    request_digest: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty("receipt ID", self.receipt_id)
        _require_nonempty("tool", self.tool)
        _require_nonempty("target name", self.target_name)
        _require_nonempty("target identity digest", self.target_identity_digest)
        format_timestamp(self.started_at)
        if self.finished_at is not None:
            format_timestamp(self.finished_at)
            if self.finished_at < self.started_at:
                raise ValidationError("receipt finish time cannot precede start time")
        terminal = {
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
            OperationStatus.UNCERTAIN,
        }
        if self.status in terminal and self.finished_at is None:
            raise ValidationError("terminal receipt status requires a finish time")

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "receipt_id": self.receipt_id,
            "tool": self.tool,
            "target_name": self.target_name,
            "target_identity_digest": self.target_identity_digest,
            "privilege": self.privilege.value if self.privilege else None,
            "request": self.request,
            "started_at": format_timestamp(self.started_at),
            "finished_at": format_timestamp(self.finished_at) if self.finished_at else None,
            "status": self.status.value,
            "result": self.result,
            "artifact_refs": list(self.artifact_refs),
            "job_id": self.job_id,
            "reboot_id": self.reboot_id,
            "operation_id": self.operation_id,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
        }

    @classmethod
    def from_dict(cls, value: dict[str, JsonValue]) -> OperationReceipt:
        def required_string(key: str) -> str:
            item = value.get(key)
            if not isinstance(item, str):
                raise ValidationError("invalid receipt field", details={"field": key})
            return item

        def optional_string(key: str) -> str | None:
            item = value.get(key)
            if item is not None and not isinstance(item, str):
                raise ValidationError("invalid receipt field", details={"field": key})
            return item

        request = value.get("request")
        result = value.get("result")
        artifacts = value.get("artifact_refs")
        if not isinstance(request, dict) or not isinstance(result, dict):
            raise ValidationError("receipt request and result must be objects")
        if not isinstance(artifacts, list) or not all(isinstance(item, str) for item in artifacts):
            raise ValidationError("receipt artifact_refs must be a string array")
        finished = value.get("finished_at")
        privilege = value.get("privilege")
        job_id = value.get("job_id")
        reboot_id = value.get("reboot_id")
        operation_id = optional_string("operation_id")
        request_id = optional_string("request_id")
        request_digest = optional_string("request_digest")
        if privilege is not None and not isinstance(privilege, str):
            raise ValidationError("invalid receipt privilege")
        if job_id is not None and not isinstance(job_id, str):
            raise ValidationError("invalid receipt job_id")
        if reboot_id is not None and not isinstance(reboot_id, str):
            raise ValidationError("invalid receipt reboot_id")
        try:
            parsed_privilege = Privilege(privilege) if privilege else None
            parsed_status = OperationStatus(required_string("status"))
        except ValueError as exc:
            raise ValidationError("receipt contains an unknown enum value") from exc
        return cls(
            receipt_id=required_string("receipt_id"),
            tool=required_string("tool"),
            target_name=required_string("target_name"),
            target_identity_digest=required_string("target_identity_digest"),
            privilege=parsed_privilege,
            request=request,
            started_at=parse_timestamp(required_string("started_at")),
            finished_at=parse_timestamp(finished) if isinstance(finished, str) else None,
            status=parsed_status,
            result=result,
            artifact_refs=tuple(str(item) for item in artifacts),
            job_id=job_id,
            reboot_id=reboot_id,
            operation_id=operation_id,
            request_id=request_id,
            request_digest=request_digest,
        )
