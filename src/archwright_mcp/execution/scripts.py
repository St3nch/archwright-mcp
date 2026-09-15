"""Immutable script requests and safe artifact preparation."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from archwright_mcp.config import PolicyConfig
from archwright_mcp.errors import ValidationError
from archwright_mcp.models import JsonValue, OutputPolicy, Privilege
from archwright_mcp.redaction import is_secret_key

_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SECRET_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_MAX_ARGUMENTS = 256
_MAX_ARGUMENT_BYTES = 16_384
_MAX_ENVIRONMENT_ENTRIES = 128
_MAX_ENVIRONMENT_VALUE_BYTES = 65_536


def _validated_pairs(
    pairs: tuple[tuple[str, str], ...],
    *,
    secret: bool,
) -> tuple[tuple[str, str], ...]:
    if len(pairs) > _MAX_ENVIRONMENT_ENTRIES:
        raise ValidationError("too many execution environment entries")
    normalized: list[tuple[str, str]] = []
    names: set[str] = set()
    for name, value in pairs:
        if not _ENVIRONMENT_NAME.fullmatch(name):
            raise ValidationError("invalid execution environment name")
        if name in names:
            raise ValidationError("duplicate execution environment name")
        names.add(name)
        if "\x00" in value:
            raise ValidationError("execution environment value contains NUL")
        if secret:
            if not _SECRET_REFERENCE.fullmatch(value):
                raise ValidationError("invalid secret reference")
        else:
            if is_secret_key(name):
                raise ValidationError("secret-looking environment names require a secret reference")
            if len(value.encode()) > _MAX_ENVIRONMENT_VALUE_BYTES:
                raise ValidationError("execution environment value is too large")
        normalized.append((name, value))
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    request_id: str
    script: bytes
    interpreter: str = "/usr/bin/bash"
    arguments: tuple[str, ...] = ()
    privilege: Privilege = Privilege.USER
    user: str | None = None
    working_directory: str = "/"
    environment: tuple[tuple[str, str], ...] = ()
    secret_environment: tuple[tuple[str, str], ...] = ()
    timeout_seconds: float = 1_800
    wait_seconds: float = 10
    output_policy: OutputPolicy = OutputPolicy.CAPTURE

    def validate(self, policy: PolicyConfig) -> None:
        if not _REQUEST_ID.fullmatch(self.request_id):
            raise ValidationError("request ID has an invalid format")
        if not self.script:
            raise ValidationError("execution script must not be empty")
        if len(self.script) > policy.max_script_bytes:
            raise ValidationError("execution script exceeds the configured size limit")
        interpreter = PurePosixPath(self.interpreter)
        if not interpreter.is_absolute() or ".." in interpreter.parts:
            raise ValidationError("interpreter must be a normalized absolute target path")
        cwd = PurePosixPath(self.working_directory)
        if not cwd.is_absolute() or ".." in cwd.parts:
            raise ValidationError("working directory must be a normalized absolute target path")
        if len(self.arguments) > _MAX_ARGUMENTS:
            raise ValidationError("too many execution arguments")
        if any(
            "\x00" in value or len(value.encode()) > _MAX_ARGUMENT_BYTES for value in self.arguments
        ):
            raise ValidationError("execution argument is invalid or too large")
        if self.privilege is Privilege.ROOT and self.user is not None:
            raise ValidationError("root execution cannot select a non-root user")
        if self.privilege is Privilege.USER and self.user == "root":
            raise ValidationError("user execution cannot select the root account")
        if self.user is not None and not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.user):
            raise ValidationError("execution user is not a valid Linux account name")
        ordinary = _validated_pairs(self.environment, secret=False)
        sensitive = _validated_pairs(self.secret_environment, secret=True)
        if {key for key, _ in ordinary} & {key for key, _ in sensitive}:
            raise ValidationError("environment name cannot be both ordinary and secret")
        for label, value, ceiling in (
            ("runtime", self.timeout_seconds, policy.max_runtime_seconds),
            ("wait", self.wait_seconds, policy.max_wait_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 < value <= ceiling
            ):
                raise ValidationError(f"execution {label} is outside the configured range")

    @property
    def effective_output_policy(self) -> OutputPolicy:
        if self.secret_environment:
            return OutputPolicy.DISCARD
        return self.output_policy

    @property
    def script_sha256(self) -> str:
        return hashlib.sha256(self.script).hexdigest()

    def normalized_digest(self) -> str:
        payload = {
            "request_id": self.request_id,
            "script_sha256": self.script_sha256,
            "script_size": len(self.script),
            "interpreter": self.interpreter,
            "arguments": list(self.arguments),
            "privilege": self.privilege.value,
            "user": self.user,
            "working_directory": self.working_directory,
            "environment": list(sorted(self.environment)),
            "secret_environment": list(sorted(self.secret_environment)),
            "timeout_seconds": self.timeout_seconds,
            "wait_seconds": self.wait_seconds,
            "output_policy": self.effective_output_policy.value,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    def receipt_request(self) -> dict[str, JsonValue]:
        return {
            "request_id": self.request_id,
            "script_sha256": self.script_sha256,
            "script_size": len(self.script),
            "interpreter": self.interpreter,
            "arguments": list(self.arguments),
            "privilege": self.privilege.value,
            "user": self.user,
            "working_directory": self.working_directory,
            "environment_names": [name for name, _ in sorted(self.environment)],
            "secret_environment_names": [name for name, _ in sorted(self.secret_environment)],
            "timeout_seconds": self.timeout_seconds,
            "wait_seconds": self.wait_seconds,
            "output_policy": self.effective_output_policy.value,
        }


@dataclass(frozen=True, slots=True)
class PreparedScript:
    artifact_id: str
    content: bytes
    size_bytes: int
    sha256: str

    @classmethod
    def from_request(cls, request: ExecutionRequest, operation_id: str) -> PreparedScript:
        artifact_id = f"{operation_id}-script"
        return cls(
            artifact_id=artifact_id,
            content=request.script,
            size_bytes=len(request.script),
            sha256=request.script_sha256,
        )
