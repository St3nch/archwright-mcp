"""Stable error types shared by every Archwright subsystem."""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Machine-readable error codes defined by the v1 design."""

    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    TARGET_NOT_ENROLLED = "TARGET_NOT_ENROLLED"
    TARGET_IDENTITY_MISMATCH = "TARGET_IDENTITY_MISMATCH"
    TARGET_HOSTKEY_MISMATCH = "TARGET_HOSTKEY_MISMATCH"
    SUDO_UNAVAILABLE = "SUDO_UNAVAILABLE"
    PROTECTED_STORAGE_MISSING = "PROTECTED_STORAGE_MISSING"
    PROTECTED_STORAGE_WRITABLE = "PROTECTED_STORAGE_WRITABLE"
    PROTECTED_STORAGE_REFUSED = "PROTECTED_STORAGE_REFUSED"
    TRANSFER_FAILED = "TRANSFER_FAILED"
    REMOTE_HASH_MISMATCH = "REMOTE_HASH_MISMATCH"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    TARGET_BUSY = "TARGET_BUSY"
    OPERATION_UNCERTAIN = "OPERATION_UNCERTAIN"
    REQUEST_ID_CONFLICT = "REQUEST_ID_CONFLICT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    UNSUPPORTED_STORAGE_TOPOLOGY = "UNSUPPORTED_STORAGE_TOPOLOGY"
    SECRET_OUTPUT_SUPPRESSED = "SECRET_OUTPUT_SUPPRESSED"
    JOB_NOT_FOUND = "JOB_NOT_FOUND"
    JOB_FAILED = "JOB_FAILED"
    FILE_PRECONDITION_FAILED = "FILE_PRECONDITION_FAILED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    REBOOT_RECONNECT_TIMEOUT = "REBOOT_RECONNECT_TIMEOUT"
    AUDIT_PERSISTENCE_FAILED = "AUDIT_PERSISTENCE_FAILED"
    CLEANUP_NOT_AUTHORIZED = "CLEANUP_NOT_AUTHORIZED"


class ArchwrightError(Exception):
    """Base exception with a stable code and structured, non-secret details."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
        }


class ValidationError(ArchwrightError):
    """Configuration or model input failed validation."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(ErrorCode.VALIDATION_FAILED, message, details=details)
