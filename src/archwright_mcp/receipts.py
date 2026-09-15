"""Atomic VPS-side operation receipt persistence."""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.models import (
    JsonValue,
    OperationReceipt,
    OperationStatus,
    Privilege,
    utc_now,
)
from archwright_mcp.redaction import redact

_RECEIPT_ID = re.compile(r"^aw-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{24}$")


def new_receipt_id(now: datetime | None = None) -> str:
    timestamp = (now or utc_now()).strftime("%Y%m%dT%H%M%SZ")
    return f"aw-{timestamp}-{secrets.token_hex(12)}"


def begin_receipt(
    *,
    tool: str,
    target_name: str,
    target_identity_digest: str,
    privilege: Privilege | None,
    request: dict[str, JsonValue],
    secret_keys: frozenset[str] = frozenset(),
    now: datetime | None = None,
    operation_id: str | None = None,
    request_id: str | None = None,
    request_digest: str | None = None,
) -> OperationReceipt:
    """Create a pending receipt with its request redacted before persistence."""

    started_at = now or utc_now()
    safe_request = redact(request, extra_secret_keys=secret_keys)
    if not isinstance(safe_request, dict):
        raise AssertionError("request redaction must preserve mappings")
    return OperationReceipt(
        receipt_id=new_receipt_id(started_at),
        tool=tool,
        target_name=target_name,
        target_identity_digest=target_identity_digest,
        privilege=privilege,
        request=safe_request,
        started_at=started_at,
        status=OperationStatus.PENDING,
        operation_id=operation_id,
        request_id=request_id,
        request_digest=request_digest,
    )


def update_receipt(
    receipt: OperationReceipt,
    *,
    status: OperationStatus,
    result: dict[str, JsonValue] | None = None,
    artifact_refs: tuple[str, ...] | None = None,
    job_id: str | None = None,
) -> OperationReceipt:
    """Update non-terminal operation evidence without losing prior identifiers."""

    if receipt.status in {
        OperationStatus.SUCCEEDED,
        OperationStatus.FAILED,
        OperationStatus.CANCELLED,
        OperationStatus.UNCERTAIN,
    }:
        raise ValidationError("receipt is already terminal")
    if status not in {OperationStatus.PENDING, OperationStatus.RUNNING}:
        raise ValidationError("update_receipt requires a non-terminal status")
    safe_result = redact(result or {})
    if not isinstance(safe_result, dict):
        raise AssertionError("result redaction must preserve mappings")
    return replace(
        receipt,
        status=status,
        result=safe_result,
        artifact_refs=artifact_refs if artifact_refs is not None else receipt.artifact_refs,
        job_id=job_id if job_id is not None else receipt.job_id,
    )


def finish_receipt(
    receipt: OperationReceipt,
    *,
    status: OperationStatus,
    result: dict[str, JsonValue],
    secret_keys: frozenset[str] = frozenset(),
    now: datetime | None = None,
) -> OperationReceipt:
    terminal = {
        OperationStatus.SUCCEEDED,
        OperationStatus.FAILED,
        OperationStatus.CANCELLED,
        OperationStatus.UNCERTAIN,
    }
    if receipt.status in terminal:
        raise ValidationError("receipt is already terminal")
    if status not in terminal:
        raise ValidationError("finish_receipt requires a terminal status")
    safe_result = redact(result, extra_secret_keys=secret_keys)
    if not isinstance(safe_result, dict):
        raise AssertionError("result redaction must preserve mappings")
    return replace(receipt, status=status, finished_at=now or utc_now(), result=safe_result)


class ReceiptStore:
    """Persist receipts as mode-0600 JSON using same-filesystem atomic rename."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise ValidationError("receipt store root must be absolute")
        self.root = root

    def create(self, receipt: OperationReceipt) -> Path:
        path = self._path(receipt)
        if path.exists():
            raise ArchwrightError(
                ErrorCode.AUDIT_PERSISTENCE_FAILED,
                "receipt already exists",
                details={"receipt_id": receipt.receipt_id},
            )
        self._atomic_write(path, receipt, replace_existing=False)
        return path

    def replace(self, receipt: OperationReceipt) -> Path:
        path = self._path(receipt)
        if not path.is_file():
            raise ArchwrightError(
                ErrorCode.AUDIT_PERSISTENCE_FAILED,
                "cannot update a missing receipt",
                details={"receipt_id": receipt.receipt_id},
            )
        self._atomic_write(path, receipt, replace_existing=True)
        return path

    def read(self, receipt_id: str) -> OperationReceipt:
        path = self._path_from_id(receipt_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ArchwrightError(
                ErrorCode.AUDIT_PERSISTENCE_FAILED,
                "unable to read receipt",
                details={"receipt_id": receipt_id},
            ) from exc
        if not isinstance(raw, dict):
            raise ArchwrightError(
                ErrorCode.AUDIT_PERSISTENCE_FAILED,
                "receipt root is not an object",
                details={"receipt_id": receipt_id},
            )
        return OperationReceipt.from_dict(raw)

    def _path(self, receipt: OperationReceipt) -> Path:
        expected_prefix = receipt.started_at.strftime("aw-%Y%m%dT%H%M%SZ-")
        if not _RECEIPT_ID.fullmatch(receipt.receipt_id) or not receipt.receipt_id.startswith(
            expected_prefix
        ):
            raise ValidationError("invalid receipt ID or timestamp mismatch")
        return (
            self.root
            / receipt.started_at.strftime("%Y")
            / receipt.started_at.strftime("%m")
            / receipt.started_at.strftime("%d")
            / f"{receipt.receipt_id}.json"
        )

    def _path_from_id(self, receipt_id: str) -> Path:
        if not _RECEIPT_ID.fullmatch(receipt_id):
            raise ValidationError("invalid receipt ID")
        date = receipt_id[3:11]
        return self.root / date[:4] / date[4:6] / date[6:8] / f"{receipt_id}.json"

    def _atomic_write(
        self, path: Path, receipt: OperationReceipt, *, replace_existing: bool
    ) -> None:
        payload = (json.dumps(receipt.as_dict(), sort_keys=True, indent=2) + "\n").encode()
        temporary: Path | None = None
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd, raw_path = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
            temporary = Path(raw_path)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                if replace_existing:
                    os.replace(temporary, path)
                    temporary = None
                else:
                    # Same-filesystem hard linking gives create-if-absent semantics.
                    # Unlike os.replace(), it cannot silently overwrite a receipt
                    # created by a concurrent operation after the caller's check.
                    os.link(temporary, path)
                    temporary.unlink()
                    temporary = None
                directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except Exception:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
                raise
        except (OSError, TypeError, ValueError) as exc:
            raise ArchwrightError(
                ErrorCode.AUDIT_PERSISTENCE_FAILED,
                "unable to persist receipt",
                details={"receipt_id": receipt.receipt_id},
            ) from exc
