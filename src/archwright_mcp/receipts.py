from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import ArchwrightError


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def redact(value: Any) -> Any:
    secret_keys = {"password", "passphrase", "psk", "private_key", "token", "secret"}
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            out[k] = "<redacted>" if k.lower() in secret_keys else redact(v)
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


@dataclass(slots=True)
class Receipt:
    receipt_id: str
    tool: str
    started_at: str
    finished_at: str
    status: str
    target_name: str
    target_identity_digest: str | None
    request: dict[str, Any]
    result: dict[str, Any]


class ReceiptStore:
    def __init__(self, base: Path, target_name: str) -> None:
        self.base = base
        self.target_name = target_name
        self.base.mkdir(parents=True, exist_ok=True)

    def new_id(self) -> str:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        return f"op_{stamp}_{uuid.uuid4().hex[:10]}"

    def persist(
        self,
        *,
        receipt_id: str,
        tool: str,
        started_at: str,
        status: str,
        request: dict[str, Any],
        result: dict[str, Any],
        identity_digest: str | None = None,
    ) -> dict[str, Any]:
        receipt = Receipt(
            receipt_id=receipt_id,
            tool=tool,
            started_at=started_at,
            finished_at=now_iso(),
            status=status,
            target_name=self.target_name,
            target_identity_digest=identity_digest,
            request=redact(request),
            result=redact(result),
        )
        day = datetime.now(UTC).strftime("%Y/%m/%d")
        directory = self.base / day
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{receipt_id}.json"
        payload = json.dumps(asdict(receipt), indent=2, sort_keys=True).encode()
        try:
            fd, tmp = tempfile.mkstemp(prefix=".receipt-", dir=directory)
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except OSError as exc:
            raise ArchwrightError(
                "AUDIT_PERSISTENCE_FAILED",
                "Could not persist operation receipt",
                {"path": str(path), "error": str(exc)},
            ) from exc
        return asdict(receipt)

    def get(self, receipt_id: str) -> dict[str, Any]:
        for path in self.base.rglob(f"{receipt_id}.json"):
            return json.loads(path.read_text())
        raise ArchwrightError("VALIDATION_FAILED", "Receipt not found", {"receipt_id": receipt_id})

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        paths = sorted(self.base.rglob("op_*.json"), reverse=True)[: max(1, min(limit, 1000))]
        return [json.loads(p.read_text()) for p in paths]

    def summary(self, limit: int = 500) -> dict[str, Any]:
        items = self.list(limit)
        mutations = [x for x in items if x["status"] in {"ok", "failed", "cancelled"}]
        return {"count": len(mutations), "receipts": mutations}


def digest_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()
