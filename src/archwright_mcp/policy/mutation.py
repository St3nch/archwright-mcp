"""The single authorization gate used by every mutating tool."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, replace

from archwright_mcp.config import TargetConfig
from archwright_mcp.errors import ArchwrightError, ErrorCode
from archwright_mcp.models import (
    EnrolledIdentity,
    JsonValue,
    OperationReceipt,
    OperationStatus,
    Privilege,
    VerificationResult,
)
from archwright_mcp.receipts import (
    ReceiptStore,
    begin_receipt,
    finish_receipt,
    update_receipt,
)
from archwright_mcp.target.enrollment import EnrollmentStore, known_hosts_fingerprints
from archwright_mcp.target.identity import IdentityCollector
from archwright_mcp.target.verification import verify_identity


@dataclass(slots=True)
class MutationAuthorization:
    receipt: OperationReceipt
    store: ReceiptStore
    verification: VerificationResult
    enrolled: EnrolledIdentity
    operation_id: str
    request_id: str
    request_digest: str
    is_replay: bool = False
    _claimed: bool = False
    _release: Callable[[bool], None] | None = None

    def claim(self, *, request_digest: str, boot_id: str) -> None:
        """Consume this authorization exactly once at the execution boundary."""

        if self.is_replay or self._claimed:
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "mutation authorization has already been consumed",
                details={"operation_id": self.operation_id, "receipt_id": self.receipt.receipt_id},
            )
        if request_digest != self.request_digest or boot_id != self.verification.evidence.get(
            "boot_id"
        ):
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "mutation authorization no longer matches the execution request or boot",
            )
        self._claimed = True

    def mark_running(self, *, job_id: str, artifact_refs: tuple[str, ...]) -> OperationReceipt:
        running = update_receipt(
            self.receipt,
            status=OperationStatus.RUNNING,
            result={"state": "running"},
            artifact_refs=artifact_refs,
            job_id=job_id,
        )
        try:
            self.store.replace(running)
        except ArchwrightError:
            self._release_once(False)
            raise
        self.receipt = running
        return running

    def finish(
        self,
        *,
        status: OperationStatus,
        result: dict[str, JsonValue],
        secret_keys: frozenset[str] = frozenset(),
    ) -> OperationReceipt:
        completed = finish_receipt(
            self.receipt,
            status=status,
            result=result,
            secret_keys=secret_keys,
        )
        try:
            self.store.replace(completed)
        except ArchwrightError:
            self._release_once(False)
            raise
        self.receipt = completed
        if status is not OperationStatus.UNCERTAIN:
            self._release_once(True)
        return completed

    def _release_once(self, audit_healthy: bool) -> None:
        callback, self._release = self._release, None
        if callback is not None:
            callback(audit_healthy)


class MutationGate:
    """Verify target/storage and persist intent before any mutating effect."""

    def __init__(
        self,
        enrollment_store: EnrollmentStore,
        identity_collector: IdentityCollector,
        receipt_store: ReceiptStore,
        target_config: TargetConfig | None = None,
    ) -> None:
        self.enrollment_store = enrollment_store
        self.identity_collector = identity_collector
        self.receipt_store = receipt_store
        self.target_config = target_config
        self._state_lock = asyncio.Lock()
        self._active_operation_id: str | None = None
        self._bindings: dict[str, MutationAuthorization] = {}
        self._audit_healthy = True

    async def authorize(
        self,
        *,
        tool: str,
        privilege: Privilege | None,
        request: dict[str, JsonValue],
        secret_keys: frozenset[str] = frozenset(),
        request_id: str | None = None,
        request_digest: str | None = None,
    ) -> MutationAuthorization:
        normalized_request_id = request_id or f"internal-{secrets.token_hex(16)}"
        normalized_digest = request_digest or self._digest_request(request)
        async with self._state_lock:
            if not self._audit_healthy:
                raise ArchwrightError(
                    ErrorCode.AUDIT_PERSISTENCE_FAILED,
                    "new mutations are blocked after an audit persistence failure",
                )
            prior = self._bindings.get(normalized_request_id)
            if prior is not None:
                if prior.request_digest != normalized_digest:
                    raise ArchwrightError(
                        ErrorCode.REQUEST_ID_CONFLICT,
                        "request ID is already bound to different inputs",
                    )
                return replace(prior, is_replay=True, _release=None)
            if self._active_operation_id is not None:
                raise ArchwrightError(
                    ErrorCode.TARGET_BUSY,
                    "another target mutation is still active",
                    details={"operation_id": self._active_operation_id},
                )
            operation_id = f"op-{secrets.token_hex(16)}"
            self._active_operation_id = operation_id

        try:
            return await self._authorize_new(
                operation_id=operation_id,
                request_id=normalized_request_id,
                request_digest=normalized_digest,
                tool=tool,
                privilege=privilege,
                request=request,
                secret_keys=secret_keys,
            )
        except ArchwrightError as exc:
            self._release(operation_id, exc.code is not ErrorCode.AUDIT_PERSISTENCE_FAILED)
            raise
        except BaseException:
            self._release(operation_id, True)
            raise

    async def _authorize_new(
        self,
        *,
        operation_id: str,
        request_id: str,
        request_digest: str,
        tool: str,
        privilege: Privilege | None,
        request: dict[str, JsonValue],
        secret_keys: frozenset[str],
    ) -> MutationAuthorization:
        enrolled = self.enrollment_store.read()
        if enrolled is None:
            raise ArchwrightError(ErrorCode.TARGET_NOT_ENROLLED, "no target is enrolled")
        self._require_policy_binding(enrolled)
        live = await self.identity_collector.collect()
        verification = verify_identity(enrolled, live)
        if not verification.passed:
            self._raise_verification_failure(verification)
        receipt = begin_receipt(
            tool=tool,
            target_name=enrolled.target_name,
            target_identity_digest=enrolled.digest,
            privilege=privilege,
            request=request,
            secret_keys=secret_keys,
            operation_id=operation_id,
            request_id=request_id,
            request_digest=request_digest,
        )
        self.receipt_store.create(receipt)
        authorization = MutationAuthorization(
            receipt=receipt,
            store=self.receipt_store,
            verification=verification,
            enrolled=enrolled,
            operation_id=operation_id,
            request_id=request_id,
            request_digest=request_digest,
            _release=lambda healthy: self._release(operation_id, healthy),
        )
        self._bindings[request_id] = authorization
        return authorization

    def _require_policy_binding(self, enrolled: EnrolledIdentity) -> None:
        config = self.target_config
        if config is None:
            return
        if (
            enrolled.target_name != config.name
            or enrolled.expected_target_serial != config.expected_target_serial
            or enrolled.protected_serials != config.protected_serials
        ):
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "target enrollment disagrees with operator configuration",
            )
        trusted = known_hosts_fingerprints(config.endpoint.known_hosts)
        if trusted != frozenset(enrolled.ssh_host_key_fingerprints):
            raise ArchwrightError(
                ErrorCode.TARGET_HOSTKEY_MISMATCH,
                "target enrollment disagrees with the dedicated host-key pins",
            )

    def _release(self, operation_id: str, audit_healthy: bool) -> None:
        if self._active_operation_id == operation_id:
            self._active_operation_id = None
        if not audit_healthy:
            self._audit_healthy = False

    @staticmethod
    def _digest_request(request: dict[str, JsonValue]) -> str:
        encoded = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    async def authorize_protected_storage_enforcement(
        self,
        *,
        request: dict[str, JsonValue],
    ) -> tuple[MutationAuthorization, EnrolledIdentity]:
        """Authorize the narrow recovery operation that re-applies read-only flags."""

        operation_id = f"op-{secrets.token_hex(16)}"
        request_id = f"internal-{secrets.token_hex(16)}"
        request_digest = self._digest_request(request)
        async with self._state_lock:
            if not self._audit_healthy:
                raise ArchwrightError(
                    ErrorCode.AUDIT_PERSISTENCE_FAILED,
                    "new mutations are blocked after an audit persistence failure",
                )
            if self._active_operation_id is not None:
                raise ArchwrightError(
                    ErrorCode.TARGET_BUSY,
                    "another target mutation is still active",
                    details={"operation_id": self._active_operation_id},
                )
            self._active_operation_id = operation_id

        try:
            enrolled = self.enrollment_store.read()
            if enrolled is None:
                raise ArchwrightError(ErrorCode.TARGET_NOT_ENROLLED, "no target is enrolled")
            self._require_policy_binding(enrolled)
            live = await self.identity_collector.collect()
            verification = verify_identity(enrolled, live, require_protected_read_only=False)
            if not verification.passed:
                self._raise_verification_failure(verification)
            receipt = begin_receipt(
                tool="protected_storage_enforce",
                target_name=enrolled.target_name,
                target_identity_digest=enrolled.digest,
                privilege=Privilege.ROOT,
                request=request,
                operation_id=operation_id,
                request_id=request_id,
                request_digest=request_digest,
            )
            self.receipt_store.create(receipt)
        except ArchwrightError as exc:
            self._release(operation_id, exc.code is not ErrorCode.AUDIT_PERSISTENCE_FAILED)
            raise
        except BaseException:
            self._release(operation_id, True)
            raise

        authorization = MutationAuthorization(
            receipt=receipt,
            store=self.receipt_store,
            verification=verification,
            enrolled=enrolled,
            operation_id=operation_id,
            request_id=request_id,
            request_digest=request_digest,
            _release=lambda healthy: self._release(operation_id, healthy),
        )
        self._bindings[request_id] = authorization
        return authorization, enrolled

    @staticmethod
    def _raise_verification_failure(verification: VerificationResult) -> None:
        # Keep selection based on structured storage state, never message parsing.
        statuses = verification.protected_storage
        if any(not status.present for status in statuses):
            code = ErrorCode.PROTECTED_STORAGE_MISSING
        elif any(status.read_only is not True for status in statuses):
            code = ErrorCode.PROTECTED_STORAGE_WRITABLE
        elif any(status.in_use is True for status in statuses):
            code = ErrorCode.PROTECTED_STORAGE_REFUSED
        else:
            code = ErrorCode.TARGET_IDENTITY_MISMATCH
        raise ArchwrightError(
            code,
            "target verification refused mutation",
            details={"mismatches": list(verification.mismatches)},
        )
