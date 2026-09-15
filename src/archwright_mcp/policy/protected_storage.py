"""Narrow recovery path for enforcing protected block-device read-only flags."""

from __future__ import annotations

from archwright_mcp.errors import ArchwrightError, ErrorCode
from archwright_mcp.models import EnrolledIdentity, VerificationResult
from archwright_mcp.target.identity import IdentityCollector
from archwright_mcp.target.verification import verify_identity
from archwright_mcp.transport.ssh import SshTransport


class ProtectedStorageController:
    def __init__(
        self,
        transport: SshTransport,
        identity_collector: IdentityCollector,
        *,
        timeout_seconds: float = 10,
        runtime_path: str = "/usr/local/libexec/archwright-target.pyz",
    ) -> None:
        self.transport = transport
        self.identity_collector = identity_collector
        self.timeout_seconds = timeout_seconds
        self.runtime_path = runtime_path

    async def enforce(
        self,
        enrolled: EnrolledIdentity,
        preflight: VerificationResult,
    ) -> VerificationResult:
        """Re-resolve protected storage, refuse consumers, set every node read-only."""

        if not preflight.passed:
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "protected-storage enforcement requires a passing identity preflight",
            )
        boot_id = preflight.evidence.get("boot_id")
        if not isinstance(boot_id, str):
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "protected-storage preflight has no boot identity",
            )
        result = await self.transport.run(
            [
                "/usr/bin/sudo",
                "-n",
                self.runtime_path,
                "protect",
                enrolled.digest,
                boot_id,
            ],
            timeout_seconds=self.timeout_seconds,
        )
        if not result.succeeded:
            raise ArchwrightError(
                ErrorCode.PROTECTED_STORAGE_WRITABLE,
                "target helper refused protected-storage enforcement",
                details={"exit_code": result.exit_code},
            )
        postflight = verify_identity(enrolled, await self.identity_collector.collect())
        if not postflight.passed:
            raise ArchwrightError(
                ErrorCode.PROTECTED_STORAGE_WRITABLE,
                "protected disk did not verify read-only after enforcement",
                details={"mismatches": list(postflight.mismatches)},
            )
        return postflight
