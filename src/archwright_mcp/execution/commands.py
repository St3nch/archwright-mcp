"""Controller flow for verified, transferred, systemd-supervised execution."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

from archwright_mcp.config import ArchwrightConfig
from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.execution.scripts import ExecutionRequest, PreparedScript
from archwright_mcp.models import (
    ExecutionHandle,
    ExecutionResult,
    JobState,
    JsonValue,
    OperationStatus,
    Privilege,
)
from archwright_mcp.policy.command_preflight import preflight_root_script
from archwright_mcp.policy.mutation import MutationAuthorization, MutationGate
from archwright_mcp.transport.ssh import ProcessOutput, SshTransport
from archwright_mcp.transport.transfer import VerifiedTransfer

SecretResolver = Callable[[str], str]


def _refuse_secret(_: str) -> str:
    raise ValidationError("secret references require an operator-configured resolver")


class ExecutionController:
    """Submit one exact script without embedding it in shell or SSH command text."""

    def __init__(
        self,
        config: ArchwrightConfig,
        gate: MutationGate,
        transport: SshTransport,
        transfer: VerifiedTransfer,
        *,
        secret_resolver: SecretResolver = _refuse_secret,
    ) -> None:
        if gate.target_config != config.target:
            raise ValidationError("execution requires a configuration-bound mutation gate")
        self.config = config
        self.gate = gate
        self.transport = transport
        self.transfer = transfer
        self.secret_resolver = secret_resolver
        self._results_by_request: dict[str, ExecutionResult] = {}

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        request.validate(self.config.policy)
        request_digest = request.normalized_digest()
        authorization = await self.gate.authorize(
            tool="execute",
            privilege=request.privilege,
            request=request.receipt_request(),
            request_id=request.request_id,
            request_digest=request_digest,
        )
        if authorization.is_replay:
            prior = self._results_by_request.get(request.request_id)
            if prior is not None:
                return prior
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "request already exists but its execution result requires reconciliation",
                details={
                    "operation_id": authorization.operation_id,
                    "receipt_id": authorization.receipt.receipt_id,
                },
            )

        staging_possible = False
        try:
            prepared = PreparedScript.from_request(request, authorization.operation_id)
            self._preflight_root_request(request, authorization)
            boot_id = authorization.verification.evidence.get("boot_id")
            if not isinstance(boot_id, str):
                raise ArchwrightError(
                    ErrorCode.TARGET_IDENTITY_MISMATCH,
                    "authorized identity evidence has no boot ID",
                )
            staging_possible = True
            staging = await self.transport.run(
                [
                    "/usr/bin/sudo",
                    "-n",
                    self.config.policy.target_runtime_path,
                    "prepare",
                    authorization.operation_id,
                    authorization.enrolled.digest,
                    boot_id,
                ],
                timeout_seconds=min(request.wait_seconds, 30),
            )
            self._validate_prepare(staging, authorization, boot_id)
            manifest = self._manifest(request, prepared, authorization)
            manifest_bytes = (
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            )
            manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
            script_path = PurePosixPath(
                f"/var/lib/archwright/uploads/{authorization.operation_id}/script"
            )
            manifest_path = PurePosixPath(
                f"/var/lib/archwright/uploads/{authorization.operation_id}/request.json"
            )
            await self.transfer.upload_bytes(
                prepared.content,
                script_path,
                timeout_seconds=min(request.wait_seconds, 60),
                maximum_bytes=self.config.policy.max_script_bytes,
            )
            await self.transfer.upload_bytes(
                manifest_bytes,
                manifest_path,
                timeout_seconds=min(request.wait_seconds, 60),
                maximum_bytes=min(self.config.policy.max_transfer_bytes, 256 * 1024),
            )
        except BaseException as exc:
            if authorization.receipt.status in {
                OperationStatus.PENDING,
                OperationStatus.RUNNING,
            }:
                self._finish_prelaunch_failure(
                    authorization,
                    exc,
                    effect_state="staging_possible" if staging_possible else "none",
                )
            raise

        authorization.claim(request_digest=request_digest, boot_id=boot_id)
        try:
            launch = await self.transport.run(
                [
                    "/usr/bin/sudo",
                    "-n",
                    self.config.policy.target_runtime_path,
                    "launch",
                    authorization.operation_id,
                    manifest_digest,
                ],
                timeout_seconds=min(request.wait_seconds, 30),
            )
        except asyncio.CancelledError:
            self._persist_uncertain(authorization)
            raise
        except ArchwrightError as exc:
            self._persist_uncertain(authorization)
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "target launch may have occurred but acknowledgement was lost",
                details={
                    "operation_id": authorization.operation_id,
                    "receipt_id": authorization.receipt.receipt_id,
                },
            ) from exc
        if not launch.succeeded:
            return self._uncertain_launch(request, authorization, launch)
        try:
            handle = self._parse_handle(launch, authorization, prepared)
        except ArchwrightError:
            self._persist_uncertain(authorization)
            raise
        try:
            authorization.mark_running(
                job_id=handle.job_id,
                artifact_refs=(prepared.artifact_id,),
            )
        except ArchwrightError as exc:
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "execution launched but running-state audit persistence failed",
                details={
                    "operation_id": handle.operation_id,
                    "receipt_id": handle.receipt_id,
                    "job_id": handle.job_id,
                },
            ) from exc
        deadline = asyncio.get_running_loop().time() + request.wait_seconds
        while True:
            try:
                status = await self._status(handle)
            except ArchwrightError:
                self._persist_uncertain(authorization)
                result = ExecutionResult(handle=handle, state=JobState.UNCERTAIN, uncertain=True)
                self._results_by_request[request.request_id] = result
                return result
            if status.state not in {JobState.STARTING, JobState.RUNNING}:
                try:
                    result = self._finish_terminal(request, authorization, status)
                except ArchwrightError as exc:
                    raise ArchwrightError(
                        ErrorCode.OPERATION_UNCERTAIN,
                        "execution finished but terminal audit persistence failed",
                        details={
                            "operation_id": handle.operation_id,
                            "receipt_id": handle.receipt_id,
                            "job_id": handle.job_id,
                        },
                    ) from exc
                self._results_by_request[request.request_id] = result
                return result
            if asyncio.get_running_loop().time() >= deadline:
                running = ExecutionResult(handle=handle, state=status.state)
                self._results_by_request[request.request_id] = running
                return running
            await asyncio.sleep(0.1)

    def _manifest(
        self,
        request: ExecutionRequest,
        prepared: PreparedScript,
        authorization: MutationAuthorization,
    ) -> dict[str, Any]:
        resolved = dict(request.environment)
        for name, reference in request.secret_environment:
            resolution_failed = False
            try:
                value = self.secret_resolver(reference)
            except BaseException:
                resolution_failed = True
                value = ""
            if resolution_failed:
                raise ValidationError("unable to resolve an execution secret reference")
            if not isinstance(value, str):
                raise ValidationError("execution secret resolver returned an invalid value")
            if "\x00" in value:
                raise ValidationError("resolved secret contains NUL")
            if len(value.encode()) > 65_536:
                raise ValidationError("resolved secret exceeds its size limit")
            resolved[name] = value
        boot_id = authorization.verification.evidence.get("boot_id")
        if not isinstance(boot_id, str):
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "authorized identity evidence has no boot ID",
            )
        return {
            "schema_version": 1,
            "operation_id": authorization.operation_id,
            "request_id": request.request_id,
            "request_digest": request.normalized_digest(),
            "target_identity_digest": authorization.enrolled.digest,
            "boot_id": boot_id,
            "script_sha256": prepared.sha256,
            "script_size": prepared.size_bytes,
            "interpreter": request.interpreter,
            "arguments": list(request.arguments),
            "privilege": request.privilege.value,
            "user": request.user,
            "working_directory": request.working_directory,
            "resolved_environment": resolved,
            "timeout_seconds": request.timeout_seconds,
            "output_limit_bytes": self._capture_limit_bytes(),
            "output_policy": request.effective_output_policy.value,
        }

    def _capture_limit_bytes(self) -> int:
        """Budget two base64 streams plus JSON inside the SSH response ceiling."""

        envelope = self.config.policy.output_limit_bytes
        metadata_reserve = 768
        raw_per_stream = max(1, ((envelope - metadata_reserve) * 3) // 8 - 3)
        return min(raw_per_stream, self.config.policy.max_retained_output_bytes, 65_536)

    def _validate_prepare(
        self,
        output: ProcessOutput,
        authorization: MutationAuthorization,
        boot_id: str,
    ) -> None:
        if not output.succeeded:
            raise ArchwrightError(
                ErrorCode.TARGET_IDENTITY_MISMATCH,
                "target refused private staging preparation",
                details={"exit_code": output.exit_code},
            )
        value = self._parse_json(output)
        if (
            value.get("state") != "prepared"
            or value.get("operation_id") != authorization.operation_id
            or value.get("target_identity_digest") != authorization.enrolled.digest
            or value.get("boot_id") != boot_id
        ):
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "target staging acknowledgement did not match its authorization",
            )

    @staticmethod
    def _preflight_root_request(
        request: ExecutionRequest, authorization: MutationAuthorization
    ) -> None:
        if request.privilege is not Privilege.ROOT:
            return
        try:
            text = request.script.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return
        paths = tuple(
            PurePosixPath(item.device_path)
            for item in authorization.verification.protected_storage
            if item.device_path is not None
        )
        result = preflight_root_script(
            text,
            protected_serials=authorization.enrolled.protected_serials,
            protected_paths=paths,
        )
        if not result.allowed:
            authorization.finish(
                status=OperationStatus.FAILED,
                result={"effect_state": "none", "failure": "protected_storage_preflight"},
            )
            raise ArchwrightError(
                ErrorCode.PROTECTED_STORAGE_REFUSED,
                "root execution names protected storage in an obviously destructive command",
                details={"findings": list(result.findings)},
            )

    @staticmethod
    def _finish_prelaunch_failure(
        authorization: MutationAuthorization,
        failure: BaseException | None,
        *,
        effect_state: str = "none",
    ) -> None:
        code = failure.code.value if isinstance(failure, ArchwrightError) else "PRELAUNCH_FAILURE"
        authorization.finish(
            status=OperationStatus.FAILED,
            result={"effect_state": effect_state, "failure_code": code},
        )

    def _uncertain_launch(
        self,
        request: ExecutionRequest,
        authorization: MutationAuthorization,
        output: ProcessOutput,
    ) -> ExecutionResult:
        self._persist_uncertain(authorization)
        token = authorization.operation_id.removeprefix("op-")
        handle = ExecutionHandle(
            operation_id=authorization.operation_id,
            receipt_id=authorization.receipt.receipt_id,
            job_id=f"job-{token}",
            unit_name=f"archwright-job-{token}.service",
            target_identity_digest=authorization.enrolled.digest,
            boot_id=str(authorization.verification.evidence["boot_id"]),
        )
        result = ExecutionResult(handle=handle, state=JobState.UNCERTAIN, uncertain=True)
        self._results_by_request[request.request_id] = result
        return result

    @staticmethod
    def _persist_uncertain(authorization: MutationAuthorization) -> None:
        try:
            authorization.finish(
                status=OperationStatus.UNCERTAIN,
                result={
                    "effect_state": "possible",
                    "failure_code": "LAUNCH_ACKNOWLEDGEMENT_LOST",
                },
            )
        except ArchwrightError as exc:
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "execution outcome and final audit persistence are uncertain",
                details={
                    "operation_id": authorization.operation_id,
                    "receipt_id": authorization.receipt.receipt_id,
                },
            ) from exc

    @staticmethod
    def _parse_json(output: ProcessOutput) -> dict[str, Any]:
        if output.stdout_truncated:
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "target runtime response exceeded its controller bound",
            )
        try:
            value = json.loads(output.stdout)
        except json.JSONDecodeError as exc:
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "target runtime response was malformed",
            ) from exc
        if not isinstance(value, dict):
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "target runtime response was not an object",
            )
        return value

    def _parse_handle(
        self,
        output: ProcessOutput,
        authorization: MutationAuthorization,
        prepared: PreparedScript,
    ) -> ExecutionHandle:
        value = self._parse_json(output)
        token = authorization.operation_id.removeprefix("op-")
        expected_job = f"job-{token}"
        expected_unit = f"archwright-job-{token}.service"
        if (
            value.get("operation_id") != authorization.operation_id
            or value.get("job_id") != expected_job
            or value.get("unit_name") != expected_unit
            or value.get("script_sha256") != prepared.sha256
        ):
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "target launch acknowledgement did not match the authorized operation",
            )
        boot_id = authorization.verification.evidence["boot_id"]
        if not isinstance(boot_id, str):
            raise AssertionError("authorization boot ID was previously validated")
        return ExecutionHandle(
            operation_id=authorization.operation_id,
            receipt_id=authorization.receipt.receipt_id,
            job_id=expected_job,
            unit_name=expected_unit,
            target_identity_digest=authorization.enrolled.digest,
            boot_id=boot_id,
        )

    async def _status(self, handle: ExecutionHandle) -> ExecutionResult:
        output = await self.transport.run(
            [
                "/usr/bin/sudo",
                "-n",
                self.config.policy.target_runtime_path,
                "status",
                handle.operation_id,
            ],
            timeout_seconds=min(self.config.policy.connect_timeout_seconds, 10),
        )
        if not output.succeeded:
            return ExecutionResult(handle=handle, state=JobState.UNCERTAIN, uncertain=True)
        value = self._parse_json(output)
        raw_state = value.get("state")
        state_map = {
            "starting": JobState.STARTING,
            "running": JobState.RUNNING,
            "succeeded": JobState.SUCCEEDED,
            "failed": JobState.FAILED,
            "timed_out": JobState.TIMED_OUT,
            "unknown": JobState.UNCERTAIN,
        }
        state = state_map.get(raw_state if isinstance(raw_state, str) else "", JobState.UNCERTAIN)
        try:
            stdout = base64.b64decode(str(value.get("stdout_b64", "")), validate=True)
            stderr = base64.b64decode(str(value.get("stderr_b64", "")), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ArchwrightError(
                ErrorCode.OPERATION_UNCERTAIN,
                "target execution output encoding was malformed",
            ) from exc
        if (
            len(stdout) > self.config.policy.max_retained_output_bytes
            or len(stderr) > self.config.policy.max_retained_output_bytes
        ):
            raise ArchwrightError(
                ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                "target execution output exceeded its authorized bound",
            )
        suppressed = value.get("output_suppressed") is True
        return ExecutionResult(
            handle=handle,
            state=state,
            exit_code=(
                value.get("exit_code")
                if isinstance(value.get("exit_code"), int)
                and not isinstance(value.get("exit_code"), bool)
                else None
            ),
            signal=(
                value.get("signal")
                if isinstance(value.get("signal"), int)
                and not isinstance(value.get("signal"), bool)
                else None
            ),
            timed_out=value.get("timed_out") is True,
            uncertain=state is JobState.UNCERTAIN,
            stdout="" if suppressed else stdout.decode("utf-8", errors="replace"),
            stderr="" if suppressed else stderr.decode("utf-8", errors="replace"),
            stdout_truncated=value.get("stdout_truncated") is True,
            stderr_truncated=value.get("stderr_truncated") is True,
        )

    @staticmethod
    def _finish_terminal(
        request: ExecutionRequest,
        authorization: MutationAuthorization,
        result: ExecutionResult,
    ) -> ExecutionResult:
        status = (
            OperationStatus.SUCCEEDED
            if result.state is JobState.SUCCEEDED
            else OperationStatus.UNCERTAIN
            if result.state is JobState.UNCERTAIN
            else OperationStatus.FAILED
        )
        safe_result: dict[str, JsonValue] = {
            "effect_state": "confirmed" if status is not OperationStatus.UNCERTAIN else "possible",
            "state": result.state.value,
            "exit_code": result.exit_code,
            "signal": result.signal,
            "timed_out": result.timed_out,
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "output_suppressed": request.effective_output_policy.value == "discard",
        }
        authorization.finish(status=status, result=safe_result)
        return result
