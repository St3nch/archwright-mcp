from __future__ import annotations

import base64
import hashlib
import json
import traceback
from pathlib import Path, PurePosixPath

import pytest

from archwright_mcp.config import ArchwrightConfig, PolicyConfig, TargetConfig
from archwright_mcp.errors import ArchwrightError, ErrorCode
from archwright_mcp.execution.commands import ExecutionController
from archwright_mcp.execution.scripts import ExecutionRequest
from archwright_mcp.models import (
    EnrolledIdentity,
    JobState,
    OperationStatus,
    OutputPolicy,
    Privilege,
    TargetEndpoint,
)
from archwright_mcp.policy.mutation import MutationGate
from archwright_mcp.receipts import ReceiptStore
from archwright_mcp.target.enrollment import known_hosts_fingerprints
from archwright_mcp.target.identity import LiveIdentity, parse_lsblk_identity
from archwright_mcp.transport.ssh import ProcessOutput
from archwright_mcp.transport.transfer import TransferResult

FIXTURE = Path(__file__).parents[2] / "fixtures" / "lsblk-sager.json"


class FakeEnrollmentStore:
    def __init__(self, value: EnrolledIdentity) -> None:
        self.value = value

    def read(self) -> EnrolledIdentity:
        return self.value


class FakeCollector:
    def __init__(self, value: LiveIdentity) -> None:
        self.value = value

    async def collect(self) -> LiveIdentity:
        return self.value


class FakeTransfer:
    def __init__(self) -> None:
        self.uploads: list[tuple[PurePosixPath, bytes]] = []

    async def upload_bytes(
        self,
        content: bytes,
        remote_path: PurePosixPath,
        *,
        timeout_seconds: float = 60,
        maximum_bytes: int = 64 * 1024 * 1024,
    ) -> TransferResult:
        assert len(content) <= maximum_bytes
        self.uploads.append((remote_path, content))
        return TransferResult(remote_path, hashlib.sha256(content).hexdigest(), len(content))


class FakeTransport:
    def __init__(self, *, launch_exit: int = 0, output_suppressed: bool = False) -> None:
        self.launch_exit = launch_exit
        self.output_suppressed = output_suppressed
        self.commands: list[list[str]] = []

    async def run(
        self,
        remote_argv: list[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int | None = None,
    ) -> ProcessOutput:
        self.commands.append(remote_argv)
        if "prepare" in remote_argv:
            index = remote_argv.index("prepare")
            operation = remote_argv[index + 1]
            payload = {
                "schema_version": 1,
                "state": "prepared",
                "operation_id": operation,
                "target_identity_digest": remote_argv[index + 2],
                "boot_id": remote_argv[index + 3],
            }
            return ProcessOutput(0, json.dumps(payload), "", False, False)
        operation = remote_argv[-2] if remote_argv[-3] == "launch" else remote_argv[-1]
        token = operation.removeprefix("op-")
        if "launch" in remote_argv:
            payload = {
                "state": "starting",
                "operation_id": operation,
                "job_id": f"job-{token}",
                "unit_name": f"archwright-job-{token}.service",
                "script_sha256": None,
            }
            return ProcessOutput(self.launch_exit, json.dumps(payload), "", False, False)
        payload = {
            "schema_version": 1,
            "operation_id": operation,
            "state": "succeeded",
            "exit_code": 0,
            "signal": None,
            "timed_out": False,
            "output_suppressed": self.output_suppressed,
            "stdout_b64": base64.b64encode(b"uid=0\n").decode(),
            "stderr_b64": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
        return ProcessOutput(0, json.dumps(payload), "", False, False)


def live() -> LiveIdentity:
    devices, root, parent = parse_lsblk_identity(FIXTURE.read_text())
    return LiveIdentity(
        machine_id="machine-id",
        dmi_product_uuid="product-uuid",
        dmi_product_name="V54x_6x_TU",
        dmi_board_name="board",
        hostname="sager",
        boot_id="boot-id",
        root_filesystem_uuid=root.filesystem_uuid or "",
        root_parent_serial=parent.serial or "",
        root_device_path=root.path,
        block_devices=devices,
    )


def setup_controller(
    tmp_path: Path,
    *,
    transport: FakeTransport | None = None,
    secret_resolver=None,  # type: ignore[no-untyped-def]
) -> tuple[ExecutionController, FakeTransfer, FakeTransport, ReceiptStore]:
    known_hosts = tmp_path / "known_hosts"
    key = base64.b64encode(b"test-host-key").decode()
    known_hosts.write_text(f"[127.0.0.1]:22022 ssh-ed25519 {key}\n")
    fingerprints = tuple(sorted(known_hosts_fingerprints(known_hosts)))
    enrolled = EnrolledIdentity(
        target_name="sager-arch",
        machine_id="machine-id",
        dmi_product_uuid="product-uuid",
        dmi_product_name="V54x_6x_TU",
        dmi_board_name="board",
        root_filesystem_uuid="3040811e-143c-418c-870b-5fe57b05dac3",
        root_parent_serial="25044DB50A3B",
        expected_target_serial="25044DB50A3B",
        protected_serials=("25044DB4D635",),
        ssh_host_key_fingerprints=fingerprints,
    )
    target = TargetConfig(
        name="sager-arch",
        endpoint=TargetEndpoint(
            host="127.0.0.1",
            port=22022,
            user="arch-bootstrap",
            controller_key=(tmp_path / "controller").resolve(),
            known_hosts=known_hosts.resolve(),
        ),
        expected_target_serial="25044DB50A3B",
        protected_serials=("25044DB4D635",),
    )
    config = ArchwrightConfig(
        target=target,
        policy=PolicyConfig(
            require_identity_for_mutation=True,
            require_protected_disks_read_only=True,
            receipt_dir=(tmp_path / "receipts").resolve(),
        ),
    )
    receipts = ReceiptStore(config.policy.receipt_dir)
    gate = MutationGate(
        FakeEnrollmentStore(enrolled),  # type: ignore[arg-type]
        FakeCollector(live()),  # type: ignore[arg-type]
        receipts,
        target,
    )
    fake_transport = transport or FakeTransport()
    transfer = FakeTransfer()
    controller = ExecutionController(
        config,
        gate,
        fake_transport,  # type: ignore[arg-type]
        transfer,  # type: ignore[arg-type]
        **({"secret_resolver": secret_resolver} if secret_resolver is not None else {}),
    )
    return controller, transfer, fake_transport, receipts


@pytest.mark.asyncio
async def test_execution_transfers_exact_script_and_persists_safe_receipt(
    tmp_path: Path,
) -> None:
    controller, transfer, transport, receipts = setup_controller(tmp_path)
    script = b"#!/bin/bash\nprintf '%s\\n' \"quoted $HOME\"\n"
    request = ExecutionRequest(
        request_id="request-0001",
        script=script,
        privilege=Privilege.ROOT,
    )
    # Supply the authorized script hash in the fake launch acknowledgement.
    original_run = transport.run

    async def run_with_hash(*args, **kwargs):  # type: ignore[no-untyped-def]
        output = await original_run(*args, **kwargs)
        if "launch" in args[0] and output.exit_code == 0:
            payload = json.loads(output.stdout)
            payload["script_sha256"] = request.script_sha256
            return ProcessOutput(0, json.dumps(payload), "", False, False)
        return output

    transport.run = run_with_hash  # type: ignore[method-assign]
    result = await controller.execute(request)
    assert result.state is JobState.SUCCEEDED
    assert result.stdout == "uid=0\n"
    assert transfer.uploads[0][1] == script
    assert all(script not in " ".join(command).encode() for command in transport.commands)
    receipt = receipts.read(result.handle.receipt_id)
    persisted = json.dumps(receipt.as_dict())
    assert receipt.status.value == "succeeded"
    assert script.decode() not in persisted
    assert "uid=0" not in persisted


@pytest.mark.asyncio
async def test_request_replay_returns_same_operation_without_second_launch(
    tmp_path: Path,
) -> None:
    controller, _, transport, _ = setup_controller(tmp_path)
    request = ExecutionRequest(request_id="request-0002", script=b"#!/bin/bash\ntrue\n")
    original_run = transport.run

    async def run_with_hash(*args, **kwargs):  # type: ignore[no-untyped-def]
        output = await original_run(*args, **kwargs)
        if "launch" in args[0]:
            payload = json.loads(output.stdout)
            payload["script_sha256"] = request.script_sha256
            return ProcessOutput(0, json.dumps(payload), "", False, False)
        return output

    transport.run = run_with_hash  # type: ignore[method-assign]
    first = await controller.execute(request)
    count = len(transport.commands)
    second = await controller.execute(request)
    assert second.handle.operation_id == first.handle.operation_id
    assert len(transport.commands) == count


@pytest.mark.asyncio
async def test_obvious_protected_disk_root_command_is_refused_before_transfer(
    tmp_path: Path,
) -> None:
    controller, transfer, transport, _ = setup_controller(tmp_path)
    request = ExecutionRequest(
        request_id="request-0003",
        script=b"#!/bin/bash\nwipefs -a /dev/nvme0n1\n",
        privilege=Privilege.ROOT,
    )
    with pytest.raises(ArchwrightError) as captured:
        await controller.execute(request)
    assert captured.value.code is ErrorCode.PROTECTED_STORAGE_REFUSED
    assert transfer.uploads == []
    assert transport.commands == []


@pytest.mark.asyncio
async def test_secret_execution_suppresses_output_and_receipt_material(
    tmp_path: Path,
) -> None:
    transport = FakeTransport(output_suppressed=True)
    controller, transfer, _, receipts = setup_controller(
        tmp_path,
        transport=transport,
        secret_resolver=lambda reference: "secret-sentinel",
    )
    request = ExecutionRequest(
        request_id="request-0004",
        script=b"#!/bin/bash\nprintf '%s' \"$API_TOKEN\"\n",
        secret_environment=(("API_TOKEN", "operator/token"),),
        output_policy=OutputPolicy.CAPTURE,
    )
    original_run = transport.run

    async def run_with_hash(*args, **kwargs):  # type: ignore[no-untyped-def]
        output = await original_run(*args, **kwargs)
        if "launch" in args[0]:
            payload = json.loads(output.stdout)
            payload["script_sha256"] = request.script_sha256
            return ProcessOutput(0, json.dumps(payload), "", False, False)
        return output

    transport.run = run_with_hash  # type: ignore[method-assign]
    result = await controller.execute(request)
    assert result.stdout == ""
    receipt_text = receipts.read(result.handle.receipt_id).as_dict()
    assert "secret-sentinel" not in json.dumps(receipt_text)
    manifest = next(content for path, content in transfer.uploads if path.suffix == ".json")
    assert b"secret-sentinel" in manifest


@pytest.mark.asyncio
async def test_lost_launch_acknowledgement_records_uncertainty(tmp_path: Path) -> None:
    controller, _, _, receipts = setup_controller(
        tmp_path, transport=FakeTransport(launch_exit=255)
    )
    result = await controller.execute(
        ExecutionRequest(request_id="request-0005", script=b"#!/bin/bash\ntrue\n")
    )
    assert result.state is JobState.UNCERTAIN
    assert result.uncertain is True
    assert receipts.read(result.handle.receipt_id).status.value == "uncertain"


@pytest.mark.asyncio
async def test_secret_resolver_failure_is_sanitized_and_finishes_intent(tmp_path: Path) -> None:
    controller, transfer, _, receipts = setup_controller(
        tmp_path,
        secret_resolver=lambda reference: (_ for _ in ()).throw(
            RuntimeError("secret-sentinel must not escape")
        ),
    )
    request = ExecutionRequest(
        request_id="request-0006",
        script=b"#!/bin/bash\ntrue\n",
        secret_environment=(("API_TOKEN", "operator/token"),),
    )
    with pytest.raises(ArchwrightError) as captured:
        await controller.execute(request)
    assert "secret-sentinel" not in str(captured.value)
    assert "secret-sentinel" not in "".join(traceback.format_exception(captured.value))
    assert captured.value.__context__ is None
    assert transfer.uploads == []
    receipt_files = tuple(tmp_path.joinpath("receipts").rglob("*.json"))
    assert len(receipt_files) == 1
    receipt = receipts.read(json.loads(receipt_files[0].read_text())["receipt_id"])
    assert receipt.status is OperationStatus.FAILED


@pytest.mark.asyncio
async def test_terminal_receipt_failure_returns_uncertainty_and_latches_gate(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    controller, _, transport, receipts = setup_controller(tmp_path)
    request = ExecutionRequest(request_id="request-0007", script=b"#!/bin/bash\ntrue\n")
    original_run = transport.run

    async def run_with_hash(*args, **kwargs):  # type: ignore[no-untyped-def]
        output = await original_run(*args, **kwargs)
        if "launch" in args[0]:
            payload = json.loads(output.stdout)
            payload["script_sha256"] = request.script_sha256
            return ProcessOutput(0, json.dumps(payload), "", False, False)
        return output

    transport.run = run_with_hash  # type: ignore[method-assign]
    original_replace = receipts.replace
    replacements = 0

    def fail_terminal(receipt):  # type: ignore[no-untyped-def]
        nonlocal replacements
        replacements += 1
        if replacements == 2:
            raise ArchwrightError(ErrorCode.AUDIT_PERSISTENCE_FAILED, "injected failure")
        return original_replace(receipt)

    monkeypatch.setattr(receipts, "replace", fail_terminal)
    with pytest.raises(ArchwrightError) as captured:
        await controller.execute(request)
    assert captured.value.code is ErrorCode.OPERATION_UNCERTAIN

    with pytest.raises(ArchwrightError) as blocked:
        await controller.execute(
            ExecutionRequest(request_id="request-0008", script=b"#!/bin/bash\ntrue\n")
        )
    assert blocked.value.code is ErrorCode.AUDIT_PERSISTENCE_FAILED


@pytest.mark.asyncio
async def test_lost_acknowledgement_keeps_other_mutations_blocked(tmp_path: Path) -> None:
    controller, _, _, _ = setup_controller(tmp_path, transport=FakeTransport(launch_exit=255))
    result = await controller.execute(
        ExecutionRequest(request_id="request-0009", script=b"#!/bin/bash\ntrue\n")
    )
    assert result.state is JobState.UNCERTAIN
    with pytest.raises(ArchwrightError) as blocked:
        await controller.execute(
            ExecutionRequest(request_id="request-0010", script=b"#!/bin/bash\ntrue\n")
        )
    assert blocked.value.code is ErrorCode.TARGET_BUSY


def test_capture_budget_fits_status_transport_envelope(tmp_path: Path) -> None:
    controller, _, _, _ = setup_controller(tmp_path)
    retained = b"x" * controller._capture_limit_bytes()
    payload = {
        "schema_version": 1,
        "operation_id": "op-" + "a" * 32,
        "state": "succeeded",
        "exit_code": 0,
        "signal": None,
        "timed_out": False,
        "output_suppressed": False,
        "stdout_b64": base64.b64encode(retained).decode(),
        "stderr_b64": base64.b64encode(retained).decode(),
        "stdout_truncated": True,
        "stderr_truncated": True,
        "script_sha256": "b" * 64,
    }
    assert len(json.dumps(payload, separators=(",", ":")).encode()) < 65_536
