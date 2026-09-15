from __future__ import annotations

import json
from pathlib import Path

import pytest

from archwright_mcp.config import TargetConfig
from archwright_mcp.errors import ArchwrightError, ErrorCode
from archwright_mcp.models import (
    EnrolledIdentity,
    OperationStatus,
    Privilege,
    TargetEndpoint,
)
from archwright_mcp.policy.mutation import MutationGate
from archwright_mcp.receipts import ReceiptStore
from archwright_mcp.target.identity import LiveIdentity, parse_lsblk_identity

FIXTURE = Path(__file__).parents[2] / "fixtures" / "lsblk-sager.json"


def enrollment() -> EnrolledIdentity:
    return EnrolledIdentity(
        target_name="sager-arch",
        machine_id="machine-id",
        dmi_product_uuid="product-uuid",
        dmi_product_name="V54x_6x_TU",
        dmi_board_name="board",
        root_filesystem_uuid="3040811e-143c-418c-870b-5fe57b05dac3",
        root_parent_serial="25044DB50A3B",
        expected_target_serial="25044DB50A3B",
        protected_serials=("25044DB4D635",),
        ssh_host_key_fingerprints=("SHA256:temporary",),
    )


def live(payload: str | None = None) -> LiveIdentity:
    devices, root, parent = parse_lsblk_identity(payload or FIXTURE.read_text())
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


class FakeEnrollmentStore:
    def __init__(self, value: EnrolledIdentity | None) -> None:
        self.value = value

    def read(self) -> EnrolledIdentity | None:
        return self.value


class FakeCollector:
    def __init__(self, value: LiveIdentity) -> None:
        self.value = value

    async def collect(self) -> LiveIdentity:
        return self.value


@pytest.mark.asyncio
async def test_gate_verifies_and_persists_redacted_intent_before_authorizing(
    tmp_path: Path,
) -> None:
    receipts = ReceiptStore(tmp_path.resolve())
    gate = MutationGate(
        FakeEnrollmentStore(enrollment()),  # type: ignore[arg-type]
        FakeCollector(live()),  # type: ignore[arg-type]
        receipts,
    )
    authorization = await gate.authorize(
        tool="wifi_connect",
        privilege=Privilege.ROOT,
        request={"ssid": "Lab", "psk": "never-write-this"},
    )
    persisted = receipts.read(authorization.receipt.receipt_id)
    assert persisted.request["ssid"] == "Lab"
    assert persisted.request["psk"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_gate_classifies_missing_protected_disk(tmp_path: Path) -> None:
    raw = json.loads(FIXTURE.read_text())
    raw["blockdevices"] = raw["blockdevices"][:1]
    gate = MutationGate(
        FakeEnrollmentStore(enrollment()),  # type: ignore[arg-type]
        FakeCollector(live(json.dumps(raw))),  # type: ignore[arg-type]
        ReceiptStore(tmp_path.resolve()),
    )
    with pytest.raises(ArchwrightError) as captured:
        await gate.authorize(tool="run_root", privilege=Privilege.ROOT, request={})
    assert captured.value.code is ErrorCode.PROTECTED_STORAGE_MISSING


@pytest.mark.asyncio
async def test_gate_classifies_writable_protected_disk(tmp_path: Path) -> None:
    writable = FIXTURE.read_text().replace('"ro": true', '"ro": false')
    gate = MutationGate(
        FakeEnrollmentStore(enrollment()),  # type: ignore[arg-type]
        FakeCollector(live(writable)),  # type: ignore[arg-type]
        ReceiptStore(tmp_path.resolve()),
    )
    with pytest.raises(ArchwrightError) as captured:
        await gate.authorize(tool="run_root", privilege=Privilege.ROOT, request={})
    assert captured.value.code is ErrorCode.PROTECTED_STORAGE_WRITABLE


@pytest.mark.asyncio
async def test_narrow_recovery_gate_allows_only_read_only_enforcement(tmp_path: Path) -> None:
    writable = FIXTURE.read_text().replace('"ro": true', '"ro": false')
    gate = MutationGate(
        FakeEnrollmentStore(enrollment()),  # type: ignore[arg-type]
        FakeCollector(live(writable)),  # type: ignore[arg-type]
        ReceiptStore(tmp_path.resolve()),
    )
    authorization, enrolled = await gate.authorize_protected_storage_enforcement(request={})
    assert authorization.receipt.tool == "protected_storage_enforce"
    assert authorization.receipt.operation_id == authorization.operation_id
    assert authorization.verification.protected_storage[0].read_only is False
    assert enrolled == enrollment()
    authorization.finish(status=OperationStatus.SUCCEEDED, result={"effect_state": "confirmed"})


@pytest.mark.asyncio
async def test_audit_create_failure_latches_gate_closed(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    receipts = ReceiptStore(tmp_path.resolve())
    gate = MutationGate(
        FakeEnrollmentStore(enrollment()),  # type: ignore[arg-type]
        FakeCollector(live()),  # type: ignore[arg-type]
        receipts,
    )

    def fail_create(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise ArchwrightError(ErrorCode.AUDIT_PERSISTENCE_FAILED, "injected failure")

    monkeypatch.setattr(receipts, "create", fail_create)
    with pytest.raises(ArchwrightError) as first:
        await gate.authorize(tool="execute", privilege=Privilege.ROOT, request={})
    assert first.value.code is ErrorCode.AUDIT_PERSISTENCE_FAILED

    with pytest.raises(ArchwrightError, match="blocked after") as second:
        await gate.authorize(tool="execute", privilege=Privilege.ROOT, request={})
    assert second.value.code is ErrorCode.AUDIT_PERSISTENCE_FAILED


@pytest.mark.asyncio
async def test_gate_refuses_enrollment_that_disagrees_with_host_pins(tmp_path: Path) -> None:
    known_hosts = (tmp_path / "known_hosts").resolve()
    known_hosts.write_text("[127.0.0.1]:22022 ssh-ed25519 dGVzdC1ob3N0LWtleQ==\n")
    target = TargetConfig(
        name="sager-arch",
        endpoint=TargetEndpoint(
            host="127.0.0.1",
            port=22022,
            user="arch-bootstrap",
            controller_key=(tmp_path / "controller").resolve(),
            known_hosts=known_hosts,
        ),
        expected_target_serial="25044DB50A3B",
        protected_serials=("25044DB4D635",),
    )
    gate = MutationGate(
        FakeEnrollmentStore(enrollment()),  # type: ignore[arg-type]
        FakeCollector(live()),  # type: ignore[arg-type]
        ReceiptStore((tmp_path / "receipts").resolve()),
        target,
    )
    with pytest.raises(ArchwrightError) as captured:
        await gate.authorize(tool="execute", privilege=Privilege.ROOT, request={})
    assert captured.value.code is ErrorCode.TARGET_HOSTKEY_MISMATCH


@pytest.mark.asyncio
async def test_request_id_replay_and_conflict_are_bound_to_digest(tmp_path: Path) -> None:
    gate = MutationGate(
        FakeEnrollmentStore(enrollment()),  # type: ignore[arg-type]
        FakeCollector(live()),  # type: ignore[arg-type]
        ReceiptStore(tmp_path.resolve()),
    )
    first = await gate.authorize(
        tool="execute",
        privilege=Privilege.USER,
        request={"script_sha256": "a" * 64},
        request_id="request-0001",
        request_digest="b" * 64,
    )
    replay = await gate.authorize(
        tool="execute",
        privilege=Privilege.USER,
        request={"script_sha256": "a" * 64},
        request_id="request-0001",
        request_digest="b" * 64,
    )
    assert replay.is_replay is True
    assert replay.operation_id == first.operation_id
    with pytest.raises(ArchwrightError) as captured:
        await gate.authorize(
            tool="execute",
            privilege=Privilege.USER,
            request={"script_sha256": "c" * 64},
            request_id="request-0001",
            request_digest="d" * 64,
        )
    assert captured.value.code is ErrorCode.REQUEST_ID_CONFLICT
    first.finish(status=OperationStatus.SUCCEEDED, result={"effect_state": "confirmed"})


@pytest.mark.asyncio
async def test_gate_refuses_second_active_mutation_and_authorization_reuse(
    tmp_path: Path,
) -> None:
    gate = MutationGate(
        FakeEnrollmentStore(enrollment()),  # type: ignore[arg-type]
        FakeCollector(live()),  # type: ignore[arg-type]
        ReceiptStore(tmp_path.resolve()),
    )
    first = await gate.authorize(
        tool="execute",
        privilege=Privilege.ROOT,
        request={},
        request_id="request-0002",
        request_digest="e" * 64,
    )
    with pytest.raises(ArchwrightError) as captured:
        await gate.authorize(
            tool="execute",
            privilege=Privilege.ROOT,
            request={},
            request_id="request-0003",
            request_digest="f" * 64,
        )
    assert captured.value.code is ErrorCode.TARGET_BUSY
    first.claim(request_digest="e" * 64, boot_id="boot-id")
    with pytest.raises(ArchwrightError) as reused:
        first.claim(request_digest="e" * 64, boot_id="boot-id")
    assert reused.value.code is ErrorCode.OPERATION_UNCERTAIN
