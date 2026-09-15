from __future__ import annotations

from datetime import UTC, datetime

import pytest

from archwright_mcp.errors import ValidationError
from archwright_mcp.models import (
    EnrolledIdentity,
    JsonValue,
    OperationReceipt,
    OperationStatus,
    Privilege,
    VerificationResult,
)


def enrolled_identity() -> EnrolledIdentity:
    return EnrolledIdentity(
        target_name="sager-arch",
        machine_id="machine-id",
        dmi_product_uuid="dmi-uuid",
        dmi_product_name="V54x_6x_TU",
        dmi_board_name="board",
        root_filesystem_uuid="root-uuid",
        root_parent_serial="25044DB50A3B",
        expected_target_serial="25044DB50A3B",
        protected_serials=("25044DB4D635",),
        ssh_host_key_fingerprints=("SHA256:temporary",),
    )


def test_identity_digest_is_deterministic() -> None:
    assert enrolled_identity().digest == enrolled_identity().digest
    assert len(enrolled_identity().digest) == 64


def test_identity_rejects_root_on_protected_serial() -> None:
    identity = enrolled_identity()
    with pytest.raises(ValidationError, match="does not match"):
        EnrolledIdentity(
            target_name=identity.target_name,
            machine_id=identity.machine_id,
            dmi_product_uuid=identity.dmi_product_uuid,
            dmi_product_name=identity.dmi_product_name,
            dmi_board_name=identity.dmi_board_name,
            root_filesystem_uuid=identity.root_filesystem_uuid,
            root_parent_serial="25044DB4D635",
            expected_target_serial=identity.expected_target_serial,
            protected_serials=identity.protected_serials,
            ssh_host_key_fingerprints=identity.ssh_host_key_fingerprints,
        )


def test_passing_verification_requires_digest() -> None:
    with pytest.raises(ValidationError, match="identity digest"):
        VerificationResult(passed=True, checked_at=datetime.now(UTC), identity_digest=None)


def test_receipt_round_trip() -> None:
    started = datetime(2026, 9, 14, 22, 30, tzinfo=UTC)
    receipt = OperationReceipt(
        receipt_id="aw-20260914T223000Z-0123456789abcdef01234567",
        tool="run_root",
        target_name="sager-arch",
        target_identity_digest="a" * 64,
        privilege=Privilege.ROOT,
        request={"script_sha256": "b" * 64},
        started_at=started,
        finished_at=started,
        status=OperationStatus.SUCCEEDED,
        result={"exit_code": 0},
    )
    assert OperationReceipt.from_dict(receipt.as_dict()) == receipt


def test_terminal_receipt_requires_finish_time() -> None:
    with pytest.raises(ValidationError, match="finish time"):
        OperationReceipt(
            receipt_id="aw-20260914T223000Z-0123456789abcdef01234567",
            tool="run_root",
            target_name="sager-arch",
            target_identity_digest="a" * 64,
            privilege=Privilege.ROOT,
            request={},
            started_at=datetime(2026, 9, 14, 22, 30, tzinfo=UTC),
            status=OperationStatus.FAILED,
        )


def test_receipt_parser_normalizes_unknown_enum_to_validation_error() -> None:
    receipt: dict[str, JsonValue] = {
        "receipt_id": "aw-20260914T223000Z-0123456789abcdef01234567",
        "tool": "run_root",
        "target_name": "sager-arch",
        "target_identity_digest": "a" * 64,
        "privilege": "demigod",
        "request": {},
        "started_at": "2026-09-14T22:30:00Z",
        "finished_at": None,
        "status": "pending",
        "result": {},
        "artifact_refs": [],
        "job_id": None,
        "reboot_id": None,
    }
    with pytest.raises(ValidationError, match="unknown enum"):
        OperationReceipt.from_dict(receipt)
