from __future__ import annotations

import json
from pathlib import Path

import pytest

from archwright_mcp.errors import ArchwrightError, ErrorCode
from archwright_mcp.models import EnrolledIdentity
from archwright_mcp.target.enrollment import EnrollmentStore


def identity() -> EnrolledIdentity:
    return EnrolledIdentity(
        target_name="sager-arch",
        machine_id="machine-id",
        dmi_product_uuid="product-uuid",
        dmi_product_name="V54x_6x_TU",
        dmi_board_name="board",
        root_filesystem_uuid="root-uuid",
        root_parent_serial="25044DB50A3B",
        expected_target_serial="25044DB50A3B",
        protected_serials=("25044DB4D635",),
        ssh_host_key_fingerprints=("SHA256:temporary",),
    )


def test_enrollment_round_trip_and_no_implicit_replacement(tmp_path: Path) -> None:
    store = EnrollmentStore((tmp_path / "target.json").resolve())
    store.write(identity())
    assert store.read() == identity()
    with pytest.raises(ArchwrightError, match="already enrolled"):
        store.write(identity())


def test_enrollment_detects_content_tampering(tmp_path: Path) -> None:
    store = EnrollmentStore((tmp_path / "target.json").resolve())
    store.write(identity())
    payload = json.loads(store.path.read_text())
    payload["identity"]["machine_id"] = "other"
    store.path.write_text(json.dumps(payload))
    with pytest.raises(ArchwrightError) as captured:
        store.read()
    assert captured.value.code is ErrorCode.TARGET_IDENTITY_MISMATCH
