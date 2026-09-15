from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta

import pytest

from archwright_mcp.errors import ArchwrightError, ValidationError
from archwright_mcp.models import OperationStatus, Privilege
from archwright_mcp.receipts import ReceiptStore, begin_receipt, finish_receipt


def test_receipt_create_finish_replace_round_trip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    now = datetime(2026, 9, 14, 22, 30, tzinfo=UTC)
    receipt = begin_receipt(
        tool="wifi_connect",
        target_name="sager-arch",
        target_identity_digest="a" * 64,
        privilege=Privilege.ROOT,
        request={"ssid": "Lab", "psk": "do-not-store"},
        now=now,
    )
    store = ReceiptStore(tmp_path.resolve())
    path = store.create(receipt)
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "do-not-store" not in path.read_text()

    finished = finish_receipt(
        receipt,
        status=OperationStatus.SUCCEEDED,
        result={"connected": True},
        now=now + timedelta(seconds=2),
    )
    store.replace(finished)
    assert store.read(receipt.receipt_id) == finished


def test_create_refuses_duplicate_receipt(tmp_path) -> None:  # type: ignore[no-untyped-def]
    receipt = begin_receipt(
        tool="run",
        target_name="sager-arch",
        target_identity_digest="a" * 64,
        privilege=Privilege.USER,
        request={},
    )
    store = ReceiptStore(tmp_path.resolve())
    store.create(receipt)
    with pytest.raises(ArchwrightError, match="already exists"):
        store.create(receipt)


def test_read_refuses_path_traversal(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = ReceiptStore(tmp_path.resolve())
    with pytest.raises(ValidationError, match="invalid receipt ID"):
        store.read("../../etc/passwd")


def test_receipt_is_valid_json(tmp_path) -> None:  # type: ignore[no-untyped-def]
    receipt = begin_receipt(
        tool="target_enroll",
        target_name="sager-arch",
        target_identity_digest="a" * 64,
        privilege=None,
        request={"serial": "25044DB50A3B"},
    )
    path = ReceiptStore(tmp_path.resolve()).create(receipt)
    assert json.loads(path.read_text())["receipt_id"] == receipt.receipt_id


def test_terminal_receipt_cannot_be_finished_twice() -> None:
    receipt = begin_receipt(
        tool="run",
        target_name="sager-arch",
        target_identity_digest="a" * 64,
        privilege=Privilege.USER,
        request={},
    )
    finished = finish_receipt(
        receipt,
        status=OperationStatus.SUCCEEDED,
        result={"exit_code": 0},
    )
    with pytest.raises(ValidationError, match="already terminal"):
        finish_receipt(
            finished,
            status=OperationStatus.SUCCEEDED,
            result={"exit_code": 0},
        )
