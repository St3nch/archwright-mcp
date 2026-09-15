from __future__ import annotations

from pathlib import Path

import pytest

from archwright_mcp.config import PolicyConfig
from archwright_mcp.errors import ValidationError
from archwright_mcp.execution.scripts import ExecutionRequest, PreparedScript
from archwright_mcp.models import OutputPolicy, Privilege


def policy() -> PolicyConfig:
    return PolicyConfig(
        require_identity_for_mutation=True,
        require_protected_disks_read_only=True,
        receipt_dir=Path("/var/lib/archwright/receipts"),
    )


def request(**changes: object) -> ExecutionRequest:
    values: dict[str, object] = {
        "request_id": "request-0001",
        "script": b"#!/bin/bash\nprintf '%s\\n' ok\n",
    }
    values.update(changes)
    return ExecutionRequest(**values)  # type: ignore[arg-type]


def test_request_digest_binds_script_and_execution_settings() -> None:
    first = request()
    second = request(script=b"#!/bin/bash\nprintf '%s\\n' changed\n")
    assert first.normalized_digest() != second.normalized_digest()
    assert first.script not in repr(first.receipt_request()).encode()
    assert first.receipt_request()["script_sha256"] == first.script_sha256


def test_prepared_script_preserves_exact_bytes_and_hash() -> None:
    original = request(script=b"\x00\xffquoted '$HOME'\n")
    original.validate(policy())
    prepared = PreparedScript.from_request(original, "op-" + "a" * 32)
    assert prepared.content == original.script
    assert prepared.size_bytes == len(original.script)
    assert prepared.sha256 == original.script_sha256


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"request_id": "short"}, "request ID"),
        ({"script": b""}, "must not be empty"),
        ({"interpreter": "bash"}, "absolute"),
        ({"working_directory": "relative"}, "absolute"),
        ({"timeout_seconds": float("inf")}, "runtime"),
        ({"wait_seconds": 31}, "wait"),
        ({"privilege": Privilege.ROOT, "user": "chaz"}, "root execution"),
        ({"privilege": Privilege.USER, "user": "root"}, "root account"),
    ],
)
def test_request_validation_refuses_invalid_boundaries(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        request(**changes).validate(policy())


def test_ordinary_environment_rejects_secret_looking_name() -> None:
    with pytest.raises(ValidationError, match="secret reference"):
        request(environment=(("API_TOKEN", "plaintext"),)).validate(policy())


def test_secret_reference_forces_output_discard() -> None:
    sensitive = request(
        secret_environment=(("API_TOKEN", "github/bootstrap-token"),),
        output_policy=OutputPolicy.CAPTURE,
    )
    sensitive.validate(policy())
    assert sensitive.effective_output_policy is OutputPolicy.DISCARD
    receipt = sensitive.receipt_request()
    assert "github/bootstrap-token" not in repr(receipt)
    assert receipt["secret_environment_names"] == ["API_TOKEN"]


def test_script_size_ceiling_is_enforced() -> None:
    small_policy = policy()
    oversized = request(script=b"x" * (small_policy.max_script_bytes + 1))
    with pytest.raises(ValidationError, match="size limit"):
        oversized.validate(small_policy)
