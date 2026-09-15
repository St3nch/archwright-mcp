from __future__ import annotations

import os
from pathlib import Path

import pytest

from archwright_mcp.config import load_config
from archwright_mcp.execution.commands import ExecutionController
from archwright_mcp.policy.mutation import MutationGate
from archwright_mcp.receipts import ReceiptStore
from archwright_mcp.target.enrollment import EnrollmentStore
from archwright_mcp.target.identity import IdentityCollector
from archwright_mcp.transport.ssh import SshTransport
from archwright_mcp.transport.transfer import VerifiedTransfer


@pytest.fixture
def execution_controller() -> ExecutionController:
    config_value = os.environ.get("ARCHWRIGHT_INTEGRATION_CONFIG")
    enrollment_value = os.environ.get("ARCHWRIGHT_INTEGRATION_ENROLLMENT")
    if not config_value or not enrollment_value:
        pytest.fail(
            "execution integration requires the explicit disposable fixture variables "
            "ARCHWRIGHT_INTEGRATION_CONFIG and ARCHWRIGHT_INTEGRATION_ENROLLMENT; "
            "the test is intentionally not skipped"
        )
    config_path = Path(config_value).resolve()
    enrollment_path = Path(enrollment_value).resolve()
    config = load_config(config_path)
    transport = SshTransport(
        config.target.endpoint,
        connect_timeout_seconds=config.policy.connect_timeout_seconds,
        output_limit_bytes=config.policy.output_limit_bytes,
    )
    collector = IdentityCollector(
        transport,
        timeout_seconds=config.policy.connect_timeout_seconds,
        runtime_path=config.policy.target_runtime_path,
    )
    gate = MutationGate(
        EnrollmentStore(enrollment_path),
        collector,
        ReceiptStore(config.policy.receipt_dir),
        config.target,
    )
    return ExecutionController(config, gate, transport, VerifiedTransfer(transport))
