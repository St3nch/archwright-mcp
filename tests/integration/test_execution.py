from __future__ import annotations

import secrets

import pytest

from archwright_mcp.execution.commands import ExecutionController
from archwright_mcp.execution.scripts import ExecutionRequest
from archwright_mcp.models import JobState, Privilege


def request_id(label: str) -> str:
    return f"integration-{label}-{secrets.token_hex(8)}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("privilege", "expected_uid"),
    [(Privilege.USER, "not-root"), (Privilege.ROOT, "root")],
)
async def test_real_user_and_root_execution(
    execution_controller: ExecutionController,
    privilege: Privilege,
    expected_uid: str,
) -> None:
    script = b"""#!/usr/bin/bash
set -euo pipefail
if [[ $(id -u) == 0 ]]; then printf 'root'; else printf 'not-root'; fi
"""
    result = await execution_controller.execute(
        ExecutionRequest(
            request_id=request_id(privilege.value),
            script=script,
            privilege=privilege,
            wait_seconds=30,
        )
    )
    assert result.state is JobState.SUCCEEDED
    assert result.stdout == expected_uid


@pytest.mark.asyncio
async def test_exact_multiline_unicode_and_quoted_bytes(
    execution_controller: ExecutionController,
) -> None:
    script = """#!/usr/bin/bash
set -euo pipefail
printf '%s\\n' 'quote: '\"'\"'$HOME; $(never-run)'\"'\"''
printf '%s\\n' 'Archwright ✓'
""".encode()
    result = await execution_controller.execute(
        ExecutionRequest(
            request_id=request_id("bytes"),
            script=script,
            wait_seconds=30,
        )
    )
    assert result.state is JobState.SUCCEEDED
    assert "$(never-run)" in result.stdout
    assert "Archwright ✓" in result.stdout


@pytest.mark.asyncio
async def test_nonzero_exit_and_bounded_output(
    execution_controller: ExecutionController,
) -> None:
    result = await execution_controller.execute(
        ExecutionRequest(
            request_id=request_id("nonzero"),
            script=b"#!/usr/bin/bash\nyes x | head -c 1048576\nexit 23\n",
            wait_seconds=30,
        )
    )
    assert result.state is JobState.FAILED
    assert result.exit_code == 23
    assert result.stdout_truncated is True
    assert len(result.stdout.encode()) <= 65_536
