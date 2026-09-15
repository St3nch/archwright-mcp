from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path

import pytest

from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.models import TargetEndpoint
from archwright_mcp.transport import ssh as ssh_module
from archwright_mcp.transport.ssh import SshTransport, decode_bounded


def transport() -> SshTransport:
    endpoint = TargetEndpoint(
        host="127.0.0.1",
        port=22022,
        user="arch-bootstrap",
        controller_key=Path("/etc/archwright/keys/controller_ed25519"),
        known_hosts=Path("/etc/archwright/known_hosts"),
    )
    return SshTransport(endpoint)


def test_ssh_argv_is_hardened_and_uses_no_user_config() -> None:
    argv = transport().ssh_argv(["/usr/bin/printf", "%s", "hello world; $(nope)"])
    assert argv[0] == "/usr/bin/ssh"
    assert argv[1:3] == ["-F", "/dev/null"]
    assert "BatchMode=yes" in argv
    assert "IdentityFile=none" in argv
    assert "IdentityAgent=none" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "PasswordAuthentication=no" in argv
    assert "UpdateHostKeys=no" in argv
    assert "-T" in argv
    assert argv[-2] == "arch-bootstrap@127.0.0.1"
    assert argv[-1] == "/usr/bin/printf %s 'hello world; $(nope)'"


def test_transport_environment_does_not_forward_agent_or_home(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent")
    monkeypatch.setenv("HOME", "/home/chaz")
    environment = transport().subprocess_environment
    assert "SSH_AUTH_SOCK" not in environment
    assert "HOME" not in environment
    assert environment["LC_ALL"] == "C.UTF-8"


def test_remote_argv_rejects_newline_and_nul() -> None:
    with pytest.raises(ValidationError, match="invalid argument"):
        transport().ssh_argv(["printf", "bad\ncommand"])
    with pytest.raises(ValidationError, match="invalid argument"):
        transport().ssh_argv(["printf", "bad\0command"])


@pytest.mark.parametrize("host", ["workstation.local", "192.168.1.2"])
def test_endpoint_refuses_non_loopback_host(host: str) -> None:
    with pytest.raises(ValidationError, match="loopback"):
        TargetEndpoint(
            host=host,
            port=22022,
            user="arch-bootstrap",
            controller_key=Path("/etc/archwright/key"),
            known_hosts=Path("/etc/archwright/known_hosts"),
        )


def test_endpoint_refuses_invalid_user() -> None:
    with pytest.raises(ValidationError, match="account name"):
        TargetEndpoint(
            host="127.0.0.1",
            port=22022,
            user="root@attacker",
            controller_key=Path("/etc/archwright/key"),
            known_hosts=Path("/etc/archwright/known_hosts"),
        )


def test_decode_bounded_handles_non_utf8_and_bytes() -> None:
    text, truncated = decode_bounded(b"abc\xffxyz", 5)
    assert text == "abc�x"
    assert truncated is True


@pytest.mark.asyncio
async def test_local_process_timeout_has_stable_error_code(tmp_path: Path) -> None:
    sleeper = tmp_path / "sleeper"
    sleeper.write_text("#!/bin/sh\nsleep 10\n")
    sleeper.chmod(0o700)
    instance = transport()
    with pytest.raises(ArchwrightError) as captured:
        await instance._run_local([str(sleeper)], timeout_seconds=0.01)
    assert captured.value.code is ErrorCode.COMMAND_TIMEOUT


@pytest.mark.asyncio
async def test_local_process_drains_flood_but_retains_only_bound(tmp_path: Path) -> None:
    flood = tmp_path / "flood"
    flood.write_text("#!/bin/sh\nyes x | head -c 1048576\nyes e | head -c 1048576 >&2\n")
    flood.chmod(0o700)
    result = await transport()._run_local([str(flood)], timeout_seconds=5, output_limit_bytes=4096)
    assert result.exit_code == 0
    assert len(result.stdout.encode()) == 4096
    assert len(result.stderr.encode()) == 4096
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True


@pytest.mark.asyncio
async def test_local_process_cancellation_reaps_process_group(tmp_path: Path) -> None:
    sleeper = tmp_path / "cancel-sleeper"
    sleeper.write_text("#!/bin/sh\nsleep 30\n")
    sleeper.chmod(0o700)
    task = asyncio.create_task(transport()._run_local([str(sleeper)], timeout_seconds=60))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_cleanup_kills_descendant_after_process_leader_exits(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    launcher = tmp_path / "launcher"
    launcher.write_text("#!/bin/sh\n(sleep 30) >/dev/null 2>&1 &\nexit 0\n")
    launcher.chmod(0o700)
    process = await asyncio.create_subprocess_exec(str(launcher), start_new_session=True)
    await process.wait()
    monkeypatch.setattr(ssh_module, "_LOCAL_TERMINATION_GRACE_SECONDS", 0.05)
    await SshTransport._stop_process(process)
    with pytest.raises(ProcessLookupError):
        os.killpg(process.pid, 0)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, 9)


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), 21601])
@pytest.mark.asyncio
async def test_local_process_refuses_invalid_timeout(value: float) -> None:
    with pytest.raises(ValidationError, match="timeout"):
        await transport()._run_local(["/bin/true"], timeout_seconds=value)


@pytest.mark.parametrize("value", [0, -1, 8 * 1024 * 1024 + 1])
@pytest.mark.asyncio
async def test_local_process_refuses_invalid_output_limit(value: int) -> None:
    with pytest.raises(ValidationError, match="output limit"):
        await transport()._run_local(["/bin/true"], timeout_seconds=1, output_limit_bytes=value)
