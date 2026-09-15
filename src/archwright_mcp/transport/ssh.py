"""Hardened OpenSSH subprocess transport."""

from __future__ import annotations

import asyncio
import contextlib
import math
import os
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.models import TargetEndpoint

DEFAULT_SSH = Path("/usr/bin/ssh")
DEFAULT_SFTP = Path("/usr/bin/sftp")
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin"
MAX_LOCAL_OUTPUT_LIMIT = 8 * 1024 * 1024
MAX_LOCAL_TIMEOUT_SECONDS = 6 * 60 * 60
_READ_CHUNK = 64 * 1024
_LOCAL_TERMINATION_GRACE_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class ProcessOutput:
    exit_code: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


def decode_bounded(data: bytes, limit: int) -> tuple[str, bool]:
    """Decode possibly non-UTF8 output while applying a byte limit."""

    if limit < 1:
        raise ValidationError("output limit must be positive")
    truncated = len(data) > limit
    selected = data[:limit]
    return selected.decode("utf-8", errors="replace"), truncated


class SshTransport:
    """Run structured remote commands through a pinned reverse-SSH endpoint."""

    def __init__(
        self,
        endpoint: TargetEndpoint,
        *,
        connect_timeout_seconds: int = 10,
        output_limit_bytes: int = 131_072,
        ssh_binary: Path = DEFAULT_SSH,
        sftp_binary: Path = DEFAULT_SFTP,
    ) -> None:
        if connect_timeout_seconds < 1:
            raise ValidationError("SSH connect timeout must be positive")
        if not 1 <= output_limit_bytes <= MAX_LOCAL_OUTPUT_LIMIT:
            raise ValidationError("SSH output limit must be positive")
        for label, path in (("ssh binary", ssh_binary), ("sftp binary", sftp_binary)):
            if not path.is_absolute():
                raise ValidationError(f"{label} must be an absolute path")
        self.endpoint = endpoint
        self.connect_timeout_seconds = connect_timeout_seconds
        self.output_limit_bytes = output_limit_bytes
        self.ssh_binary = ssh_binary
        self.sftp_binary = sftp_binary

    @property
    def destination(self) -> str:
        return f"{self.endpoint.user}@{self.endpoint.host}"

    @property
    def subprocess_environment(self) -> dict[str, str]:
        """Return a small fixed environment with no agent or user config leakage."""

        return {
            "PATH": DEFAULT_PATH,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    def common_options(self) -> list[str]:
        """Return options shared by ssh and sftp invocations."""

        return [
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityFile=none",
            "-o",
            "IdentityAgent=none",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.endpoint.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"ConnectTimeout={self.connect_timeout_seconds}",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "ControlMaster=no",
            "-o",
            "LogLevel=ERROR",
            "-i",
            str(self.endpoint.controller_key),
        ]

    def ssh_argv(self, remote_argv: Sequence[str]) -> list[str]:
        """Build an ssh command from structured remote argv.

        OpenSSH ultimately passes one command string to the remote login shell.
        ``shlex.join`` is confined to already separated internal arguments; model
        script text is transferred as file data and never enters this path.
        """

        command = self._remote_command(remote_argv)
        return [
            str(self.ssh_binary),
            *self.common_options(),
            "-T",
            "-p",
            str(self.endpoint.port),
            "--",
            self.destination,
            command,
        ]

    def sftp_argv(self) -> list[str]:
        return [
            str(self.sftp_binary),
            *self.common_options(),
            "-b",
            "-",
            "-P",
            str(self.endpoint.port),
            "--",
            self.destination,
        ]

    async def run(
        self,
        remote_argv: Sequence[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int | None = None,
    ) -> ProcessOutput:
        """Execute structured argv on the target without a local shell."""

        return await self._run_local(
            self.ssh_argv(remote_argv),
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )

    async def run_sftp_batch(
        self,
        batch: bytes,
        *,
        timeout_seconds: float,
        output_limit_bytes: int | None = None,
    ) -> ProcessOutput:
        """Execute a generated SFTP batch over stdin."""

        if b"\x00" in batch:
            raise ValidationError("SFTP batch must not contain NUL bytes")
        return await self._run_local(
            self.sftp_argv(),
            stdin=batch,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )

    async def _run_local(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int | None = None,
        stdin: bytes | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> ProcessOutput:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= MAX_LOCAL_TIMEOUT_SECONDS
        ):
            raise ValidationError("process timeout must be positive")
        limit = self.output_limit_bytes if output_limit_bytes is None else output_limit_bytes
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_LOCAL_OUTPUT_LIMIT
        ):
            raise ValidationError("output limit is outside the supported range")
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=dict(environment or self.subprocess_environment),
                start_new_session=True,
            )
        except OSError as exc:
            raise ArchwrightError(
                ErrorCode.TARGET_UNREACHABLE,
                "unable to start OpenSSH transport",
            ) from exc

        if process.stdout is None or process.stderr is None:
            await self._stop_process(process)
            raise ArchwrightError(ErrorCode.TARGET_UNREACHABLE, "OpenSSH pipes unavailable")

        stdout_task = asyncio.create_task(self._drain_bounded(process.stdout, limit))
        stderr_task = asyncio.create_task(self._drain_bounded(process.stderr, limit))
        stdin_task = asyncio.create_task(self._write_input(process, stdin))
        wait_task = asyncio.create_task(process.wait())
        tasks = (stdout_task, stderr_task, stdin_task, wait_task)
        try:
            async with asyncio.timeout(timeout_seconds):
                await asyncio.gather(*tasks)
        except TimeoutError as exc:
            await self._stop_process(process)
            await asyncio.gather(*tasks, return_exceptions=True)
            raise ArchwrightError(
                ErrorCode.COMMAND_TIMEOUT,
                "OpenSSH operation exceeded its timeout",
                details={"timeout_seconds": timeout_seconds},
            ) from exc
        except asyncio.CancelledError:
            await self._stop_process(process)
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        if process.returncode is None:
            raise ArchwrightError(
                ErrorCode.TARGET_UNREACHABLE,
                "OpenSSH transport ended without an exit status",
            )
        stdout_text, stdout_truncated = stdout_task.result()
        stderr_text, stderr_truncated = stderr_task.result()
        return ProcessOutput(
            exit_code=process.returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    @staticmethod
    async def _write_input(process: asyncio.subprocess.Process, data: bytes | None) -> None:
        if process.stdin is None:
            return
        try:
            if data is not None:
                process.stdin.write(data)
                await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            process.stdin.close()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                await process.stdin.wait_closed()

    @staticmethod
    async def _drain_bounded(stream: asyncio.StreamReader, limit: int) -> tuple[str, bool]:
        retained = bytearray()
        truncated = False
        while chunk := await stream.read(_READ_CHUNK):
            remaining = limit - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
        return retained.decode("utf-8", errors="replace"), truncated

    @staticmethod
    async def _stop_process(process: asyncio.subprocess.Process) -> None:
        """Terminate the whole OpenSSH process group, escalating once."""

        try:
            os.killpg(process.pid, 15)
        except ProcessLookupError:
            return
        deadline = asyncio.get_running_loop().time() + _LOCAL_TERMINATION_GRACE_SECONDS
        while asyncio.get_running_loop().time() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            await asyncio.sleep(0.05)
        try:
            os.killpg(process.pid, 9)
        except ProcessLookupError:
            return
        if process.returncode is None:
            await process.wait()

    @staticmethod
    def _remote_command(remote_argv: Sequence[str]) -> str:
        if not remote_argv:
            raise ValidationError("remote argv must not be empty")
        normalized = []
        for argument in remote_argv:
            if not isinstance(argument, str) or "\x00" in argument or "\n" in argument:
                raise ValidationError("remote argv contains an invalid argument")
            normalized.append(argument)
        return shlex.join(normalized)
