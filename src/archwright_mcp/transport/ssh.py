from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ..config import Settings
from ..errors import ArchwrightError


@dataclass(slots=True)
class ProcessResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class SSHTransport:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _ssh_base(self) -> list[str]:
        e = self.settings.endpoint
        return [
            "ssh", "-p", str(e.port), "-i", str(e.identity_file),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", f"UserKnownHostsFile={e.known_hosts_file}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={self.settings.connect_timeout}",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            f"{e.user}@{e.host}",
        ]

    def _scp_base(self) -> list[str]:
        e = self.settings.endpoint
        return [
            "scp", "-P", str(e.port), "-i", str(e.identity_file),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", f"UserKnownHostsFile={e.known_hosts_file}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={self.settings.connect_timeout}",
        ]

    def run(self, argv: Sequence[str], *, timeout: int | None = None, input_bytes: bytes | None = None, limit: int | None = None) -> ProcessResult:
        started = time.monotonic()
        try:
            cp = subprocess.run(list(argv), input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout or self.settings.command_timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ArchwrightError("COMMAND_TIMEOUT", "Local transport command timed out", {"argv0": argv[0] if argv else None, "timeout": timeout}) from exc
        except OSError as exc:
            raise ArchwrightError("TARGET_UNREACHABLE", "Could not start OpenSSH transport", {"error": str(exc)}) from exc
        max_bytes = limit or self.settings.output_limit_bytes
        out = cp.stdout
        err = cp.stderr
        out_tr = len(out) > max_bytes
        err_tr = len(err) > max_bytes
        if out_tr:
            out = out[:max_bytes]
        if err_tr:
            err = err[:max_bytes]
        return ProcessResult(cp.returncode, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace"), time.monotonic() - started, out_tr, err_tr)

    def remote(self, command: str, *, root: bool = False, timeout: int | None = None, limit: int | None = None) -> ProcessResult:
        remote_command = f"sudo -n -- /bin/bash -lc {self._quote(command)}" if root else f"/bin/bash -lc {self._quote(command)}"
        result = self.run(self._ssh_base() + [remote_command], timeout=timeout, limit=limit)
        if result.exit_code == 255:
            raise ArchwrightError("TARGET_UNREACHABLE", "SSH transport failed", {"stderr": result.stderr[-4096:]})
        return result

    @staticmethod
    def _quote(text: str) -> str:
        return "'" + text.replace("'", "'\"'\"'") + "'"

    def upload(self, local: Path, remote_path: str) -> ProcessResult:
        e = self.settings.endpoint
        return self.run(self._scp_base() + [str(local), f"{e.user}@{e.host}:{remote_path}"], timeout=self.settings.command_timeout)

    def download(self, remote_path: str, local: Path) -> ProcessResult:
        e = self.settings.endpoint
        return self.run(self._scp_base() + [f"{e.user}@{e.host}:{remote_path}", str(local)], timeout=self.settings.command_timeout)

    def reachable(self) -> bool:
        try:
            return self.remote("true", timeout=self.settings.connect_timeout).exit_code == 0
        except ArchwrightError:
            return False
