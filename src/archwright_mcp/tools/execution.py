from __future__ import annotations

import base64
from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from .helpers import command, q


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def run(script: str, cwd: str | None = None, timeout_seconds: int = 120, env: dict[str, str] | None = None) -> dict[str, Any]:
        return c.execute(tool="run", script=script, root=False, cwd=cwd, timeout_seconds=timeout_seconds, env=env, mutation=True)

    @mcp.tool()
    def run_root(script: str, cwd: str | None = None, timeout_seconds: int = 120, env: dict[str, str] | None = None) -> dict[str, Any]:
        return c.execute(tool="run_root", script=script, root=True, cwd=cwd, timeout_seconds=timeout_seconds, env=env, mutation=True)

    @mcp.tool()
    def run_script(content: str, interpreter: str = "/bin/bash", arguments: list[str] | None = None, cwd: str | None = None, privilege: str = "user", timeout_seconds: int = 300) -> dict[str, Any]:
        if privilege not in {"user", "root"}:
            raise ValueError("privilege must be user or root")
        if not interpreter.startswith("/"):
            raise ValueError("interpreter must be an absolute path")
        encoded = base64.b64encode(content.encode()).decode()
        payload = f"{c.settings.target_staging_dir}/payload-{c.new_job_id()}.script"
        argv = " ".join([q(interpreter), q(payload), *(q(x) for x in (arguments or []))])
        wrapper = (
            f"printf '%s' {q(encoded)} | base64 -d > {q(payload)}\n"
            f"chmod 700 {q(payload)}\n"
            f"trap 'rm -f {q(payload)}' EXIT\n"
            f"exec {argv}\n"
        )
        return c.execute(tool="run_script", script=wrapper, root=privilege == "root", cwd=cwd, timeout_seconds=timeout_seconds, mutation=True, request_extra={"interpreter": interpreter, "arguments": arguments or [], "privilege": privilege})

    @mcp.tool()
    def which(executable: str, version_args: list[str] | None = None) -> dict[str, Any]:
        ver = " ".join(q(x) for x in (version_args or ["--version"]))
        return command(c, "which", f"p=$(command -v {q(executable)}) || exit 1; printf '%s\\n' \"$p\"; \"$p\" {ver} 2>&1 | head -20")

    @mcp.tool()
    def environment() -> dict[str, Any]:
        return command(c, "environment", "printf 'user=%s\\n' \"$(id -un)\"; id; printf 'shell=%s\\n' \"$SHELL\"; printf 'path=%s\\n' \"$PATH\"; locale")

    @mcp.tool()
    def job_start(script: str, privilege: str = "user", cwd: str | None = None, description: str = "", runtime_timeout_seconds: int = 3600) -> dict[str, Any]:
        if privilege not in {"user", "root"}:
            return {"ok": False, "error": {"code": "VALIDATION_FAILED", "message": "privilege must be user or root"}}
        c.mutation_gate()
        job_id = c.new_job_id()
        unit = f"archwright-{job_id}"
        encoded = base64.b64encode(script.encode()).decode()
        if privilege == "root":
            target_script = f"/run/archwright/jobs/{job_id}.sh"
            stage_script = "install -d -m700 -o root -g root /run/archwright/jobs\n" + f"printf '%s' {q(encoded)} | base64 -d > {q(target_script)}\nchmod 700 {q(target_script)}\n"
            c.execute(tool="job_stage", script=stage_script, root=True, timeout_seconds=60, mutation=True, request_extra={"job_id": job_id, "description": description, "privilege": privilege})
            user_flags = ""
        else:
            target_script = f"{c.settings.target_staging_dir}/jobs/{job_id}.sh"
            stage_script = f"mkdir -p {q(c.settings.target_staging_dir + '/jobs')}\nprintf '%s' {q(encoded)} | base64 -d > {q(target_script)}\nchmod 700 {q(target_script)}\n"
            c.execute(tool="job_stage", script=stage_script, root=False, timeout_seconds=60, mutation=True, request_extra={"job_id": job_id, "description": description, "privilege": privilege})
            user_flags = f"--uid={q(c.settings.endpoint.user)} --gid={q(c.settings.endpoint.user)}"
        workdir = f"--working-directory={q(cwd)}" if cwd else ""
        cmd = f"systemd-run --unit={q(unit)} --property=RuntimeMaxSec={int(runtime_timeout_seconds)} {workdir} {user_flags} /bin/bash {q(target_script)}"
        started = command(c, "job_start", cmd, root=True, mutation=True, request={"job_id": job_id, "description": description, "privilege": privilege})
        return {"ok": started.get("ok", False), "job_id": job_id, "unit": unit, "script_path": target_script, "start": started}

    @mcp.tool()
    def job_status(job_id: str) -> dict[str, Any]:
        return command(c, "job_status", f"systemctl show {q(f'archwright-{job_id}')} --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,StateChangeTimestamp,InactiveExitTimestamp")

    @mcp.tool()
    def job_output(job_id: str, lines: int = 300) -> dict[str, Any]:
        return command(c, "job_output", f"journalctl -u {q(f'archwright-{job_id}')} --no-pager -n {max(1,min(lines,5000))}")

    @mcp.tool()
    def job_cancel(job_id: str) -> dict[str, Any]:
        return command(c, "job_cancel", f"systemctl stop {q(f'archwright-{job_id}')}", root=True, mutation=True, request={"job_id": job_id})

    @mcp.tool()
    def job_list() -> dict[str, Any]:
        return command(c, "job_list", "systemctl list-units 'archwright-job_*' 'archwright-job-*' --all --no-pager --plain")
