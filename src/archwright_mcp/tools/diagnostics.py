from __future__ import annotations

from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from .helpers import command, q


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def journal_query(unit: str | None = None, boot: str | None = None, priority: str | None = None, since: str | None = None, until: str | None = None, grep: str | None = None, lines: int = 300) -> dict[str, Any]:
        args = ["journalctl", "--no-pager", "-n", str(max(1, min(lines, 5000)))]
        if unit: args += ["-u", q(unit)]
        if boot: args += ["-b", q(boot)]
        if priority: args += ["-p", q(priority)]
        if since: args += ["--since", q(since)]
        if until: args += ["--until", q(until)]
        if grep: args += ["--grep", q(grep)]
        return command(c, "journal_query", " ".join(args))

    @mcp.tool()
    def dmesg_read(level: str | None = None, lines: int = 500) -> dict[str, Any]:
        args = "dmesg --color=never --time-format=iso"
        if level: args += f" --level={q(level)}"
        return command(c, "dmesg_read", f"{args} | tail -n {max(1,min(lines,5000))}", root=True)

    @mcp.tool()
    def failed_units() -> dict[str, Any]: return command(c, "failed_units", "systemctl --failed --no-pager --plain")
    @mcp.tool()
    def process_list(filter_text: str = "", limit: int = 500) -> dict[str, Any]:
        cmd = "ps -eo pid,ppid,user,state,lstart,etimes,%cpu,%mem,args --sort=-%cpu"
        if filter_text: cmd += f" | grep -F -- {q(filter_text)}"
        cmd += f" | head -n {max(1,min(limit,5000))}"
        return command(c, "process_list", cmd)
    @mcp.tool()
    def process_tree(pid: int | None = None) -> dict[str, Any]: return command(c, "process_tree", f"pstree -ap {pid}" if pid else "pstree -ap")
    @mcp.tool()
    def process_kill(pid: int, signal: str = "TERM") -> dict[str, Any]:
        pre = command(c, "process_identity", f"ps -p {int(pid)} -o pid,ppid,user,lstart,args --no-headers")
        kill = command(c, "process_kill", f"kill -s {q(signal)} {int(pid)}", root=True, mutation=True, request={"pid": pid, "signal": signal})
        return {"ok": kill.get("ok", False), "process": pre, "kill": kill}
    @mcp.tool()
    def socket_list() -> dict[str, Any]: return command(c, "socket_list", "ss -H -tulpna")
