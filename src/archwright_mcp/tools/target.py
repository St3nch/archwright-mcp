from __future__ import annotations

import socket
from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from ..errors import ArchwrightError


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def target_status() -> dict[str, Any]:
        """Return controller transport and target status."""
        reachable = c.transport.reachable()
        data: dict[str, Any] = {"ok": reachable, "endpoint": {"host": c.settings.endpoint.host, "port": c.settings.endpoint.port, "user": c.settings.endpoint.user}, "controller_host": socket.gethostname()}
        if reachable:
            try:
                data["identity"] = c.live_identity()
                data["sudo"] = c.transport.remote("sudo -n true").exit_code == 0
            except ArchwrightError as exc:
                data["inspection_error"] = exc.as_dict()
        return data

    @mcp.tool()
    def target_identity() -> dict[str, Any]:
        """Return live machine identity evidence."""
        return {"ok": True, "identity": c.live_identity()}

    @mcp.tool()
    def target_enroll(target_name: str, expected_target_serial: str, protected_serials: list[str]) -> dict[str, Any]:
        """Enroll the current target using explicit hardware serial policy."""
        return c.enroll(target_name, expected_target_serial, protected_serials)

    @mcp.tool()
    def target_verify() -> dict[str, Any]:
        """Verify enrolled target identity and protected-storage state."""
        return c.verify(require_protected_ro=True)

    @mcp.tool()
    def target_wait(timeout_seconds: int = 180) -> dict[str, Any]:
        """Wait for the target to reconnect and pass verification."""
        return c.wait(timeout_seconds=timeout_seconds)
