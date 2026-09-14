from __future__ import annotations

from mcp.server import MCPServer

from .config import load_settings
from .core import Controller
from .tools import diagnostics, execution, filesystem, hardware, network, power_lifecycle
from .tools import storage_boot, system, target, workstation


def build_server() -> MCPServer:
    controller = Controller(load_settings())
    mcp = MCPServer("Archwright")
    target.register(mcp, controller)
    execution.register(mcp, controller)
    filesystem.register(mcp, controller)
    system.register(mcp, controller)
    diagnostics.register(mcp, controller)
    hardware.register(mcp, controller)
    network.register(mcp, controller)
    storage_boot.register(mcp, controller)
    workstation.register(mcp, controller)
    power_lifecycle.register(mcp, controller)
    return mcp


def main() -> None:
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
