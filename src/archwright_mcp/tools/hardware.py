from __future__ import annotations

from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from .helpers import command


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def hardware_summary() -> dict[str, Any]:
        return command(c, "hardware_summary", "printf '%s\\n' '=== uname ==='; uname -a; printf '%s\\n' '=== cpu ==='; lscpu; printf '%s\\n' '=== memory ==='; free -h; printf '%s\\n' '=== block ==='; lsblk -o NAME,MODEL,SERIAL,SIZE,FSTYPE,MOUNTPOINTS,RO; printf '%s\\n' '=== pci ==='; lspci -nnk; printf '%s\\n' '=== usb ==='; lsusb 2>/dev/null || true")
    @mcp.tool()
    def pci_devices() -> dict[str, Any]: return command(c, "pci_devices", "lspci -nnk")
    @mcp.tool()
    def usb_devices() -> dict[str, Any]: return command(c, "usb_devices", "lsusb -v 2>/dev/null || lsusb")
    @mcp.tool()
    def block_devices() -> dict[str, Any]: return {"ok": True, "devices": c.block_devices()}
    @mcp.tool()
    def sensors() -> dict[str, Any]: return command(c, "sensors", "sensors 2>/dev/null || true")
    @mcp.tool()
    def battery_status() -> dict[str, Any]:
        return command(c, "battery_status", "for b in /sys/class/power_supply/BAT*; do [ -e \"$b\" ] || continue; echo \"[$b]\"; grep -H . \"$b\"/{status,capacity,energy_full,energy_full_design,charge_full,charge_full_design,voltage_now,power_now,current_now} 2>/dev/null || true; done")
    @mcp.tool()
    def graphics_status() -> dict[str, Any]:
        return command(c, "graphics_status", "lspci -nnk | sed -n '/VGA\\|Display\\|3D controller/,+4p'; printf '\\nDRM:\\n'; ls -l /sys/class/drm 2>/dev/null || true; printf '\\nOpenGL:\\n'; glxinfo -B 2>/dev/null || true; printf '\\nVulkan:\\n'; vulkaninfo --summary 2>/dev/null || true")
    @mcp.tool()
    def audio_status() -> dict[str, Any]: return command(c, "audio_status", "aplay -l 2>/dev/null || true; arecord -l 2>/dev/null || true; systemctl --user status pipewire wireplumber --no-pager 2>/dev/null || true; wpctl status 2>/dev/null || true")
    @mcp.tool()
    def network_devices() -> dict[str, Any]: return command(c, "network_devices", "ip -details link; ip -brief address; for x in /sys/class/net/*; do printf '%s ' \"$(basename \"$x\")\"; readlink -f \"$x/device/driver\" 2>/dev/null || true; done")
    @mcp.tool()
    def bluetooth_status() -> dict[str, Any]: return command(c, "bluetooth_status", "systemctl status bluetooth --no-pager 2>/dev/null || true; bluetoothctl show 2>/dev/null || true; bluetoothctl devices 2>/dev/null || true")
    @mcp.tool()
    def firmware_status() -> dict[str, Any]: return command(c, "firmware_status", "for f in bios_vendor bios_version bios_date product_name product_version product_uuid board_name board_vendor; do printf '%s=' \"$f\"; cat \"/sys/class/dmi/id/$f\" 2>/dev/null || true; done; fwupdmgr get-devices 2>/dev/null || true")
