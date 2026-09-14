from __future__ import annotations

import re
from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from ..errors import ArchwrightError
from .helpers import command, q


def _aur_name(package: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9@._+\-]+", package):
        raise ArchwrightError("VALIDATION_FAILED", "Invalid AUR package name")
    return package


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def package_search(query: str) -> dict[str, Any]: return command(c, "package_search", f"pacman -Ss -- {q(query)}")
    @mcp.tool()
    def package_info(package: str) -> dict[str, Any]: return command(c, "package_info", f"pacman -Si -- {q(package)}; pacman -Qi -- {q(package)} 2>/dev/null || true")
    @mcp.tool()
    def package_install(packages: list[str], needed: bool = True) -> dict[str, Any]:
        return command(c, "package_install", f"pacman -S --noconfirm {'--needed' if needed else ''} -- {' '.join(q(x) for x in packages)}", root=True, mutation=True, timeout=3600, request={"packages": packages})
    @mcp.tool()
    def package_remove(packages: list[str], mode: str = "Rns") -> dict[str, Any]:
        if mode not in {"R", "Rs", "Rns", "Rn"}: raise ArchwrightError("VALIDATION_FAILED", "Unsupported removal mode")
        return command(c, "package_remove", f"pacman -{mode} --noconfirm -- {' '.join(q(x) for x in packages)}", root=True, mutation=True, timeout=1800, request={"packages": packages, "mode": mode})
    @mcp.tool()
    def package_upgrade() -> dict[str, Any]: return command(c, "package_upgrade", "pacman -Syu --noconfirm", root=True, mutation=True, timeout=7200)
    @mcp.tool()
    def package_list(kind: str = "all") -> dict[str, Any]:
        mapping={"all":"-Q","explicit":"-Qe","foreign":"-Qm","orphans":"-Qdt"}; return command(c,"package_list",f"pacman {mapping.get(kind,'-Q')}")
    @mcp.tool()
    def package_files(package_or_path: str, owner_lookup: bool = False) -> dict[str, Any]:
        return command(c,"package_files",f"pacman {'-Qo' if owner_lookup else '-Ql'} -- {q(package_or_path)}")
    @mcp.tool()
    def aur_info(package: str) -> dict[str, Any]:
        package=_aur_name(package); script=f"set -euo pipefail\nd=$(mktemp -d)\ntrap 'rm -rf \"$d\"' EXIT\ngit clone --depth 1 https://aur.archlinux.org/{package}.git \"$d/pkg\"\ncd \"$d/pkg\"\nprintf '%s\\n' '--- PKGBUILD ---'\ncat PKGBUILD\nprintf '%s\\n' '--- SRCINFO ---'\ncat .SRCINFO 2>/dev/null || true\n"; return c.execute(tool="aur_info",script=script,root=False,timeout_seconds=300)
    @mcp.tool()
    def aur_install(package: str) -> dict[str, Any]:
        package=_aur_name(package); script=f"set -euo pipefail\nd=$(mktemp -d)\ntrap 'rm -rf \"$d\"' EXIT\ngit clone --depth 1 https://aur.archlinux.org/{package}.git \"$d/pkg\"\ncd \"$d/pkg\"\nmakepkg --syncdeps --noconfirm --cleanbuild --clean\npkg=$(find . -maxdepth 1 -type f -name '*.pkg.tar.*' ! -name '*.sig' -print -quit)\ntest -n \"$pkg\"\nsudo -n pacman -U --noconfirm -- \"$pkg\"\n"; return c.execute(tool="aur_install",script=script,root=False,timeout_seconds=7200,mutation=True,request_extra={"package":package})
    @mcp.tool()
    def flatpak_manage(action: str, refs: list[str] | None = None, remote: str = "flathub") -> dict[str, Any]:
        refs=refs or []; names=" ".join(q(x) for x in refs); mapping={"list":"flatpak list","search":f"flatpak search {names}","install":f"flatpak install -y {q(remote)} {names}","remove":f"flatpak uninstall -y {names}","update":"flatpak update -y","remotes":"flatpak remotes --show-details"};
        if action not in mapping: raise ArchwrightError("VALIDATION_FAILED","Unsupported Flatpak action")
        return command(c,"flatpak_manage",mapping[action],mutation=action in {"install","remove","update"},timeout=3600,request={"action":action,"refs":refs})
    @mcp.tool()
    def service_status(unit: str) -> dict[str, Any]: return command(c,"service_status",f"systemctl status --no-pager --full {q(unit)} || true; journalctl -u {q(unit)} --no-pager -n 80")
    @mcp.tool()
    def service_start(unit: str) -> dict[str, Any]: return command(c,"service_start",f"systemctl start {q(unit)}",root=True,mutation=True)
    @mcp.tool()
    def service_stop(unit: str) -> dict[str, Any]: return command(c,"service_stop",f"systemctl stop {q(unit)}",root=True,mutation=True)
    @mcp.tool()
    def service_restart(unit: str) -> dict[str, Any]: return command(c,"service_restart",f"systemctl restart {q(unit)}",root=True,mutation=True)
    @mcp.tool()
    def service_enable(unit: str, now: bool=False) -> dict[str, Any]: return command(c,"service_enable",f"systemctl enable {'--now' if now else ''} {q(unit)}",root=True,mutation=True)
    @mcp.tool()
    def service_disable(unit: str, now: bool=False) -> dict[str, Any]: return command(c,"service_disable",f"systemctl disable {'--now' if now else ''} {q(unit)}",root=True,mutation=True)
    @mcp.tool()
    def service_list(state: str="", unit_type: str="service", pattern: str="") -> dict[str, Any]:
        args=f"--type={q(unit_type)} --all --no-pager" + (f" --state={q(state)}" if state else "") + (f" {q(pattern)}" if pattern else ""); return command(c,"service_list",f"systemctl list-units {args}")
    @mcp.tool()
    def unit_read(unit: str) -> dict[str, Any]: return command(c,"unit_read",f"systemctl cat {q(unit)}; systemctl show {q(unit)} -p FragmentPath -p DropInPaths")
    @mcp.tool()
    def daemon_reload() -> dict[str, Any]: return command(c,"daemon_reload","systemctl daemon-reload",root=True,mutation=True)
