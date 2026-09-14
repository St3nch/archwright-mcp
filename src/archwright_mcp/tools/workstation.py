from __future__ import annotations

from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from ..errors import ArchwrightError
from .helpers import command, q


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def user_list(filter_text: str="") -> dict[str, Any]:
        cmd="getent passwd; printf '\\n=== groups ===\\n'; getent group"; cmd=f"({cmd}) | grep -F -- {q(filter_text)}" if filter_text else cmd; return command(c,"user_list",cmd)
    @mcp.tool()
    def user_create(user: str, groups: list[str] | None=None, shell: str="/bin/bash", create_home: bool=True) -> dict[str, Any]:
        group=f"-G {q(','.join(groups or []))}" if groups else ""; return command(c,"user_create",f"useradd {'-m' if create_home else '-M'} -s {q(shell)} {group} -- {q(user)}",root=True,mutation=True,request={"user":user,"groups":groups or [],"shell":shell})
    @mcp.tool()
    def user_modify(user: str, groups: list[str] | None=None, shell: str | None=None, append_groups: bool=True) -> dict[str, Any]:
        args=[]
        if groups: args += (["-a"] if append_groups else []) + ["-G",q(",".join(groups))]
        if shell: args += ["-s",q(shell)]
        return command(c,"user_modify",f"usermod {' '.join(args)} -- {q(user)}",root=True,mutation=True,request={"user":user,"groups":groups or [],"shell":shell})
    @mcp.tool()
    def user_remove(user: str, remove_home: bool=False) -> dict[str, Any]: return command(c,"user_remove",f"userdel {'-r' if remove_home else ''} -- {q(user)}",root=True,mutation=True,request={"user":user,"remove_home":remove_home})
    @mcp.tool()
    def sudo_status() -> dict[str, Any]: return command(c,"sudo_status","sudo -n -l 2>&1; printf '\\n=== sudoers dropins ===\\n'; ls -l /etc/sudoers.d 2>/dev/null || true")
    @mcp.tool()
    def permissions_set(path: str, mode: str | None=None, owner: str | None=None, group: str | None=None, recursive: bool=False) -> dict[str, Any]:
        cmds=[]; rec="-R" if recursive else ""
        if owner is not None or group is not None: cmds.append(f"chown {rec} {q(f'{owner or ""}:{group or ""}')} -- {q(path)}")
        if mode is not None: cmds.append(f"chmod {rec} {q(mode)} -- {q(path)}")
        if not cmds: raise ArchwrightError("VALIDATION_FAILED","No permission change requested")
        return command(c,"permissions_set"," && ".join(cmds),root=True,mutation=True,request={"path":path,"mode":mode,"owner":owner,"group":group,"recursive":recursive})
    @mcp.tool()
    def desktop_status() -> dict[str, Any]: return command(c,"desktop_status","pacman -Q plasma-desktop sddm kwin 2>/dev/null || true; systemctl status sddm --no-pager 2>/dev/null || true; loginctl list-sessions --no-legend 2>/dev/null || true; loginctl show-seat seat0 2>/dev/null || true")
    @mcp.tool()
    def display_status() -> dict[str, Any]: return command(c,"display_status","kscreen-doctor -o 2>/dev/null || true; for s in /sys/class/drm/card*-*/status; do echo \"$s: $(cat \"$s\" 2>/dev/null)\"; done")
    @mcp.tool()
    def kde_config_read(file: str, group: str | None=None, key: str | None=None) -> dict[str, Any]:
        if group and key: return command(c,"kde_config_read",f"kreadconfig6 --file {q(file)} --group {q(group)} --key {q(key)}")
        return command(c,"kde_config_read",f"cat -- \"$HOME/.config/{file}\" 2>/dev/null || true")
    @mcp.tool()
    def kde_config_write(file: str, group: str, key: str, value: str, value_type: str | None=None) -> dict[str, Any]: return command(c,"kde_config_write",f"kwriteconfig6 --file {q(file)} --group {q(group)} --key {q(key)} {'--type '+q(value_type) if value_type else ''} {q(value)}",mutation=True,request={"file":file,"group":group,"key":key,"value":value})
    @mcp.tool()
    def xdg_status() -> dict[str, Any]: return command(c,"xdg_status","xdg-user-dir DESKTOP 2>/dev/null || true; xdg-user-dir DOCUMENTS 2>/dev/null || true; xdg-mime query default x-scheme-handler/http 2>/dev/null || true; xdg-mime query default x-scheme-handler/https 2>/dev/null || true; printf 'XDG_CURRENT_DESKTOP=%s\\nXDG_SESSION_TYPE=%s\\n' \"$XDG_CURRENT_DESKTOP\" \"$XDG_SESSION_TYPE\"")
    @mcp.tool()
    def wayland_status() -> dict[str, Any]: return command(c,"wayland_status","printf 'WAYLAND_DISPLAY=%s\\nDISPLAY=%s\\nXDG_SESSION_TYPE=%s\\n' \"$WAYLAND_DISPLAY\" \"$DISPLAY\" \"$XDG_SESSION_TYPE\"; pgrep -a kwin_wayland 2>/dev/null || true")
    @mcp.tool()
    def git_status_global() -> dict[str, Any]: return command(c,"git_status_global","git --version; git config --global --show-origin --list 2>/dev/null || true; git config --system --show-origin --list 2>/dev/null || true")
    @mcp.tool()
    def git_config_global(key: str, value: str | None=None, unset: bool=False) -> dict[str, Any]: return command(c,"git_config_global",f"git config --global --unset-all {q(key)}" if unset else f"git config --global {q(key)} {q(value or '')}",mutation=True,request={"key":key,"value":value,"unset":unset})
    @mcp.tool()
    def github_ssh_test() -> dict[str, Any]: return command(c,"github_ssh_test","ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -T git@github.com 2>&1; code=$?; test $code -eq 0 -o $code -eq 1")
    @mcp.tool()
    def python_status() -> dict[str, Any]: return command(c,"python_status","command -v python || true; python --version 2>&1 || true; command -v python3 || true; python3 --version 2>&1 || true")
    @mcp.tool()
    def uv_status() -> dict[str, Any]: return command(c,"uv_status","command -v uv || true; uv --version 2>&1 || true; uv cache dir 2>/dev/null || true")
    @mcp.tool()
    def toolchain_status() -> dict[str, Any]: return command(c,"toolchain_status","for x in gcc clang make cmake ninja meson rustc cargo go node npm pnpm; do command -v \"$x\" >/dev/null && { printf '%s: ' \"$x\"; \"$x\" --version 2>&1 | head -1; }; done")
    @mcp.tool()
    def container_status() -> dict[str, Any]: return command(c,"container_status","docker --version 2>/dev/null || true; podman --version 2>/dev/null || true; systemctl status docker --no-pager 2>/dev/null || true; systemctl --user status podman.socket --no-pager 2>/dev/null || true")
