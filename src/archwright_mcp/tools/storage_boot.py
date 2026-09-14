from __future__ import annotations

from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from ..errors import ArchwrightError
from .helpers import command, q


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def mount_list() -> dict[str, Any]: return command(c, "mount_list", "findmnt -J")
    @mcp.tool()
    def mount(source: str, target: str, fstype: str | None = None, options: str | None = None) -> dict[str, Any]:
        args=[]
        if fstype: args += ["-t", q(fstype)]
        if options: args += ["-o", q(options)]
        return command(c,"mount",f"mount {' '.join(args)} -- {q(source)} {q(target)}",root=True,mutation=True,request={"source":source,"target":target})
    @mcp.tool()
    def unmount(target: str, lazy: bool=False) -> dict[str, Any]: return command(c,"unmount",f"umount {'-l' if lazy else ''} -- {q(target)}",root=True,mutation=True,request={"target":target,"lazy":lazy})
    @mcp.tool()
    def filesystem_usage(path: str="/") -> dict[str, Any]: return command(c,"filesystem_usage",f"df -hT -- {q(path)}; df -hi -- {q(path)}")
    @mcp.tool()
    def filesystem_info(path: str="/") -> dict[str, Any]: return command(c,"filesystem_info",f"findmnt -J -T {q(path)}; src=$(findmnt -no SOURCE -T {q(path)}); blkid \"$src\" 2>/dev/null || true")
    @mcp.tool()
    def swap_status() -> dict[str, Any]: return command(c,"swap_status","swapon --show --bytes --output=NAME,TYPE,SIZE,USED,PRIO --noheadings; zramctl 2>/dev/null || true")
    @mcp.tool()
    def fstab_read() -> dict[str, Any]: return command(c,"fstab_read","cat /etc/fstab; printf '\\n=== findmnt verify ===\\n'; findmnt --verify --verbose || true")
    @mcp.tool()
    def fstab_validate() -> dict[str, Any]: return command(c,"fstab_validate","findmnt --verify --verbose")
    @mcp.tool()
    def protected_storage_status() -> dict[str, Any]: return c.protected_storage_status()
    @mcp.tool()
    def protected_storage_enforce() -> dict[str, Any]:
        verification=c.verify(require_protected_ro=False); mismatches=[x for x in verification["mismatches"] if x["field"]!="protected_storage"]
        if mismatches: raise ArchwrightError("TARGET_IDENTITY_MISMATCH","Cannot enforce protection on mismatched target",{"mismatches":mismatches})
        return c.enforce_protected_storage()
    @mcp.tool()
    def boot_status() -> dict[str, Any]: return command(c,"boot_status","test -d /sys/firmware/efi && echo firmware=uefi || echo firmware=legacy; bootctl status 2>/dev/null || true; findmnt /boot /boot/efi 2>/dev/null || true")
    @mcp.tool()
    def efi_entries() -> dict[str, Any]: return command(c,"efi_entries","efibootmgr -v",root=True)
    @mcp.tool()
    def kernel_status() -> dict[str, Any]: return command(c,"kernel_status","uname -a; pacman -Q linux linux-lts linux-zen linux-hardened 2>/dev/null || true; ls -l /boot/vmlinuz-* 2>/dev/null || true")
    @mcp.tool()
    def initramfs_status() -> dict[str, Any]: return command(c,"initramfs_status","cat /etc/mkinitcpio.conf 2>/dev/null || true; find /etc/mkinitcpio.d -maxdepth 1 -type f -print -exec cat {} \\; 2>/dev/null || true; ls -lh /boot/*initramfs* 2>/dev/null || true")
    @mcp.tool()
    def initramfs_rebuild(preset: str | None=None) -> dict[str, Any]: return command(c,"initramfs_rebuild",f"mkinitcpio -p {q(preset)}" if preset else "mkinitcpio -P",root=True,mutation=True,timeout=900)
    @mcp.tool()
    def microcode_status() -> dict[str, Any]: return command(c,"microcode_status","pacman -Q intel-ucode amd-ucode 2>/dev/null || true; journalctl -k -b --no-pager | grep -i microcode | tail -30 || true")
    @mcp.tool()
    def secure_boot_status() -> dict[str, Any]: return command(c,"secure_boot_status","if command -v mokutil >/dev/null; then mokutil --sb-state; elif command -v bootctl >/dev/null; then bootctl status | grep -i 'secure boot' || true; else hexdump -Cv /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | tail -1 || true; fi")
