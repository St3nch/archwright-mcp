from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from ..errors import ArchwrightError
from ..receipts import now_iso
from .helpers import command, q


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def power_status() -> dict[str, Any]: return command(c,"power_status","powerprofilesctl get 2>/dev/null || true; powerprofilesctl list 2>/dev/null || true; for x in /sys/class/power_supply/AC* /sys/class/power_supply/BAT*; do [ -e \"$x\" ] || continue; echo \"[$x]\"; grep -H . \"$x\"/{online,status,capacity} 2>/dev/null || true; done")
    @mcp.tool()
    def suspend_test_prepare() -> dict[str, Any]:
        token=f"suspend_{uuid.uuid4().hex[:12]}"; path=c.settings.state_dir/"state"/f"{token}.json"; snapshot={"created_at":now_iso(),"identity":c.live_identity(),"network":c.transport.remote("ip -j address").stdout,"audio":c.transport.remote("wpctl status 2>/dev/null || true").stdout,"drm":c.transport.remote("find /sys/class/drm -maxdepth 2 -name status -print -exec cat {} \\; 2>/dev/null").stdout}; path.write_text(json.dumps(snapshot,indent=2)); return {"ok":True,"token":token,"snapshot":snapshot}
    @mcp.tool()
    def suspend(token: str | None=None) -> dict[str, Any]: return command(c,"suspend","systemd-run --on-active=1s --unit=archwright-suspend systemctl suspend",root=True,mutation=True,request={"token":token})
    @mcp.tool()
    def resume_verify(token: str) -> dict[str, Any]:
        path=c.settings.state_dir/"state"/f"{Path(token).name}.json"
        if not path.exists(): raise ArchwrightError("VALIDATION_FAILED","Suspend test token not found")
        before=json.loads(path.read_text()); after={"identity":c.live_identity(),"network":c.transport.remote("ip -j address").stdout,"audio":c.transport.remote("wpctl status 2>/dev/null || true").stdout,"drm":c.transport.remote("find /sys/class/drm -maxdepth 2 -name status -print -exec cat {} \\; 2>/dev/null").stdout}; return {"ok":before["identity"]["machine_id"]==after["identity"]["machine_id"],"before":before,"after":after}
    @mcp.tool()
    def hibernate_status() -> dict[str, Any]: return command(c,"hibernate_status","cat /sys/power/state; cat /sys/power/disk 2>/dev/null || true; swapon --show; systemctl status systemd-hibernate.service --no-pager 2>/dev/null || true")
    @mcp.tool()
    def lid_status() -> dict[str, Any]: return command(c,"lid_status","grep -R '^[^#].*HandleLidSwitch' /etc/systemd/logind.conf /etc/systemd/logind.conf.d 2>/dev/null || true; for x in /proc/acpi/button/lid/*/state; do cat \"$x\" 2>/dev/null; done")
    @mcp.tool()
    def sleep_configuration() -> dict[str, Any]: return command(c,"sleep_configuration","cat /sys/power/mem_sleep 2>/dev/null || true; systemd-analyze cat-config systemd/sleep.conf 2>/dev/null || true; systemd-analyze cat-config systemd/logind.conf 2>/dev/null || true")
    @mcp.tool()
    def reboot() -> dict[str, Any]: return command(c,"reboot","systemd-run --on-active=2s --unit=archwright-reboot systemctl reboot",root=True,mutation=True)
    @mcp.tool()
    def shutdown() -> dict[str, Any]:
        result=command(c,"shutdown","systemd-run --on-active=2s --unit=archwright-poweroff systemctl poweroff",root=True,mutation=True); result["warning"]="Target poweroff requires physical intervention to return."; return result
    @mcp.tool()
    def reboot_required() -> dict[str, Any]: return command(c,"reboot_required","running=$(uname -r); echo running=$running; for k in /usr/lib/modules/*; do [ -d \"$k\" ] && echo installed=$(basename \"$k\"); done; needs-restarting -r 2>/dev/null || true")
    @mcp.tool()
    def boot_verify() -> dict[str, Any]:
        verification=c.verify(require_protected_ro=True); failed=c.transport.remote("systemctl --failed --no-pager --plain").stdout; tunnel=c.transport.remote("systemctl is-active archwright-reverse-tunnel 2>/dev/null || true").stdout.strip(); return {"ok":verification["ok"] and not failed.strip(),"verification":verification,"failed_units":failed,"reverse_tunnel":tunnel}
    @mcp.tool()
    def receipt_get(receipt_id: str) -> dict[str, Any]: return {"ok":True,"receipt":c.receipts.get(receipt_id)}
    @mcp.tool()
    def receipt_list(limit: int=100) -> dict[str, Any]: return {"ok":True,"receipts":c.receipts.list(limit)}
    @mcp.tool()
    def change_summary(limit: int=500) -> dict[str, Any]: return {"ok":True,**c.receipts.summary(limit)}
    @mcp.tool()
    def bootstrap_status() -> dict[str, Any]:
        reachable=c.transport.reachable(); status:dict[str,Any]={"ok":reachable,"reachable":reachable}
        if reachable:
            try: status["verification"]=c.verify(require_protected_ro=True); status["sudo"]=c.transport.remote("sudo -n true").exit_code==0; status["failed_units"]=c.transport.remote("systemctl --failed --no-pager --plain").stdout
            except ArchwrightError as exc: status["ok"]=False; status["error"]=exc.as_dict()["error"]
        return status
    @mcp.tool()
    def bootstrap_self_test() -> dict[str, Any]:
        verification=c.mutation_gate(); user=c.execute(tool="self_test_user",script="printf 'archwright-user-ok\\n'",root=False,mutation=False); root=c.execute(tool="self_test_root",script="id -u; test $(id -u) -eq 0",root=True,mutation=True); path="/var/tmp/archwright-self-test"; write=c.execute(tool="self_test_file",script=f"printf 'archwright-self-test\\n' > {q(path)}; grep -Fx 'archwright-self-test' {q(path)}; rm -f {q(path)}",root=True,mutation=True); return {"ok":all(x.get("exit_code")==0 for x in [user,root,write]),"verification":verification,"user":user,"root":root,"file":write}
    @mcp.tool()
    def bootstrap_cleanup_preview() -> dict[str, Any]: return {"ok":True,"would_remove":["/etc/archwright/","/etc/sudoers.d/archwright-bootstrap","/etc/systemd/system/archwright-bootstrap-sshd.service","/etc/systemd/system/archwright-reverse-tunnel.service","/etc/systemd/system/archwright-protect-windows.service","/var/tmp/archwright/","user:arch-bootstrap"],"note":"Preview only. Cleanup requires explicit owner_authorized=true."}
    @mcp.tool()
    def bootstrap_cleanup(owner_authorized: bool=False) -> dict[str, Any]:
        if not owner_authorized: raise ArchwrightError("CLEANUP_NOT_AUTHORIZED","Owner authorization flag is required")
        script="""set -euo pipefail
systemctl disable --now archwright-reverse-tunnel.service 2>/dev/null || true
systemctl disable --now archwright-bootstrap-sshd.service 2>/dev/null || true
systemctl disable archwright-protect-windows.service 2>/dev/null || true
rm -f /etc/systemd/system/archwright-reverse-tunnel.service /etc/systemd/system/archwright-bootstrap-sshd.service /etc/systemd/system/archwright-protect-windows.service /etc/sudoers.d/archwright-bootstrap
rm -rf /etc/archwright /var/tmp/archwright
systemctl daemon-reload
systemd-run --on-active=3s --unit=archwright-final-user-cleanup /bin/bash -lc 'pkill -u arch-bootstrap || true; userdel -r arch-bootstrap 2>/dev/null || true'
"""; return c.execute(tool="bootstrap_cleanup",script=script,root=True,mutation=True,timeout_seconds=120,request_extra={"owner_authorized":True})
    @mcp.tool()
    def bootstrap_disable(owner_authorized: bool=False) -> dict[str, Any]:
        if not owner_authorized: raise ArchwrightError("CLEANUP_NOT_AUTHORIZED","Owner authorization flag is required")
        return {"ok":True,"owner_authorized":True,"operator_action_required":"sudo systemctl disable --now archwright-mcp.service","note":"The MCP does not grant the target authority to mutate the VPS controller."}
