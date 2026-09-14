from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from ..errors import ArchwrightError
from .helpers import command, q


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def network_status() -> dict[str, Any]:
        return command(c, "network_status", "ip -brief link; ip -brief address; ip route; ip -6 route; printf '\\n=== resolver ===\\n'; resolvectl status 2>/dev/null || cat /etc/resolv.conf; printf '\\n=== NM ===\\n'; nmcli general status 2>/dev/null || true")
    @mcp.tool()
    def network_ping(host: str, count: int = 4, timeout_seconds: int = 3) -> dict[str, Any]:
        return command(c,"network_ping",f"ping -c {max(1,min(count,20))} -W {max(1,min(timeout_seconds,30))} -- {q(host)}")
    @mcp.tool()
    def dns_lookup(name: str) -> dict[str, Any]: return command(c,"dns_lookup",f"getent ahosts {q(name)}; resolvectl query {q(name)} 2>/dev/null || true")
    @mcp.tool()
    def networkmanager_status() -> dict[str, Any]: return command(c,"networkmanager_status","systemctl status NetworkManager --no-pager 2>/dev/null || true; nmcli general status 2>/dev/null || true; nmcli device status 2>/dev/null || true; nmcli -f NAME,UUID,TYPE,DEVICE connection show 2>/dev/null || true")
    @mcp.tool()
    def wifi_scan(interface: str | None=None) -> dict[str, Any]:
        dev=f"ifname {q(interface)} " if interface else ""; return command(c,"wifi_scan",f"nmcli -f IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY device wifi list {dev}--rescan yes")
    @mcp.tool()
    def wifi_connect(ssid: str, passphrase: str | None=None, interface: str | None=None, hidden: bool=False) -> dict[str, Any]:
        args=f"nmcli device wifi connect {q(ssid)}" + (f" password {q(passphrase)}" if passphrase is not None else "") + (f" ifname {q(interface)}" if interface else "") + (" hidden yes" if hidden else "")
        return command(c,"wifi_connect",args,root=True,mutation=True,timeout=90,request={"ssid":ssid,"interface":interface,"hidden":hidden})
    @mcp.tool()
    def firewall_status() -> dict[str, Any]: return command(c,"firewall_status","if command -v ufw >/dev/null; then ufw status verbose; elif command -v firewall-cmd >/dev/null; then firewall-cmd --state; firewall-cmd --list-all; elif command -v nft >/dev/null; then nft list ruleset; else echo 'no supported firewall CLI detected'; fi",root=True)
    @mcp.tool()
    def firewall_manage(implementation: str, arguments: list[str]) -> dict[str, Any]:
        allowed={"ufw":"ufw","firewalld":"firewall-cmd","nft":"nft"}; exe=allowed.get(implementation)
        if not exe: raise ArchwrightError("VALIDATION_FAILED","Unsupported firewall implementation")
        return command(c,"firewall_manage",f"{exe} {' '.join(q(x) for x in arguments)}",root=True,mutation=True,request={"implementation":implementation,"arguments":arguments})
    @mcp.tool()
    def vps_connectivity_test(host: str, port: int=22, expected_hostkey_sha256: str | None=None) -> dict[str, Any]:
        if not 1 <= port <= 65535: raise ArchwrightError("VALIDATION_FAILED","Invalid port")
        cmd=f"getent ahosts {q(host)}; timeout 8 bash -c '</dev/tcp/{q(host)}/{port}' && echo tcp=ok || echo tcp=failed; ssh-keyscan -p {port} -T 5 {q(host)} 2>/dev/null | ssh-keygen -lf -"
        result=command(c,"vps_connectivity_test",cmd)
        if expected_hostkey_sha256:
            result["hostkey_match"]=expected_hostkey_sha256 in result.get("stdout",""); result["ok"]=result.get("ok",False) and result["hostkey_match"]
        return result
    @mcp.tool()
    def github_connectivity_test() -> dict[str, Any]: return command(c,"github_connectivity_test","getent ahosts github.com; timeout 8 bash -c '</dev/tcp/github.com/22' && echo tcp22=ok || true; ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -T git@github.com 2>&1 || test $? -eq 1")
    @mcp.tool()
    def ssh_status() -> dict[str, Any]: return command(c,"ssh_status","systemctl status archwright-bootstrap-sshd --no-pager 2>/dev/null || true; systemctl status sshd --no-pager 2>/dev/null || true; ss -ltnp | grep -E 'sshd|:22|:222' || true",root=True)
    @mcp.tool()
    def ssh_keygen(path: str, algorithm: str="ed25519", comment: str="archwright", owner: str="arch-bootstrap") -> dict[str, Any]:
        if algorithm not in {"ed25519","rsa"}: raise ArchwrightError("VALIDATION_FAILED","Unsupported key algorithm")
        parent=str(PurePosixPath(path).parent); bits="-b 4096" if algorithm=="rsa" else ""
        return command(c,"ssh_keygen",f"install -d -m700 -o {q(owner)} -g {q(owner)} {q(parent)}; sudo -u {q(owner)} ssh-keygen -q -t {algorithm} {bits} -N '' -C {q(comment)} -f {q(path)}",root=True,mutation=True,request={"path":path,"algorithm":algorithm,"comment":comment})
    @mcp.tool()
    def ssh_authorized_keys(user: str, action: str="list", public_key: str | None=None) -> dict[str, Any]:
        home=f"$(getent passwd {q(user)} | cut -d: -f6)"; path=f"{home}/.ssh/authorized_keys"
        if action=="list": return command(c,"ssh_authorized_keys",f"cat {path} 2>/dev/null || true",root=True)
        if not public_key or "\n" in public_key or not re.match(r"^ssh-(ed25519|rsa) ", public_key): raise ArchwrightError("VALIDATION_FAILED","Valid public_key required")
        if action=="add": cmd=f"h={home}; install -d -m700 -o {q(user)} -g {q(user)} \"$h/.ssh\"; touch \"$h/.ssh/authorized_keys\"; chown {q(user)}:{q(user)} \"$h/.ssh/authorized_keys\"; chmod 600 \"$h/.ssh/authorized_keys\"; grep -Fxq {q(public_key)} \"$h/.ssh/authorized_keys\" || printf '%s\\n' {q(public_key)} >> \"$h/.ssh/authorized_keys\""
        elif action=="remove": cmd=f"h={home}; f=\"$h/.ssh/authorized_keys\"; [ -f \"$f\" ] || exit 0; tmp=$(mktemp); grep -Fvx {q(public_key)} \"$f\" > \"$tmp\" || true; install -m600 -o {q(user)} -g {q(user)} \"$tmp\" \"$f\"; rm -f \"$tmp\""
        else: raise ArchwrightError("VALIDATION_FAILED","Unsupported action")
        return command(c,"ssh_authorized_keys",cmd,root=True,mutation=True,request={"user":user,"action":action,"public_key_fingerprint_only":True})
    @mcp.tool()
    def ssh_known_hosts(action: str, host: str, fingerprint: str | None=None, port: int=22, user: str="arch-bootstrap") -> dict[str, Any]:
        path=f"$(getent passwd {q(user)} | cut -d: -f6)/.ssh/known_hosts"
        if action=="inspect": return command(c,"ssh_known_hosts",f"ssh-keygen -F {q(host)} -f {path} 2>/dev/null || true",root=True)
        if action=="remove": return command(c,"ssh_known_hosts",f"ssh-keygen -R {q(host)} -f {path}",root=True,mutation=True)
        if action!="add": raise ArchwrightError("VALIDATION_FAILED","Unsupported action")
        scan=f"ssh-keyscan -p {port} -T5 {q(host)}"
        if fingerprint: scan+=f" | tee /tmp/aw-keyscan | ssh-keygen -lf - | grep -F {q(fingerprint)} >/dev/null && cat /tmp/aw-keyscan"
        cmd=f"h=$(getent passwd {q(user)} | cut -d: -f6); install -d -m700 -o {q(user)} -g {q(user)} \"$h/.ssh\"; {scan} >> \"$h/.ssh/known_hosts\"; chown {q(user)}:{q(user)} \"$h/.ssh/known_hosts\"; chmod 600 \"$h/.ssh/known_hosts\""
        return command(c,"ssh_known_hosts",cmd,root=True,mutation=True,request={"host":host,"port":port,"fingerprint":fingerprint})
    @mcp.tool()
    def ssh_test(host: str, user: str, port: int=22, command_text: str="true", identity_file: str | None=None) -> dict[str, Any]:
        ident=f"-i {q(identity_file)} -o IdentitiesOnly=yes" if identity_file else ""; return command(c,"ssh_test",f"ssh -p {port} {ident} -o BatchMode=yes -o ConnectTimeout=8 {q(user)}@{q(host)} {q(command_text)}")
    @mcp.tool()
    def reverse_tunnel_status() -> dict[str, Any]:
        local=c.settings.endpoint; return command(c,"reverse_tunnel_status","systemctl status archwright-reverse-tunnel --no-pager 2>/dev/null || true; journalctl -u archwright-reverse-tunnel --no-pager -n 80 2>/dev/null || true") | {"controller_endpoint":{"host":local.host,"port":local.port}}
    @mcp.tool()
    def reverse_tunnel_restart() -> dict[str, Any]: return command(c,"reverse_tunnel_restart","systemctl restart archwright-reverse-tunnel",root=True,mutation=True,request={})
