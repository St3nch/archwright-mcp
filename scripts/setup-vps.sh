#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then echo "run as root" >&2; exit 1; fi
: "${ARCHWRIGHT_TUNNEL_PUBKEY:?set ARCHWRIGHT_TUNNEL_PUBKEY to the target tunnel public key}"
TUNNEL_USER=archwright-tunnel
MCP_USER=archwright
id "${MCP_USER}" >/dev/null 2>&1 || useradd --system --home /var/lib/archwright --create-home --shell /usr/bin/nologin "${MCP_USER}"
id "${TUNNEL_USER}" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "${TUNNEL_USER}"
install -d -m700 -o "${TUNNEL_USER}" -g "${TUNNEL_USER}" "/home/${TUNNEL_USER}/.ssh"
printf '%s %s\n' 'restrict,port-forwarding,permitlisten="127.0.0.1:2222"' "${ARCHWRIGHT_TUNNEL_PUBKEY}" > "/home/${TUNNEL_USER}/.ssh/authorized_keys"
chown "${TUNNEL_USER}:${TUNNEL_USER}" "/home/${TUNNEL_USER}/.ssh/authorized_keys"
chmod 600 "/home/${TUNNEL_USER}/.ssh/authorized_keys"
install -d -m750 -o root -g "${MCP_USER}" /etc/archwright
install -d -m750 -o "${MCP_USER}" -g "${MCP_USER}" /var/lib/archwright /var/lib/archwright/staging
echo "VPS tunnel identity prepared. Ensure sshd permits remote forwarding for ${TUNNEL_USER} and GatewayPorts remains no."
