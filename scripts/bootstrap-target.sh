#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

: "${ARCHWRIGHT_CONTROLLER_PUBKEY:?set ARCHWRIGHT_CONTROLLER_PUBKEY to the VPS controller public key}"
: "${ARCHWRIGHT_VPS_HOST:?set ARCHWRIGHT_VPS_HOST to the VPS hostname/IP}"
: "${ARCHWRIGHT_VPS_HOSTKEY:?set ARCHWRIGHT_VPS_HOSTKEY to a pinned known_hosts line for the VPS}"
: "${ARCHWRIGHT_PROTECTED_SERIALS:?set ARCHWRIGHT_PROTECTED_SERIALS to space-separated protected disk serials}"

BOOTSTRAP_USER=arch-bootstrap
SSHD_PORT=22222

pacman -S --needed --noconfirm openssh sudo util-linux

if ! id "${BOOTSTRAP_USER}" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "${BOOTSTRAP_USER}"
fi

install -d -m 700 -o "${BOOTSTRAP_USER}" -g "${BOOTSTRAP_USER}" "/home/${BOOTSTRAP_USER}/.ssh"
printf '%s\n' "${ARCHWRIGHT_CONTROLLER_PUBKEY}" > "/home/${BOOTSTRAP_USER}/.ssh/authorized_keys"
chown "${BOOTSTRAP_USER}:${BOOTSTRAP_USER}" "/home/${BOOTSTRAP_USER}/.ssh/authorized_keys"
chmod 600 "/home/${BOOTSTRAP_USER}/.ssh/authorized_keys"

cat > /etc/sudoers.d/archwright-bootstrap <<EOF
${BOOTSTRAP_USER} ALL=(ALL:ALL) NOPASSWD: ALL
EOF
chmod 440 /etc/sudoers.d/archwright-bootstrap
visudo -cf /etc/sudoers.d/archwright-bootstrap

install -d -m 700 -o root -g root /etc/archwright
install -d -m 700 -o root -g root /usr/local/lib/archwright
install -d -m 700 -o "${BOOTSTRAP_USER}" -g "${BOOTSTRAP_USER}" /var/tmp/archwright

for key in rsa ecdsa ed25519; do
  path="/etc/archwright/ssh_host_${key}_key"
  if [[ ! -f "${path}" ]]; then
    ssh-keygen -q -N '' -t "${key}" -f "${path}"
  fi
done

cat > /etc/archwright/sshd_config <<EOF
Port ${SSHD_PORT}
ListenAddress 127.0.0.1
Protocol 2
HostKey /etc/archwright/ssh_host_rsa_key
HostKey /etc/archwright/ssh_host_ecdsa_key
HostKey /etc/archwright/ssh_host_ed25519_key
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers ${BOOTSTRAP_USER}
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
UsePAM yes
Subsystem sftp internal-sftp
LogLevel VERBOSE
EOF
sshd -t -f /etc/archwright/sshd_config

cat > /usr/local/lib/archwright/protect-disks <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
file=/etc/archwright/protected-serials
[[ -r "$file" ]] || exit 0
mapfile -t serials < <(tr ' ' '\n' < "$file" | sed '/^$/d')
for serial in "${serials[@]}"; do
  path=$(lsblk -dnpo PATH,SERIAL | awk -v s="$serial" '$2==s {print $1; exit}')
  if [[ -z "$path" ]]; then
    echo "protected serial not found: $serial" >&2
    exit 20
  fi
  blockdev --setro "$path"
  ro=$(lsblk -dnro RO "$path")
  if [[ "$ro" != "1" ]]; then
    echo "failed to enforce read-only: $serial ($path)" >&2
    exit 21
  fi
  echo "protected read-only: $serial ($path)"
done
EOF
chmod 700 /usr/local/lib/archwright/protect-disks
printf '%s\n' "${ARCHWRIGHT_PROTECTED_SERIALS}" > /etc/archwright/protected-serials
chmod 600 /etc/archwright/protected-serials

install -m 644 /dev/stdin /etc/systemd/system/archwright-bootstrap-sshd.service <<'EOF'
[Unit]
Description=Archwright temporary loopback SSH daemon
After=network.target
Before=archwright-reverse-tunnel.service
[Service]
Type=simple
ExecStartPre=/usr/bin/sshd -t -f /etc/archwright/sshd_config
ExecStart=/usr/bin/sshd -D -e -f /etc/archwright/sshd_config
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF

install -m 644 /dev/stdin /etc/systemd/system/archwright-protect-windows.service <<'EOF'
[Unit]
Description=Archwright protected disk read-only enforcement
After=systemd-udev-settle.service
Before=archwright-reverse-tunnel.service
Wants=systemd-udev-settle.service
[Service]
Type=oneshot
ExecStart=/usr/local/lib/archwright/protect-disks
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

if [[ ! -f "/home/${BOOTSTRAP_USER}/.ssh/archwright_tunnel_ed25519" ]]; then
  sudo -u "${BOOTSTRAP_USER}" ssh-keygen -q -t ed25519 -N '' -C archwright-target-tunnel -f "/home/${BOOTSTRAP_USER}/.ssh/archwright_tunnel_ed25519"
fi
printf '%s\n' "${ARCHWRIGHT_VPS_HOSTKEY}" > "/home/${BOOTSTRAP_USER}/.ssh/known_hosts"
chown "${BOOTSTRAP_USER}:${BOOTSTRAP_USER}" "/home/${BOOTSTRAP_USER}/.ssh/known_hosts"
chmod 600 "/home/${BOOTSTRAP_USER}/.ssh/known_hosts"

cat > /etc/systemd/system/archwright-reverse-tunnel.service <<EOF
[Unit]
Description=Archwright temporary reverse SSH tunnel to VPS
After=network-online.target archwright-bootstrap-sshd.service archwright-protect-windows.service
Wants=network-online.target
Requires=archwright-bootstrap-sshd.service archwright-protect-windows.service
[Service]
Type=simple
User=${BOOTSTRAP_USER}
ExecStart=/usr/bin/ssh -NT -i /home/${BOOTSTRAP_USER}/.ssh/archwright_tunnel_ed25519 -o BatchMode=yes -o IdentitiesOnly=yes -o UserKnownHostsFile=/home/${BOOTSTRAP_USER}/.ssh/known_hosts -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -R 127.0.0.1:2222:127.0.0.1:${SSHD_PORT} archwright-tunnel@${ARCHWRIGHT_VPS_HOST}
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now archwright-protect-windows.service
systemctl enable --now archwright-bootstrap-sshd.service

echo
echo "Target-side bootstrap prepared."
echo "Tunnel public key (install on VPS archwright-tunnel account):"
cat "/home/${BOOTSTRAP_USER}/.ssh/archwright_tunnel_ed25519.pub"
echo
echo "After the VPS key is authorized, run:"
echo "  systemctl enable --now archwright-reverse-tunnel.service"
