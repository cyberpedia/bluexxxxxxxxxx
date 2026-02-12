#!/usr/bin/env bash
set -euo pipefail

# PHASE 0: Hardened Ubuntu 22.04 server bootstrap for Cerberus.
#
# This script applies baseline production hardening with secure defaults:
# - OS updates and minimal required packages
# - UFW policy (SSH + HTTP/HTTPS only)
# - Fail2ban (SSH + API rate/abuse protection)
# - Docker Engine + Docker Compose plugin
# - Dedicated least-privilege 'cerberus' system user
# - NTP via systemd-timesyncd
# - Hardened SSH daemon settings (no root / no passwords)
# - Log rotation policy for Cerberus and Docker logs
# - /opt/cerberus directory structure + permissions
#
# WARNING:
# - Run as root on Ubuntu 22.04 LTS.
# - Ensure SSH key access is configured BEFORE password login is disabled.
# - Test in staging before production rollout.

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Run this script as root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
readonly CERBERUS_USER="cerberus"
readonly CERBERUS_HOME="/opt/cerberus"

log() { printf '[INFO] %s\n' "$*"; }
backup_file() {
  local target="$1"
  if [[ -f "$target" ]]; then
    cp -a "$target" "${target}.bak.$(date +%Y%m%d%H%M%S)"
  fi
}

log "Updating package index and upgrading installed packages"
apt-get update
apt-get -y upgrade

log "Installing baseline security and utility packages"
apt-get install -y \
  ca-certificates curl gnupg lsb-release \
  ufw fail2ban auditd audispd-plugins \
  unattended-upgrades apt-listchanges \
  logrotate jq

log "Configuring unattended security updates"
cat > /etc/apt/apt.conf.d/52unattended-upgrades-local <<'EOC'
Unattended-Upgrade::Origins-Pattern {
  "origin=Ubuntu,archive=${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOC

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOC'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOC

log "Applying kernel/network hardening sysctl baseline"
cat > /etc/sysctl.d/99-cerberus-hardening.conf <<'EOC'
# Reduce information leaks and tighten network behavior
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2

# Basic anti-spoofing and safer TCP settings
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOC
sysctl --system >/dev/null

log "Configuring UFW (default deny inbound, allow outbound, allow 22/80/443)"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable

log "Configuring Fail2ban"
mkdir -p /etc/fail2ban/jail.d /var/log/cerberus
cat > /etc/fail2ban/jail.d/cerberus.local <<'EOC'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = 22
logpath = %(sshd_log)s
maxretry = 5

[cerberus-api]
enabled = true
port = http,https
filter = cerberus-api
logpath = /var/log/cerberus/api-access.log
maxretry = 30
findtime = 5m
bantime = 30m
EOC

cat > /etc/fail2ban/filter.d/cerberus-api.conf <<'EOC'
[Definition]
# Example pattern catches repeated 401/403/429 responses in a common access log format.
failregex = ^<HOST>\s+-\s+-\s+\[[^\]]+\]\s+"(GET|POST|PUT|PATCH|DELETE|OPTIONS)\s+[^\"]+\s+HTTP/[0-9.]+"\s+(401|403|429)\s+.*$
ignoreregex =
EOC

systemctl enable --now fail2ban

log "Installing Docker Engine + Docker Compose plugin from Docker repo"
install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
fi
chmod a+r /etc/apt/keyrings/docker.gpg

cat > /etc/apt/sources.list.d/docker.list <<EOC
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable
EOC

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

log "Creating dedicated least-privilege cerberus service user"
if ! id -u "${CERBERUS_USER}" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /home/${CERBERUS_USER} --shell /usr/sbin/nologin "${CERBERUS_USER}"
fi
usermod -aG docker "${CERBERUS_USER}"

log "Preparing /opt/cerberus directory layout"
install -d -m 0750 -o "${CERBERUS_USER}" -g "${CERBERUS_USER}" "${CERBERUS_HOME}"/{config,data,logs,run}

log "Enabling time sync (systemd-timesyncd)"
timedatectl set-ntp true
systemctl enable --now systemd-timesyncd

log "Hardening SSH daemon configuration"
install -d -m 0755 /etc/ssh/sshd_config.d
backup_file /etc/ssh/sshd_config.d/99-cerberus-hardening.conf
cat > /etc/ssh/sshd_config.d/99-cerberus-hardening.conf <<'EOC'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowAgentForwarding no
LoginGraceTime 30
Protocol 2
EOC

sshd -t
systemctl restart ssh

log "Setting stricter defaults for common sensitive files"
backup_file /etc/login.defs
sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs

log "Configuring log rotation for Cerberus and Docker container JSON logs"
cat > /etc/logrotate.d/cerberus <<'EOC'
/opt/cerberus/logs/*.log /var/log/cerberus/*.log {
  daily
  rotate 14
  compress
  delaycompress
  missingok
  notifempty
  create 0640 cerberus cerberus
  sharedscripts
  postrotate
    systemctl kill -s HUP cerberus@* >/dev/null 2>&1 || true
  endscript
}
EOC

mkdir -p /etc/docker
if [[ -f /etc/docker/daemon.json ]]; then
  backup_file /etc/docker/daemon.json
fi
cat > /etc/docker/daemon.json <<'EOC'
{
  "icc": false,
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  },
  "no-new-privileges": true
}
EOC
systemctl restart docker

log "Enabling key security services"
systemctl enable --now ufw
systemctl enable --now auditd
systemctl enable --now unattended-upgrades

log "PHASE 0 server setup completed successfully."
