#!/usr/bin/env bash
set -euo pipefail

# PHASE 0: Hardened Ubuntu 22.04 LTS setup for Cerberus
# Security posture: CIS-style baseline hardening with practical production defaults.
#
# Usage:
#   sudo bash scripts/phase0_hardened_setup.sh
#
# Notes:
# - Test this script on a staging host before production rollout.
# - Ensure at least one SSH key-based admin account exists before disabling password auth.
# - The script is intentionally idempotent where feasible.

if [[ ${EUID} -ne 0 ]]; then
  echo "[ERROR] Run as root (sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

CERBERUS_USER="cerberus"
CERBERUS_GROUP="cerberus"
CERBERUS_HOME="/opt/cerberus"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_HARDEN_FILE="${SSHD_DROPIN_DIR}/99-cerberus-hardening.conf"
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
SYSCTL_HARDEN_FILE="/etc/sysctl.d/99-cerberus-hardening.conf"
JOURNALD_HARDEN_FILE="/etc/systemd/journald.conf.d/99-cerberus.conf"
LOGROTATE_CERBERUS_FILE="/etc/logrotate.d/cerberus"
DOCKER_DAEMON_FILE="/etc/docker/daemon.json"

log() {
  printf '\n[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"
}

backup_file() {
  local file="$1"
  if [[ -f "$file" && ! -f "${file}.bak" ]]; then
    cp -a "$file" "${file}.bak"
    log "Backed up $file to ${file}.bak"
  fi
}

log "Updating apt package metadata and upgrading installed packages"
apt-get update -y
apt-get upgrade -y

log "Installing baseline security and operations packages"
apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  ufw \
  fail2ban \
  unattended-upgrades \
  apt-listchanges \
  chrony \
  logrotate \
  auditd \
  audispd-plugins

# -------- CIS-style kernel/network hardening --------
log "Applying sysctl hardening settings"
cat > "$SYSCTL_HARDEN_FILE" <<'SYSCTL_EOF'
# Cerberus host hardening (CIS-inspired)
# IP forwarding disabled unless explicitly needed
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Redirects and source routing protections
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Logging suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN flood and spoofing resistance
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirect acceptance
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
SYSCTL_EOF
sysctl --system >/dev/null

# -------- Automatic security updates --------
log "Enabling unattended upgrades for security patches"
dpkg-reconfigure -f noninteractive unattended-upgrades

# -------- Time synchronization --------
log "Configuring chrony NTP time synchronization"
systemctl enable --now chrony

# -------- SSH hardening --------
log "Hardening SSH configuration"
mkdir -p "$SSHD_DROPIN_DIR"
backup_file "$SSHD_HARDEN_FILE"
cat > "$SSHD_HARDEN_FILE" <<'SSH_EOF'
# Cerberus SSH hardening
# Use key-based auth only; prohibit direct root login.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
SSH_EOF

sshd -t
systemctl restart ssh

# -------- Firewall --------
log "Configuring UFW firewall with least privilege"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# -------- Fail2ban --------
log "Configuring Fail2ban for SSH and API abuse protection"
backup_file "$FAIL2BAN_JAIL_LOCAL"
cat > "$FAIL2BAN_JAIL_LOCAL" <<'F2B_EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
usedns = warn
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 5

# API brute-force / abuse protection
# Adjust "logpath" to your reverse-proxy or app auth-failure log.
[cerberus-api]
enabled = true
port = http,https
filter = cerberus-api
logpath = /var/log/nginx/access.log
maxretry = 30
findtime = 5m
bantime = 30m
F2B_EOF

cat > /etc/fail2ban/filter.d/cerberus-api.conf <<'F2B_FILTER_EOF'
[Definition]
# Example pattern catches repeated 401/403 calls for same source.
# Tune for your actual API and log format.
failregex = ^<HOST> - .* "(GET|POST|PUT|PATCH|DELETE).+" (401|403) .*$
ignoreregex =
F2B_FILTER_EOF

systemctl enable --now fail2ban
systemctl restart fail2ban

# -------- Docker + Docker Compose --------
log "Installing Docker Engine and Docker Compose plugin"
install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
fi

ARCH="$(dpkg --print-architecture)"
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
cat > /etc/apt/sources.list.d/docker.list <<EOF_DOCKER_REPO
deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable
EOF_DOCKER_REPO

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

mkdir -p /etc/docker
cat > "$DOCKER_DAEMON_FILE" <<'DOCKER_EOF'
{
  "icc": false,
  "live-restore": true,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  }
}
DOCKER_EOF

systemctl daemon-reload
systemctl enable --now docker
systemctl restart docker

# -------- Least-privilege service user --------
log "Creating least-privilege cerberus service account"
if ! getent group "$CERBERUS_GROUP" >/dev/null; then
  groupadd --system "$CERBERUS_GROUP"
fi

if ! id -u "$CERBERUS_USER" >/dev/null 2>&1; then
  useradd --system \
    --gid "$CERBERUS_GROUP" \
    --home-dir "$CERBERUS_HOME" \
    --create-home \
    --shell /usr/sbin/nologin \
    "$CERBERUS_USER"
fi

# Optional: enable Docker access only if required by your deployment model.
# usermod -aG docker "$CERBERUS_USER"

log "Preparing Cerberus directory structure"
mkdir -p "$CERBERUS_HOME"/{bin,config,data,logs}
chown -R "$CERBERUS_USER":"$CERBERUS_GROUP" "$CERBERUS_HOME"
chmod 0750 "$CERBERUS_HOME"
chmod -R o-rwx "$CERBERUS_HOME"/{config,data,logs}

# -------- Journald and log rotation --------
log "Configuring journald retention and persistence"
mkdir -p /etc/systemd/journald.conf.d
cat > "$JOURNALD_HARDEN_FILE" <<'JOURNALD_EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=1G
MaxFileSec=1month
ForwardToSyslog=no
JOURNALD_EOF
systemctl restart systemd-journald

log "Creating logrotate policy for Cerberus logs"
cat > "$LOGROTATE_CERBERUS_FILE" <<'LOGROTATE_EOF'
/opt/cerberus/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 0640 cerberus cerberus
}
LOGROTATE_EOF

# -------- Ensure key services are running --------
log "Enabling critical services"
systemctl enable --now ssh ufw auditd

log "Hardening setup complete. Review validation commands in docs/phase0_validation_and_rollback.md"
