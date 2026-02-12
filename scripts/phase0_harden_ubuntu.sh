#!/usr/bin/env bash
# Harden Ubuntu 22.04 LTS host for Cerberus production deployment.
# This script applies opinionated CIS-style controls and bootstrap infra dependencies.
#
# Usage:
#   sudo bash scripts/phase0_harden_ubuntu.sh
#
# Security notes:
# - Run from a trusted administrative session.
# - Ensure an SSH public key already exists for your admin user before disabling password auth.
# - Review all values in the "Configurable settings" block before execution.

set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Run as root (sudo)."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# -----------------------------
# Configurable settings
# -----------------------------
CERBERUS_USER="cerberus"
CERBERUS_GROUP="cerberus"
CERBERUS_HOME="/home/${CERBERUS_USER}"
CERBERUS_DIR="/opt/cerberus"
ADMIN_GROUP="sudo"
SSH_PORT="22"
API_PROTECT_PORT="8080" # adjust to Cerberus API port
TIMEZONE="UTC"

log() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }

ensure_pkg() {
  local pkg="$1"
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    apt-get install -y "$pkg"
  fi
}

log "Updating package metadata and applying security updates..."
apt-get update -y
apt-get upgrade -y
apt-get install -y unattended-upgrades apt-listchanges ca-certificates curl gnupg lsb-release

dpkg-reconfigure -f noninteractive unattended-upgrades

log "Setting timezone and enabling time synchronization (chrony)..."
ensure_pkg chrony
timedatectl set-timezone "$TIMEZONE"
systemctl enable --now chrony

log "Applying baseline kernel/network hardening (CIS-style sysctl controls)..."
cat >/etc/sysctl.d/99-cerberus-hardening.conf <<'SYSCTL'
# Prevent IP spoofing and bad redirects
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable SYN cookies and log suspicious packets
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Restrict ptrace and core dumps
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
SYSCTL
sysctl --system >/dev/null

log "Disabling uncommon filesystems (CIS recommendation)..."
cat >/etc/modprobe.d/cerberus-disable-fs.conf <<'MODPROBE'
install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install squashfs /bin/true
install udf /bin/true
MODPROBE

log "Securing shared memory mount options..."
if ! grep -qE '^tmpfs\s+/dev/shm\s+tmpfs\s+.*nosuid.*nodev.*noexec' /etc/fstab; then
  cp /etc/fstab /etc/fstab.bak.$(date +%F-%H%M%S)
  echo 'tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0' >>/etc/fstab
  mount -o remount /dev/shm || warn "Could not remount /dev/shm immediately; reboot required."
fi

log "Installing and configuring UFW (allow SSH, HTTP, HTTPS only)..."
ensure_pkg ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}"/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable

log "Installing and configuring Fail2ban for SSH and API protection..."
ensure_pkg fail2ban
cat >/etc/fail2ban/jail.d/cerberus.local <<EOFJAIL
[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
maxretry = 5
findtime = 10m
bantime = 1h

[cerberus-api]
enabled = true
port = ${API_PROTECT_PORT}
filter = cerberus-api
logpath = /var/log/cerberus/api.log
maxretry = 10
findtime = 10m
bantime = 2h
EOFJAIL

cat >/etc/fail2ban/filter.d/cerberus-api.conf <<'EOFFILTER'
[Definition]
# Update regex to match your API auth failure messages.
failregex = ^.*(Failed login|Invalid token|Unauthorized).*$
ignoreregex =
EOFFILTER

systemctl enable --now fail2ban

log "Installing Docker Engine + Docker Compose plugin from Docker repository..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

ARCH="$(dpkg --print-architecture)"
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" \
  >/etc/apt/sources.list.d/docker.list

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

log "Creating dedicated least-privilege user/group for Cerberus..."
if ! getent group "$CERBERUS_GROUP" >/dev/null; then
  groupadd --system "$CERBERUS_GROUP"
fi
if ! id -u "$CERBERUS_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$CERBERUS_HOME" --shell /usr/sbin/nologin --gid "$CERBERUS_GROUP" "$CERBERUS_USER"
fi

# Permit service control by admins and runtime by cerberus user only.
usermod -aG docker "$CERBERUS_USER"
install -d -o "$CERBERUS_USER" -g "$CERBERUS_GROUP" -m 0750 "$CERBERUS_DIR"
install -d -o root -g "$CERBERUS_GROUP" -m 0750 /var/log/cerberus
touch /var/log/cerberus/api.log
chown "$CERBERUS_USER":"$CERBERUS_GROUP" /var/log/cerberus/api.log
chmod 0640 /var/log/cerberus/api.log

log "Hardening OpenSSH daemon configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F-%H%M%S)

# Ensure secure settings (append if missing; replace if existing)
set_ssh_option() {
  local key="$1" value="$2"
  if grep -qiE "^\s*${key}\s+" /etc/ssh/sshd_config; then
    sed -i -E "s#^\s*${key}\s+.*#${key} ${value}#I" /etc/ssh/sshd_config
  else
    echo "${key} ${value}" >> /etc/ssh/sshd_config
  fi
}

set_ssh_option "Port" "$SSH_PORT"
set_ssh_option "Protocol" "2"
set_ssh_option "PermitRootLogin" "no"
set_ssh_option "PasswordAuthentication" "no"
set_ssh_option "KbdInteractiveAuthentication" "no"
set_ssh_option "ChallengeResponseAuthentication" "no"
set_ssh_option "UsePAM" "yes"
set_ssh_option "X11Forwarding" "no"
set_ssh_option "ClientAliveInterval" "300"
set_ssh_option "ClientAliveCountMax" "2"
set_ssh_option "MaxAuthTries" "4"
set_ssh_option "AllowTcpForwarding" "no"
set_ssh_option "AllowAgentForwarding" "no"
set_ssh_option "LoginGraceTime" "30"

sshd -t
systemctl restart ssh

log "Configuring logrotate policy for Cerberus logs..."
cat >/etc/logrotate.d/cerberus <<'EOFLOGROTATE'
/var/log/cerberus/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 cerberus cerberus
    sharedscripts
    postrotate
        systemctl kill -s HUP cerberus@*.service >/dev/null 2>&1 || true
    endscript
}
EOFLOGROTATE

log "Enabling audit daemon for accountability (CIS-aligned)..."
ensure_pkg auditd
systemctl enable --now auditd

log "Final status summary..."
ufw status verbose
fail2ban-client status
systemctl is-active chrony docker ssh fail2ban auditd

log "Phase 0 bootstrap complete."
log "IMPORTANT: Validate access from a separate SSH session before closing current session."
