# Phase 0 Validation and Rollback Guide

This guide validates each component configured by `scripts/phase0_hardened_setup.sh` and provides rollback actions.

## Validation commands

Run commands as root (or prefix with `sudo`).

### 1) OS updates and unattended upgrades
```bash
apt-cache policy unattended-upgrades
systemctl is-enabled unattended-upgrades
```

### 2) Sysctl hardening applied
```bash
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.tcp_syncookies
```
Expected:
- `net.ipv4.ip_forward = 0`
- `net.ipv4.conf.all.accept_redirects = 0`
- `net.ipv4.tcp_syncookies = 1`

### 3) UFW firewall
```bash
ufw status verbose
```
Expected:
- Default incoming: deny
- Allowed inbound ports: 22, 80, 443 only

### 4) Fail2ban
```bash
systemctl status fail2ban --no-pager
fail2ban-client status
fail2ban-client status sshd
fail2ban-client status cerberus-api
```

### 5) Docker and Compose
```bash
docker --version
docker compose version
systemctl is-active docker
cat /etc/docker/daemon.json
```

### 6) cerberus least-privilege account and directories
```bash
id cerberus
getent passwd cerberus
namei -l /opt/cerberus
ls -ld /opt/cerberus /opt/cerberus/config /opt/cerberus/data /opt/cerberus/logs
```
Expected:
- shell is `/usr/sbin/nologin`
- `/opt/cerberus` owned by `cerberus:cerberus`
- restrictive permissions on config/data/logs

### 7) NTP/chrony time sync
```bash
systemctl is-active chrony
chronyc tracking
chronyc sources -v
```

### 8) SSH hardening
```bash
sshd -T | egrep 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|maxauthtries'
```
Expected:
- `permitrootlogin no`
- `passwordauthentication no`
- `kbdinteractiveauthentication no`
- `maxauthtries 3`

### 9) Journald and log rotation
```bash
systemctl is-active systemd-journald
journalctl --disk-usage
logrotate --debug /etc/logrotate.d/cerberus
```

### 10) Audit subsystem
```bash
systemctl is-active auditd
auditctl -s
```

## Rollback instructions

> Rollback carefully and preserve emergency console access before modifying SSH/firewall controls.

### A) SSH rollback (restore password auth/root login if emergency)
```bash
cp -a /etc/ssh/sshd_config.d/99-cerberus-hardening.conf /etc/ssh/sshd_config.d/99-cerberus-hardening.conf.rollback
rm -f /etc/ssh/sshd_config.d/99-cerberus-hardening.conf
systemctl restart ssh
```

### B) UFW rollback
```bash
ufw disable
# optional reset if needed:
# ufw --force reset
```

### C) Fail2ban rollback
```bash
systemctl stop fail2ban
systemctl disable fail2ban
rm -f /etc/fail2ban/jail.local /etc/fail2ban/filter.d/cerberus-api.conf
systemctl restart fail2ban || true
```

### D) Docker rollback
```bash
systemctl stop docker
apt-get remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.gpg /etc/docker/daemon.json
apt-get update -y
```

### E) Sysctl rollback
```bash
rm -f /etc/sysctl.d/99-cerberus-hardening.conf
sysctl --system
```

### F) chrony rollback (if another NTP solution is used)
```bash
systemctl stop chrony
systemctl disable chrony
apt-get remove -y chrony
```

### G) cerberus account and directories rollback
```bash
systemctl stop cerberus@* 2>/dev/null || true
userdel cerberus || true
groupdel cerberus || true
rm -rf /opt/cerberus
```

### H) journald/logrotate rollback
```bash
rm -f /etc/systemd/journald.conf.d/99-cerberus.conf /etc/logrotate.d/cerberus
systemctl restart systemd-journald
```

### I) unattended upgrades rollback
```bash
apt-get remove -y unattended-upgrades apt-listchanges
```
