# Phase 0 Validation and Rollback Guide

This guide validates each component installed by `scripts/phase0_harden_ubuntu.sh` and provides rollback procedures.

## Validation Commands

Run as root or with `sudo`.

### 1) CIS-style hardening / sysctl
```bash
sudo sysctl -a | egrep 'rp_filter|accept_redirects|send_redirects|tcp_syncookies|ptrace_scope|kptr_restrict|dmesg_restrict'
sudo cat /etc/sysctl.d/99-cerberus-hardening.conf
```

### 2) UFW firewall (SSH + HTTP/HTTPS only)
```bash
sudo ufw status numbered
sudo ss -tulpen
```
Expected: UFW enabled, inbound allows only TCP 22/80/443.

### 3) Fail2ban (SSH + API jail)
```bash
sudo systemctl status fail2ban --no-pager
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client status cerberus-api
sudo cat /etc/fail2ban/jail.d/cerberus.local
```

### 4) Docker + Compose plugin
```bash
sudo systemctl status docker --no-pager
sudo docker version
sudo docker compose version
```

### 5) Dedicated cerberus user + least privilege paths
```bash
id cerberus
getent passwd cerberus
namei -l /opt/cerberus
ls -ld /opt/cerberus /var/log/cerberus
```
Expected: `cerberus` system user, `/opt/cerberus` mode 750 owned by `cerberus:cerberus`.

### 6) NTP/Time sync
```bash
timedatectl status
chronyc tracking
chronyc sources -v
```
Expected: `System clock synchronized: yes`.

### 7) SSH hardening
```bash
sudo sshd -T | egrep 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|maxauthtries|x11forwarding|allowtcpforwarding|allowagentforwarding'
sudo grep -E '^(PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|MaxAuthTries|X11Forwarding|AllowTcpForwarding|AllowAgentForwarding)' /etc/ssh/sshd_config
```
Expected: root login disabled, password login disabled.

### 8) Log rotation
```bash
sudo cat /etc/logrotate.d/cerberus
sudo logrotate -d /etc/logrotate.d/cerberus
```

### 9) Audit daemon
```bash
sudo systemctl status auditd --no-pager
sudo auditctl -s
```

### 10) Systemd template unit
```bash
sudo cp systemd/cerberus@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl cat cerberus@.service
sudo systemd-analyze verify /etc/systemd/system/cerberus@.service
```

## Rollback Instructions

> Perform rollback in a maintenance window. Keep console access in case SSH policy changes lock you out.

### A) Firewall rollback
```bash
sudo ufw disable
sudo ufw --force reset
```

### B) Fail2ban rollback
```bash
sudo systemctl disable --now fail2ban
sudo rm -f /etc/fail2ban/jail.d/cerberus.local /etc/fail2ban/filter.d/cerberus-api.conf
sudo systemctl restart fail2ban || true
```

### C) Docker rollback
```bash
sudo systemctl disable --now docker
sudo apt-get remove --purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo rm -f /etc/apt/sources.list.d/docker.list
sudo rm -f /etc/apt/keyrings/docker.gpg
sudo apt-get autoremove -y
```

### D) Cerberus user and directories rollback
```bash
sudo systemctl stop cerberus@* || true
sudo userdel cerberus || true
sudo groupdel cerberus || true
sudo rm -rf /opt/cerberus /var/log/cerberus
```

### E) SSH rollback
```bash
sudo cp /etc/ssh/sshd_config.bak.<timestamp> /etc/ssh/sshd_config
sudo sshd -t
sudo systemctl restart ssh
```

### F) Sysctl rollback
```bash
sudo rm -f /etc/sysctl.d/99-cerberus-hardening.conf
sudo sysctl --system
```

### G) /dev/shm fstab rollback
```bash
sudo sed -i '\#tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0#d' /etc/fstab
sudo mount -o remount /dev/shm
```

### H) Logrotate rollback
```bash
sudo rm -f /etc/logrotate.d/cerberus
```

### I) auditd rollback
```bash
sudo systemctl disable --now auditd
sudo apt-get remove --purge -y auditd
```

### J) Remove template unit
```bash
sudo systemctl disable --now cerberus@<instance>.service || true
sudo rm -f /etc/systemd/system/cerberus@.service
sudo systemctl daemon-reload
```
