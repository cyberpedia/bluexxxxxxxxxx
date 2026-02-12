# PHASE 0: Hardened Ubuntu Server Setup (Ubuntu 22.04)

## Artifacts
- Bootstrap script: `scripts/phase0_hardened_setup.sh`
- Systemd template: `systemd/cerberus@.service`

## Apply
```bash
sudo bash scripts/phase0_hardened_setup.sh
sudo cp systemd/cerberus@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Validation Commands
Run each command and verify expected secure state.

### OS hardening and updates
```bash
sudo unattended-upgrade --dry-run --debug
sudo sysctl -a | rg 'kptr_restrict|dmesg_restrict|tcp_syncookies|rp_filter'
```

### Firewall (UFW)
```bash
sudo ufw status verbose
sudo ss -tulpen | rg ':22|:80|:443'
```

### Fail2ban
```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client status cerberus-api
```

### Docker + Compose
```bash
docker --version
docker compose version
sudo systemctl status docker --no-pager
```

### Least-privilege Cerberus user
```bash
id cerberus
getent passwd cerberus
namei -l /opt/cerberus
```

### Time synchronization
```bash
timedatectl status
systemctl status systemd-timesyncd --no-pager
```

### SSH hardening
```bash
sudo sshd -T | rg 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|maxauthtries|x11forwarding'
sudo systemctl status ssh --no-pager
```

### Log rotation
```bash
sudo logrotate -d /etc/logrotate.d/cerberus
sudo cat /etc/docker/daemon.json
```

### Systemd Cerberus template
```bash
sudo systemd-analyze verify /etc/systemd/system/cerberus@.service
sudo systemctl enable --now cerberus@api
sudo systemctl status cerberus@api --no-pager
```

## Rollback Instructions
> Roll back in controlled maintenance windows.

1. **Disable Cerberus instances and remove unit template**
   ```bash
   sudo systemctl disable --now cerberus@api
   sudo rm -f /etc/systemd/system/cerberus@.service
   sudo systemctl daemon-reload
   ```
2. **Restore SSH access policy if needed**
   ```bash
   sudo rm -f /etc/ssh/sshd_config.d/99-cerberus-hardening.conf
   sudo systemctl restart ssh
   ```
3. **Disable firewall policy (emergency only)**
   ```bash
   sudo ufw disable
   ```
4. **Disable Fail2ban**
   ```bash
   sudo systemctl disable --now fail2ban
   sudo rm -f /etc/fail2ban/jail.d/cerberus.local /etc/fail2ban/filter.d/cerberus-api.conf
   ```
5. **Remove Docker stack (optional full rollback)**
   ```bash
   sudo systemctl disable --now docker
   sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   sudo rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.gpg
   sudo apt-get autoremove -y
   ```
6. **Remove Cerberus user/data (destructive)**
   ```bash
   sudo userdel cerberus
   sudo rm -rf /opt/cerberus /var/log/cerberus
   ```
7. **Revert sysctl/logrotate customizations**
   ```bash
   sudo rm -f /etc/sysctl.d/99-cerberus-hardening.conf /etc/logrotate.d/cerberus
   sudo sysctl --system
   ```

## Security Best Practices Notes
- Keep an emergency break-glass account with SSH key auth and MFA where possible.
- Restrict inbound traffic further by source CIDRs for SSH in cloud security groups/NACLs.
- Prefer rootless containers when possible and pin image digests in Compose files.
- Forward logs to a centralized SIEM and monitor fail2ban events/ban trends.
- Patch monthly at minimum; immediately for critical CVEs.

PHASE 0 COMPLETE
