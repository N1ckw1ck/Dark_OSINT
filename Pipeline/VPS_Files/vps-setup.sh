#!/bin/bash
# Run as root after fresh Debian 12 install
# HOME_IP is the public ip that you want to be able to connect to the VPS from
#
# Usage: bash vps-setup.sh <your_home_ip>
# Example: bash vps-setup.sh 203.0.113.42
#
# A different sftp username can be specified with 
#   bash vps-setup.sh <your_home_ip> <your_sftp_username>
# However this might cause issues/confusion down the line, simpler to accept the default "osint" username

set -euo pipefail

HOME_IP="${1:-}"
SFTP_USER="${2:-osint}"

if [[ -z "$HOME_IP" ]]; then
    echo "[ERROR] Usage: bash vps-setup.sh <your_home_ip> <sftp_username>"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  VPS Setup — Debian 12 Hardening + Dark OSINT Suite"
echo "  Home IP  : $HOME_IP"
echo "  SFTP user: $SFTP_USER"
echo "════════════════════════════════════════════════════════════"
echo ""

# System update
echo "[1/8] System update..."
apt update -qq && apt upgrade -y -qq
apt install -y -qq \
    ufw fail2ban tor gnupg curl wget \
    python3 python3-pip python3-venv \
    unattended-upgrades apt-listchanges \
    logwatch auditd libpam-pwquality \
    openssh-server rsyslog

# Create SFTP-only user
echo "[2/8] Creating SFTP user: $SFTP_USER..."
if ! id "$SFTP_USER" &>/dev/null; then
    useradd -m -s /usr/sbin/nologin "$SFTP_USER"
fi

# ChrootDirectory needs chroot root owned by root root root
chown root:root "/home/$SFTP_USER"
chmod 755 "/home/$SFTP_USER"

# Create output directory owned by the SFTP user, writable to by osintd
mkdir -p "/home/$SFTP_USER/outbox"
chown "$SFTP_USER:$SFTP_USER" "/home/$SFTP_USER/outbox"
chmod 770 "/home/$SFTP_USER/outbox"

# SFTP user authorized_keys — you will add your public key here after script
mkdir -p "/home/$SFTP_USER/.ssh"
chmod 700 "/home/$SFTP_USER/.ssh"
touch "/home/$SFTP_USER/.ssh/authorized_keys"
chmod 600 "/home/$SFTP_USER/.ssh/authorized_keys"
chown -R "$SFTP_USER:$SFTP_USER" "/home/$SFTP_USER/.ssh"

# Create OSINT working user (no login shell, runs tools via cron)
echo "[3/8] Creating osint working user, directories, venv..."
if ! id "osintd" &>/dev/null; then
    useradd -m -s /bin/bash osintd
fi

# let SFTP_USER write to osintd's outbox
usermod -aG "$SFTP_USER" osintd

mkdir -p /home/osintd/dark_osint
mkdir -p /home/osintd/dark_osint/config
mkdir -p /home/osintd/dark_osint/output/erebus
mkdir -p /home/osintd/dark_osint/output/hemera
mkdir -p /home/osintd/dark_osint/output/mnemosyne
chown -R osintd:osintd /home/osintd/dark_osint

# create venv, install requirements for osintd
sudo -u osintd python3 -m venv /home/osintd/venv
sudo -u osintd /home/osintd/venv/bin/pip install --quiet --upgrade pip
sudo -u osintd /home/osintd/venv/bin/pip install --quiet 'requests[socks]' stem beautifulsoup4 python-gnupg rich

# Log rotate for pipeline.log
cat > /etc/logrotate.d/dark_osint_pipeline << 'EOF'
/home/osintd/dark_osint/pipeline.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

# SSH hardening
echo "[4/8] Hardening SSH..."
cat > /etc/ssh/sshd_config << 'EOF'
# Hardened sshd_config
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Auth — keys only, no passwords
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin prohibit-password
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Limits
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 3

# No forwarding
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# Timeout idle sessions after 10 minutes
ClientAliveInterval 300
ClientAliveCountMax 2

# SFTP chroot config
# The SFTP user is jailed to their home directory
Subsystem sftp internal-sftp -l INFO

Match User SFTP_USER_PLACEHOLDER
    ChrootDirectory /home/SFTP_USER_PLACEHOLDER
    ForceCommand internal-sftp -l INFO
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication no
EOF

# Substitute the actual SFTP username
sed -i "s/SFTP_USER_PLACEHOLDER/$SFTP_USER/g" /etc/ssh/sshd_config

# Firewall
echo "[5/8] Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH only from your home IP
ufw allow from "$HOME_IP" to any port 22 proto tcp comment "SSH from home"

# Allow Tor outbound (it uses random ports, outgoing allow handles this)
# No inbound ports needed for this setup

ufw --force enable
ufw status verbose

# fail2ban
echo "[6/8] Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 86400
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# Automatic security updates
echo "[7/8] Enabling unattended security upgrades..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# auditd rules — watch the OSINT output directory for tampering
echo "[8/8] Configuring auditd..."
cat > /etc/audit/rules.d/osint.rules << 'EOF'
# Watch for writes/attribute changes in the SFTP outbox
-w /home/SFTP_PLACEHOLDER/outbox -p wa -k sftp_outbox
# Watch for changes to the SSH authorized_keys files
-w /root/.ssh/authorized_keys -p wa -k ssh_keys
-w /home/SFTP_PLACEHOLDER/.ssh/authorized_keys -p wa -k ssh_keys
# Watch for cron changes
-w /etc/crontab -p wa -k cron_watch
-w /var/spool/cron -p wa -k cron_watch
EOF

sed -i "s/SFTP_PLACEHOLDER/$SFTP_USER/g" /etc/audit/rules.d/osint.rules
service auditd restart

# Tor config, runs as a system service on 9050
# stem will detect this and use it rather than launching its own process
systemctl enable tor
systemctl start tor

# Restart SSH (existing session stays open)
systemctl restart sshd

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Setup complete."
echo ""
echo "  NEXT STEPS:"
echo "  1. Add your SFTP public key"
echo "      a) Copy from local machine:"
echo "           cat ~/.ssh/vps_dark_suite.pub"
echo "      b) Paste directly into VPS:"
echo "           nano /home/$SFTP_USER/.ssh/authorized_keys"
echo ""
echo "  2. SCP your tool files to /home/osintd/dark_osint/"
echo "      a) From local machine:"
echo "           scp -i ~/.ssh/vps_dark_suite d_*.py Pipeline/VPS_Files/* root@VPS_IP:/home/osintd/dark_osint/"
echo "      b) Then in VPS:"
echo "           chown -R osintd:osintd /home/osintd/dark_osint"
echo ""
echo "  3. In VPS, make pipeline.py executable and set permissions:"
echo "      chmod +x /home/osintd/dark_osint/run-pipeline.sh"
echo "      chown osintd:osintd /home/osintd/dark_osint/run-pipeline.sh"
echo ""
echo "  4. Set up cron for osintd user:"
echo "      a) crontab -u osintd -e"
echo "      b) Append:"
echo "           0 2 * * * /home/osintd/dark_osint/run-pipeline.sh >> /home/osintd/dark_osint/pipeline.log 2>&1"
echo ""
echo "  5. Create query files:"
echo "      nano /home/osintd/dark_osint/config/queries.txt"
echo "        OR"
echo "      nano /home/osintd/dark_osint/config/queries_monday.txt"
echo "      nano /home/osintd/dark_osint/config/queries_tuesday.txt"
echo "      nano /home/osintd/dark_osint/config/..."
echo ""
echo "  6. Test SFTP connection from local machine"
echo ""
echo "  7. Open a NEW terminal and test SSH before closing this one"
echo "     SEE README.md, setup guide for more information"
echo "════════════════════════════════════════════════════════════"
echo ""