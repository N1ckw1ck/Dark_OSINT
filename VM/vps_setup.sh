#!/bin/bash
# vps_setup.sh — Vultr Debian 12 hardening + dark web OSINT suite setup
# Run as root on a fresh Debian 12 instance.
# Usage: bash vps_setup.sh <your_home_ip> <sftp_username>
# Example: bash vps_setup.sh 203.0.113.42 user1

set -euo pipefail

# Args
HOME_IP="${1:-}"
SFTP_USER="${2:-osint}"

if [[ -z "$HOME_IP" ]]; then
    echo "[ERROR] Usage: bash vps_setup.sh <your_home_ip> <sftp_username>"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  VPS Setup — Debian 12 Hardening + OSINT Suite"
echo "  Home IP  : $HOME_IP"
echo "  SFTP user: $SFTP_USER"
echo "════════════════════════════════════════════════════════════"
echo ""

# System update
echo "[1/9] System update..."
apt update -qq && apt upgrade -y -qq
apt install -y -qq \
    ufw fail2ban tor gnupg curl wget \
    python3 python3-pip python3-venv \
    unattended-upgrades apt-listchanges \
    logwatch auditd libpam-pwquality \
    openssh-server rsyslog

# Create SFTP-only user
echo "[2/9] Creating SFTP user: $SFTP_USER..."
if ! id "$SFTP_USER" &>/dev/null; then
    useradd -m -s /usr/sbin/nologin "$SFTP_USER"
fi

# Create output directory owned by the SFTP user
mkdir -p "/home/$SFTP_USER/outbox"
chown "$SFTP_USER:$SFTP_USER" "/home/$SFTP_USER/outbox"
chmod 750 "/home/$SFTP_USER/outbox"

# SFTP user authorized_keys — you will add your public key here after script
mkdir -p "/home/$SFTP_USER/.ssh"
chmod 700 "/home/$SFTP_USER/.ssh"
touch "/home/$SFTP_USER/.ssh/authorized_keys"
chmod 600 "/home/$SFTP_USER/.ssh/authorized_keys"
chown -R "$SFTP_USER:$SFTP_USER" "/home/$SFTP_USER/.ssh"

# Create OSINT working user (no login shell, runs tools via cron)
echo "[3/9] Creating osint working user..."
if ! id "osintd" &>/dev/null; then
    useradd -m -s /bin/bash osintd
fi
mkdir -p /home/osintd/dark_osint
mkdir -p /home/osintd/dark_osint/output
chown -R osintd:osintd /home/osintd/dark_osint

# SSH hardening
echo "[4/9] Hardening SSH..."
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
PermitRootLogin no
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
echo "[5/9] Configuring firewall..."
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
echo "[6/9] Configuring fail2ban..."
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
echo "[7/9] Enabling unattended security upgrades..."
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

# Python deps (system-level for osintd user)
echo "[8/9] Installing Python dependencies..."
pip3 install --break-system-packages \
    "requests[socks]" stem beautifulsoup4 rich python-gnupg \
    fastapi uvicorn python-multipart

# auditd rules — watch the OSINT output directory for tampering
echo "[9/9] Configuring auditd..."
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

# Tor config
# Tor runs as a system service on 9050
# stem will detect this and use it rather than launching its own process
systemctl enable tor
systemctl start tor

# Restart SSH (safe — existing session stays open)
systemctl restart sshd

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Setup complete."
echo ""
echo "  NEXT STEPS:"
echo "  1. Add your SFTP public key:"
echo "     cat your_key.pub >> /home/$SFTP_USER/.ssh/authorized_keys"
echo ""
echo "  2. SCP your tool files to /home/osintd/dark_osint/"
echo "     From local: scp -i ~/.ssh/vultr_khaeos d_*.py pipeline.py"
echo "                     root@VPS_IP:/home/osintd/dark_osint/"
echo "     Then: chown -R osintd:osintd /home/osintd/dark_osint"
echo ""
echo "  3. Set up cron for osintd user (see README)"
echo ""
echo "  4. Test SFTP connection from local machine"
echo ""
echo "  5. Open a NEW terminal and test SSH before closing this one"
echo "════════════════════════════════════════════════════════════"
echo ""