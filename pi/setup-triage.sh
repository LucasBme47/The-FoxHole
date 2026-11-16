#!/bin/bash
# TheFoxHole V3 - triage daemon, ignore lists, dashboard toggle, Samba share (run with sudo)
# Before running: copy this folder to /tmp/foxhole on the Pi, create /etc/suricata-triage.env
# (see suricata-triage.env.example), and replace YOUR_PI_USER below with your Pi login name.
set -euo pipefail
S=/tmp/foxhole

echo "== triage daemon =="
install -d -m 755 /usr/local/lib/foxhole /etc/foxhole /var/lib/foxhole
install -m 755 "$S/foxhole_triage.py" /usr/local/lib/foxhole/foxhole_triage.py
python3 -m py_compile /usr/local/lib/foxhole/foxhole_triage.py && echo "python syntax OK"
for f in ignore-signatures.txt ignore-domains.txt ignore-ips.txt; do
  [ -f "/etc/foxhole/$f" ] || install -m 644 "$S/$f" "/etc/foxhole/$f"
done
cat > /etc/systemd/system/foxhole-triage.service <<'EOF'
[Unit]
Description=FoxHole AI triage daemon (Suricata alerts + AbuseIPDB traffic checks)
After=network-online.target suricata.service hailo-ollama.service
Wants=network-online.target

[Service]
User=root
EnvironmentFile=/etc/suricata-triage.env
Environment=FOXHOLE_MODEL=qwen2.5-instruct:1.5b
ExecStart=/usr/bin/python3 -u /usr/local/lib/foxhole/foxhole_triage.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
grep -q "alias soc=" /etc/bash.bashrc || echo "alias soc='journalctl -u foxhole-triage -f --output=cat'" >> /etc/bash.bashrc

echo "== dashboard-internet command =="
install -m 755 "$S/dashboard-internet" /usr/local/sbin/dashboard-internet
/usr/local/sbin/dashboard-internet status

echo "== Samba NAS share =="
[ -f /etc/samba/smb.conf.debian-orig ] || cp /etc/samba/smb.conf /etc/samba/smb.conf.debian-orig
if ! grep -q "^\[NAS\]" /etc/samba/smb.conf; then
  # serve SMB on the LAN side only
  sed -i 's|^\[global\]$|[global]\n   interfaces = lo eth1\n   bind interfaces only = yes|' /etc/samba/smb.conf
  cat >> /etc/samba/smb.conf <<'EOF'

[NAS]
     path = /mnt/nas
     browseable = yes
     read only = no
     valid users = YOUR_PI_USER
     create mask = 0664
     directory mask = 0775
EOF
fi
testparm -s 2>&1 | grep -E "Loaded services|interfaces|bind interfaces|^\[NAS\]|path = /mnt/nas|valid users" || true
systemctl enable smbd nmbd 2>&1 | tail -1 || true
systemctl restart smbd nmbd

systemctl daemon-reload
systemctl enable foxhole-triage 2>&1 | tail -1
systemctl restart foxhole-triage
sleep 4
systemctl is-active foxhole-triage smbd
journalctl -u foxhole-triage -n 6 --no-pager -o cat
