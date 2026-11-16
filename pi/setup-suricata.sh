#!/bin/bash
# TheFoxHole V3 - Suricata IPS configuration (run with sudo on the Pi)
set -euo pipefail
Y=/etc/suricata/suricata.yaml
SRC=/tmp/foxhole

[ -f "$Y.debian-orig" ] || cp "$Y" "$Y.debian-orig"

# 1. Custom rules + disabled rules
install -d -m 755 /etc/suricata/rules
install -m 644 "$SRC/local.rules" /etc/suricata/rules/local.rules
install -m 644 "$SRC/suricata-disable.conf" /etc/suricata/disable.conf

# 2. HOME_NET = the Pi-protected LAN only
sed -i -E 's|^(\s*)HOME_NET: "\[192\.168\.0\.0/16,10\.0\.0\.0/8,172\.16\.0\.0/12\]"|\1HOME_NET: "[10.0.0.0/24]"|' "$Y"

# 3. local.rules by absolute path
grep -q '^  - /etc/suricata/rules/local.rules' "$Y" || \
  sed -i 's|^  - suricata.rules$|  - suricata.rules\n  - /etc/suricata/rules/local.rules|' "$Y"

# 4. Turn off the two stats outputs (log volume; see old Phase 08)
sed -i -E '/^        - stats:$/,/^            deltas:/ s/^/#/' "$Y"
sed -i -E '/^  - stats:$/{n;s/enabled: yes/enabled: no/}' "$Y"

# 5. IPS mode: read from NFQUEUE 0 instead of passive af-packet
install -d /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
EOF

# 6. Log rotation: daily, 100 MB ceiling, keep 7
cat > /etc/logrotate.d/suricata <<'EOF'
/var/log/suricata/*.log
/var/log/suricata/*.json
{
	daily
	maxsize 100M
	rotate 7
	missingok
	notifempty
	compress
	delaycompress
	copytruncate
	sharedscripts
	postrotate
		/bin/kill -HUP $(cat /var/run/suricata.pid)
	endscript
}
EOF

# 7. Rebuild rules with disable.conf applied, validate, restart
suricata-update 2>&1 | tail -2
echo "--- config test ---"
suricata -T -c "$Y" 2>&1 | grep -vE "^i: |^Info" | tail -15
systemctl daemon-reload
systemctl restart suricata
sleep 25
echo "--- status ---"
systemctl is-active suricata
grep -E "^\s*HOME_NET:" "$Y"
grep -A3 '^rule-files' "$Y"
tr '\0' ' ' < /proc/$(pidof suricata)/cmdline; echo
grep -iE "rule files processed|rules successfully loaded|rules failed|engine started|NFQ" /var/log/suricata/suricata.log | tail -6
