#!/bin/bash
# TheFoxHole V3 - monitoring + logging stack (run with sudo on the Pi)
# Grafana (apt.grafana.com), Prometheus config, Loki + Promtail 3.6.1 binaries,
# pihole-exporter. Config files come from the old repo, staged in /tmp/foxhole/configs.
set -euo pipefail
C=/tmp/foxhole/configs
W=/tmp/foxhole/dl
mkdir -p "$W"; cd "$W"

echo "== Grafana repo + install =="
if [ ! -f /usr/share/keyrings/grafana.gpg ]; then
  wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor -o /usr/share/keyrings/grafana.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq grafana 2>&1 | tail -2

echo "== Prometheus config =="
[ -f /etc/prometheus/prometheus.yml.debian-orig ] || cp /etc/prometheus/prometheus.yml /etc/prometheus/prometheus.yml.debian-orig
install -m 644 "$C/prometheus-pi.yml" /etc/prometheus/prometheus.yml
promtool check config /etc/prometheus/prometheus.yml | tail -1
systemctl restart prometheus

echo "== Grafana provisioning =="
install -m 644 "$C/grafana-datasources.yaml" /etc/grafana/provisioning/datasources/foxhole.yaml
install -m 644 "$C/grafana-dashboard-provider.yaml" /etc/grafana/provisioning/dashboards/foxhole.yaml
mkdir -p /var/lib/grafana/dashboards
wget -q -O node-exporter-full.json https://grafana.com/api/dashboards/1860/revisions/latest/download
wget -q -O pihole.json https://grafana.com/api/dashboards/10176/revisions/latest/download
sed -i 's/${DS_PROMETHEUS}/prometheus/g' node-exporter-full.json pihole.json
python3 -c "import json,sys; [json.load(open(f)) for f in ('node-exporter-full.json','pihole.json')]; print('dashboards are valid JSON')"
install -m 644 node-exporter-full.json pihole.json /var/lib/grafana/dashboards/
install -m 644 "$C/foxhole-soc-dashboard.json" /var/lib/grafana/dashboards/foxhole-soc.json
chown -R grafana:grafana /var/lib/grafana/dashboards
grep -q '^default_timezone = UTC' /etc/grafana/grafana.ini || printf '\n[date_formats]\ndefault_timezone = UTC\n' >> /etc/grafana/grafana.ini

echo "== Loki + Promtail 3.6.1 (checksums verified) =="
B=https://github.com/grafana/loki/releases/download/v3.6.1
for f in loki-linux-arm64.zip promtail-linux-arm64.zip SHA256SUMS; do
  [ -f "$f" ] || curl -fsSL --retry 3 -o "$f" "$B/$f"
done
grep -E " (loki|promtail)-linux-arm64.zip$" SHA256SUMS | sha256sum -c -
unzip -oq loki-linux-arm64.zip; unzip -oq promtail-linux-arm64.zip
install -m 755 loki-linux-arm64 /usr/local/bin/loki
install -m 755 promtail-linux-arm64 /usr/local/bin/promtail
id loki >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin loki
mkdir -p /var/lib/loki /etc/loki /etc/promtail /var/lib/promtail
chown -R loki /var/lib/loki
install -m 644 "$C/loki-pi.yml" /etc/loki/config.yml
install -m 644 "$C/loki.service" /etc/systemd/system/loki.service
install -m 644 "$C/promtail-pi.yml" /etc/promtail/config.yml
cat > /etc/systemd/system/promtail.service <<'EOF'
[Unit]
Description=Promtail log shipper
After=network.target loki.service

[Service]
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/config.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
/usr/local/bin/loki -config.file=/etc/loki/config.yml -verify-config 2>&1 | tail -1

echo "== pihole-exporter v1.3.1 (checksum verified) =="
E=https://github.com/eko/pihole-exporter/releases/download/v1.3.1
for f in pihole_exporter-linux-arm64 pihole_exporter-linux-arm64.sha256.txt; do
  [ -f "$f" ] || curl -fsSL --retry 3 -o "$f" "$E/$f"
done
want=$(awk '{print $1}' pihole_exporter-linux-arm64.sha256.txt)
have=$(sha256sum pihole_exporter-linux-arm64 | awk '{print $1}')
[ "$want" = "$have" ] && echo "pihole_exporter checksum OK" || { echo "CHECKSUM MISMATCH"; exit 1; }
install -m 755 pihole_exporter-linux-arm64 /usr/local/bin/pihole_exporter
install -m 644 "$C/pihole-exporter.service" /etc/systemd/system/pihole-exporter.service

echo "== journald cap =="
mkdir -p /etc/systemd/journald.conf.d
# Storage=persistent: Raspberry Pi OS packages ship 40-rpi-volatile-storage.conf (journal in RAM
# only, lost at every reboot). This file sorts after it, so it wins.
printf '[Journal]\nStorage=persistent\nSystemMaxUse=300M\n' > /etc/systemd/journald.conf.d/foxhole.conf
systemctl restart systemd-journald

echo "== start services =="
systemctl daemon-reload
systemctl enable --now loki promtail grafana-server 2>&1 | grep -v "^Synchronizing\|^Executing" || true
systemctl restart grafana-server
sleep 25
for s in prometheus prometheus-node-exporter grafana-server loki promtail; do printf "%s: %s\n" "$s" "$(systemctl is-active $s)"; done
echo -n "loki ready: "; curl -s http://localhost:3100/ready
ss -tlnp | grep -E ":(3000|3100|9090|9100) " | awk '{print $4}'
