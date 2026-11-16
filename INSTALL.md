# Install guide

These are the commands used for this build, on a Raspberry Pi 5 running Raspberry Pi OS based on Debian 13 "Trixie". Run them on the Pi. Words in CAPITALS (for example `YOUR_PI_USER`) are placeholders to replace with your own values.

Versions move on. Where a step downloads something from a vendor, check the vendor's current documentation before running it.

> **Before you start:** do the whole build with the Pi connected to your router as an ordinary device, and only move computers behind it at the end. Keep a keyboard and screen handy in case a firewall mistake locks you out of SSH.

## 1. Edit the example values

The addresses and names in `pi/` are examples. Change them first; see the "Where the addresses live" table in the [README](README.md).

Then copy the folder to the Pi from your management computer:

```bash
scp -r pi YOUR_PI_USER@PI_ADDRESS:/tmp/foxhole
```

`/tmp/foxhole` must not exist yet, or the files land one folder too deep. `/tmp` is emptied when the Pi reboots, so copy the folder again after the reboot in step 7.

## 2. Packages from the Debian repositories

```bash
sudo apt-get update
sudo apt-get install -y nftables suricata suricata-update fail2ban \
  prometheus prometheus-node-exporter samba ntfs-3g docker.io docker-compose \
  python3-requests jq unzip curl
```

`ntfs-3g` is only needed if the NAS disk is NTFS.

## 3. Network

`eth0` (onboard port) keeps its address from the router. `eth1` (USB adapter) gets a fixed address and never becomes the default route:

```bash
# Let eth1 keep its address even with no cable plugged in
printf "[device-eth1-lan]\nmatch-device=interface-name:eth1\nignore-carrier=true\n" \
  | sudo tee /etc/NetworkManager/conf.d/10-foxhole-eth1.conf
sudo systemctl reload NetworkManager

sudo nmcli connection add type ethernet ifname eth1 con-name lan \
  ipv4.method manual ipv4.addresses 10.0.0.1/24 ipv4.never-default yes \
  ipv6.method disabled connection.autoconnect yes
sudo nmcli connection up lan

# Let the Pi forward traffic between its two ports
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ipforward.conf
sudo sysctl -p /etc/sysctl.d/99-ipforward.conf
```

Optional, if you do not use the Pi's Wi-Fi: `sudo nmcli radio wifi off`.

## 4. Docker must not touch the firewall

`nftables.conf` owns the whole ruleset, so Docker is told to leave it alone:

```bash
printf '{\n  "iptables": false,\n  "ip6tables": false\n}\n' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
```

## 5. Pi-hole v6

A small settings file is created first so the installer can run without questions:

```bash
sudo install -d -m 755 /etc/pihole
printf '[dns]\n  upstreams = [ "8.8.8.8", "4.2.2.2" ]\n  interface = "eth1"\n' \
  | sudo tee /etc/pihole/pihole.toml

curl -sSL https://install.pi-hole.net -o /tmp/pihole-install.sh
# Read the script before running it.
sudo bash /tmp/pihole-install.sh --unattended
```

Then the settings for this layout:

```bash
sudo pihole-FTL --config dns.listeningMode SINGLE
sudo pihole-FTL --config dhcp.start 10.0.0.100
sudo pihole-FTL --config dhcp.end 10.0.0.200
sudo pihole-FTL --config dhcp.router 10.0.0.1
sudo pihole-FTL --config dhcp.netmask 255.255.255.0
sudo pihole-FTL --config dhcp.leaseTime 24h
# Fixed addresses: one "MAC,address,name" entry per device
sudo pihole-FTL --config dhcp.hosts '[ "AA:BB:CC:DD:EE:01,10.0.0.2,AdminPC", "AA:BB:CC:DD:EE:02,10.0.0.18,GameServer", "AA:BB:CC:DD:EE:03,10.0.0.20,DashboardPC" ]'
sudo pihole-FTL --config dhcp.active true
# Move the web page off port 80 to 8080
sudo pihole-FTL --config webserver.port "8080o,[::]:8080o"
# Set the web password (you will be asked to type it)
sudo pihole setpassword
```

## 6. Suricata (inline)

```bash
sudo bash /tmp/foxhole/setup-suricata.sh
```

This installs `local.rules` and `disable.conf`, sets `HOME_NET`, switches Suricata to read from NFQUEUE 0, sets up log rotation and restarts it. Expect "2 rule files processed" and "0 rules failed" at the end.

## 7. Hailo software and the model (AI HAT+ 2)

```bash
sudo apt-get install -y dkms hailo-h10-all
sudo reboot
```

`hailo-ollama` comes in Hailo's GenAI model zoo package. This build used version 5.1.1, downloaded from Hailo:

```bash
cd /tmp
curl -fSL -o hailo_gen_ai_model_zoo_5.1.1_arm64.deb \
  https://dev-public.hailo.ai/2025_12/Hailo10/hailo_gen_ai_model_zoo_5.1.1_arm64.deb
sudo dpkg -i hailo_gen_ai_model_zoo_5.1.1_arm64.deb
```

Create `/etc/systemd/system/hailo-ollama.service`:

```ini
[Unit]
Description=Hailo-Ollama inference server (LLM on the AI HAT+ 2 NPU)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=YOUR_PI_USER
ExecStart=/usr/bin/hailo-ollama
Restart=on-failure
RestartSec=10
WorkingDirectory=/home/YOUR_PI_USER

[Install]
WantedBy=multi-user.target
```

Start it and download the model:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hailo-ollama
curl http://localhost:8000/api/pull -H "Content-Type: application/json" \
  -d '{ "model": "qwen2.5-instruct:1.5b", "stream": true }'
curl -s http://localhost:8000/api/tags     # the model should be listed
```

Note: on this build the model files were carried over from an earlier install, so the pull command above was exercised with a different model, not with this exact one.

## 8. The LLM relay

```bash
sudo install -d -m 755 /usr/local/lib/foxhole
sudo install -m 755 /tmp/foxhole/llm_proxy.py /usr/local/lib/foxhole/llm_proxy.py
sudo install -m 644 /tmp/foxhole/configs/foxhole-llm-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now foxhole-llm-proxy
```

Test it (the first answer takes longer while the model loads):

```bash
curl -s http://127.0.0.1:8001/api/chat -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5-instruct:1.5b","messages":[{"role":"user","content":"Say hi."}],"stream":false}'
```

## 9. Monitoring

Create the credentials file for the Pi-hole exporter first. It needs a Pi-hole **app password**, which you create in Pi-hole's web settings:

```bash
sudo install -m 600 -o root -g root /tmp/foxhole/pihole-exporter.env.example /etc/pihole-exporter.env
sudo nano /etc/pihole-exporter.env
```

Then:

```bash
sudo bash /tmp/foxhole/setup-monitoring.sh
sudo systemctl enable --now pihole-exporter
```

Grafana is then on port 3000. Its first login is `admin` / `admin`, and it makes you choose a new password straight away.

## 10. NAS disk (optional)

Format and label the disk however you prefer, then mount it at `/mnt/nas`. For an NTFS disk, add one line to `/etc/fstab` (find the UUID with `sudo blkid`):

```
UUID=YOUR_DISK_UUID  /mnt/nas  ntfs-3g  defaults,nofail,uid=1000,gid=1000,umask=0022  0  0
```

```bash
sudo mkdir -p /mnt/nas
sudo systemctl daemon-reload
sudo mount -a
```

## 11. Triage service, dashboard switch and Samba share

Create the credentials file, then run the script (replace `YOUR_PI_USER` inside `setup-triage.sh` first):

```bash
sudo install -m 600 -o root -g root /tmp/foxhole/suricata-triage.env.example /etc/suricata-triage.env
sudo nano /etc/suricata-triage.env

sudo bash /tmp/foxhole/setup-triage.sh
sudo smbpasswd -a YOUR_PI_USER                 # password for the NAS share
```

Send a test email. The program needs the values from the credentials file, so it is started through systemd, which reads that file the same way the service does:

```bash
sudo systemd-run --pipe --wait -p EnvironmentFile=/etc/suricata-triage.env \
  /usr/bin/python3 /usr/local/lib/foxhole/foxhole_triage.py --test-email
```

## 12. Open WebUI

```bash
sudo install -d -m 755 /opt/open-webui
sudo install -m 644 /tmp/foxhole/docker-compose.yml /opt/open-webui/docker-compose.yml
cd /opt/open-webui
sudo docker compose pull
sudo docker compose up -d
```

It takes a few minutes to start the first time. Then open `http://10.0.0.1:8081` from the management computer; the first account you create is the administrator.

## 13. Firewall (last)

```bash
sudo install -m 644 /tmp/foxhole/nftables.conf /etc/nftables.conf
sudo nft -c -f /etc/nftables.conf      # syntax check only; prints nothing when it is fine
sudo nft -f /etc/nftables.conf         # load it
sudo systemctl enable nftables         # load it at every boot
```

After this, SSH works only from the management computer's address on the LAN side. If you are connected from somewhere else, you will be cut off at this point: that is expected.

## 14. Optional: limited passwordless sudo

Edit `YOUR_PI_USER` in `011_foxhole-scoped`, then:

```bash
sudo visudo -c -f /tmp/foxhole/011_foxhole-scoped
sudo install -m 440 /tmp/foxhole/011_foxhole-scoped /etc/sudoers.d/011_foxhole-scoped
```

## 15. Move the computers behind the Pi

Plug the switch into the Pi's USB Ethernet adapter and restart each computer's network connection so it picks up an address from Pi-hole.

Final check on the Pi:

```bash
systemctl is-active nftables suricata pihole-FTL hailo-ollama foxhole-llm-proxy \
  foxhole-triage grafana-server prometheus loki promtail pihole-exporter smbd docker
```

Every line should say `active`.
