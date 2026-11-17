# The-FoxHole

A Raspberry Pi 5 configured to sit inline between a wired network and the home router. All wired internet traffic is inspected by Suricata. A small Qwen LLM on the AI HAT+ 2 summarises threats, a triage service checks addresses against AbuseIPDB and sends email alerts, and you can chat with the model through Open WebUI. Also included: Pi-hole ad blocking, Grafana / Prometheus / Loki dashboards, a Samba NAS, and two port-forward rules for an internal-only Minecraft server (the server itself is not included).

> **This is a homelab project, shared as a reference.** The addresses, device names and user names in these files are examples. Read each file and change them to fit your own network before using anything.

## How it is wired

```
Internet -- Router (192.168.0.0/24, also the house Wi-Fi)
               |
             eth0  (onboard port, "WAN", address from the router)
        Raspberry Pi 5  "TheFoxHole"
             eth1  (USB Ethernet adapter, "LAN", 10.0.0.1/24)
               |
            Switch -- wired computers (10.0.0.0/24)
```

Example devices used throughout the files:

| Name | Address | Role |
|---|---|---|
| AdminPC | 10.0.0.2 | Management laptop. The only device allowed to SSH to the Pi or open its admin pages. |
| GameServer | 10.0.0.18 | Minecraft server, home network only. |
| DashboardPC | 10.0.0.20 | Shows Grafana. No internet unless switched on for updates. |

## Hardware and software

- Raspberry Pi 5 (8 GB), Raspberry Pi AI HAT+ 2 (Hailo-10H), USB Ethernet adapter, USB SSD for the NAS
- Debian 13 "Trixie" (Raspberry Pi OS)
- nftables, Suricata 7 (inline IPS through NFQUEUE, ET Open rules), Pi-hole v6
- hailo-ollama with `qwen2.5-instruct:1.5b`, Open WebUI in Docker
- Grafana, Prometheus, node exporter, Loki, Promtail, pihole-exporter
- Samba

## What each part does

| Function | How |
|---|---|
| Firewall and NAT | nftables, default drop. Everything forwarded is queued to Suricata. |
| Intrusion prevention | Suricata inline. If Suricata stops, forwarding stops (fail-closed). |
| DNS, DHCP, ad blocking | Pi-hole on the LAN side. Admin page on port 8080. |
| Threat triage | `foxhole_triage.py` follows Suricata's `eve.json`, checks internet addresses against AbuseIPDB and emails you. See "Staying inside AbuseIPDB's free plan" below. |
| Rule updates | `foxhole-rules-update.timer` refreshes the Suricata rules every night, including ET Open's known-bad address lists. |
| Local AI | Qwen 2.5 1.5B on the Hailo NPU writes the short summary in each alert email. |
| AI relay | `llm_proxy.py` sits in front of hailo-ollama: it removes request fields hailo-ollama rejects, makes requests take turns on the NPU, and pins replies to English. |
| Chat | Open WebUI on port 8081. |
| Dashboards | Grafana on port 3000, Prometheus on 9090, logs in Loki. |
| NAS | Samba share on the LAN side only. |
| Backups | `foxhole-backup` writes a weekly settings + data archive to the NAS and keeps the newest 8. |

### Email alerts

- `[URGENT] [THREAT n%]`: a device exchanged traffic with an address AbuseIPDB rates 80% or higher. Includes an AI summary and fixed remediation steps.
- `[SURICATA SevN]`: a Suricata alert of severity 1 or 2.
- `[AUTOBLOCK]`: repeated SSH attempts; the source is blocked for 30 minutes.

The remediation steps are fixed text, not AI-written, because a 1.5B model is not reliable enough to invent them.

### Staying inside AbuseIPDB's free plan

The free plan allows 1,000 address lookups a day. A home network easily talks to that many different addresses, almost all of them Microsoft, Google, Akamai and Amazon. The triage service stretches the budget like this:

- **Answers are remembered by score:** 0% for 7 days, 1-24% for 3 days, 25% and up for 1 day, so risky addresses are re-checked often.
- **The remaining count comes from AbuseIPDB's own answer headers**, because AbuseIPDB's day does not start at local midnight. When it says the limit is reached, lookups pause until its reset time (no retry storm). A failed lookup is not retried for 15 minutes.
- **A reserve of 150 lookups** is kept for Suricata alerts; ordinary traffic checks stop first.
- **AbuseIPDB's daily list of the 10,000 worst addresses** (the free plan allows 5 downloads a day) is downloaded once a day and every connection is checked against it locally, at no cost. A listed address is emailed as `[URGENT] [THREAT 100%]` even while lookups are paused.
- **A usage line** ("Past hour: ... lookups ...") is written to the log every hour, so you can see what the budget is spent on.

## Files

Everything is in [`pi/`](pi/). The setup scripts expect this folder copied to `/tmp/foxhole` on the Pi.

| File | Goes to (on the Pi) | Purpose |
|---|---|---|
| `nftables.conf` | `/etc/nftables.conf` | Firewall, NAT, Minecraft forwards |
| `local.rules` | `/etc/suricata/rules/local.rules` | Custom Suricata rules (SSH brute force, Minecraft) |
| `suricata-disable.conf` | `/etc/suricata/disable.conf` | Rules switched off (Syncro RMM, Splashtop) |
| `foxhole_triage.py` | `/usr/local/lib/foxhole/` | Triage service |
| `suricata-triage.env.example` | `/etc/suricata-triage.env` | Template for mail and AbuseIPDB credentials |
| `pihole-exporter.env.example` | `/etc/pihole-exporter.env` | Template for the Pi-hole exporter's password |
| `ignore-*.txt` | `/etc/foxhole/` | Signatures, domains and addresses never emailed about |
| `llm_proxy.py` | `/usr/local/lib/foxhole/` | Relay in front of hailo-ollama |
| `docker-compose.yml` | `/opt/open-webui/` | Open WebUI |
| `dashboard-internet` | `/usr/local/sbin/` | `on` / `off` / `status` switch for DashboardPC's internet |
| `011_foxhole-scoped` | `/etc/sudoers.d/` | Limited passwordless sudo |
| `foxhole-rules-update.service` / `.timer` | `/etc/systemd/system/` | Nightly Suricata rule update (installed by `setup-suricata.sh`) |
| `foxhole-backup` | `/usr/local/sbin/` | Settings + data backup to the NAS |
| `foxhole-backup.service` / `.timer` | `/etc/systemd/system/` | Runs the backup weekly (Sunday ~05:30) |
| `setup-suricata.sh` | run once | Configures Suricata for inline mode |
| `setup-monitoring.sh` | run once | Installs Grafana, Loki, Promtail, pihole-exporter |
| `setup-triage.sh` | run once | Installs the triage service, dashboard switch and Samba share |
| `configs/` | see each file's header | Prometheus, Loki, Promtail, Grafana and systemd unit files |

## Installing

**[INSTALL.md](INSTALL.md) has the full step-by-step commands.** In outline:

1. Edit the example addresses and names in `pi/` to match your network.
2. Install the Debian packages and set up the two network ports.
3. Install Pi-hole, then Suricata (`setup-suricata.sh`).
4. Install Hailo's software, hailo-ollama, the model and the relay.
5. Install monitoring (`setup-monitoring.sh`), the triage service (`setup-triage.sh`) and Open WebUI.
6. Load the firewall last, then move the wired computers behind the Pi.

### Where the addresses live

There is no single settings file yet. If you change an address or a device, change it in every place listed:

| Value | Files that contain it |
|---|---|
| LAN network (10.0.0.0/24) | `foxhole_triage.py` (`HOME_NET`), `setup-suricata.sh` (`HOME_NET`), Pi-hole DHCP settings |
| Router / Wi-Fi network (192.168.0.0/24) | `nftables.conf` (`WIFI_NET`), `local.rules` |
| AdminPC (10.0.0.2) | `nftables.conf` (`LAPTOP`), `foxhole_triage.py` (`DEVICES`, `AUTOBLOCK_EXEMPT_IPS`), Pi-hole DHCP settings |
| GameServer (10.0.0.18) | `nftables.conf` (`GAMESRV`), `local.rules`, `foxhole_triage.py` (`DEVICES`), Pi-hole DHCP settings |
| DashboardPC (10.0.0.20) | `nftables.conf` (`DASH`), `dashboard-internet`, `foxhole_triage.py` (`DEVICES`), Pi-hole DHCP settings |
| Pi login name | `011_foxhole-scoped`, `setup-triage.sh`, `foxhole-backup`, the `hailo-ollama` service file |

Moving these into one file is a welcome contribution; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Everyday commands

| Task | Command |
|---|---|
| Give DashboardPC internet for updates | `sudo dashboard-internet on` |
| Take it away again | `sudo dashboard-internet off` |
| Watch the triage service | `soc` |
| Send a test email | See step 11 of [INSTALL.md](INSTALL.md) |
| Reload Suricata rules | `sudo systemctl reload suricata` |
| Update Suricata rules now (also runs nightly) | `sudo systemctl start foxhole-rules-update` |
| Back up to the NAS now (also runs weekly) | `sudo systemctl start foxhole-backup` |
| Unblock an address | `sudo nft delete element inet filter BLOCKED_IPS { ADDRESS }` |

## Known limits

- **Addresses are repeated across several files.** See "Where the addresses live" above.
- **Fail-closed.** If Suricata is down, the wired computers have no internet.
- **Same-switch traffic is not inspected.** Traffic between two wired computers never passes the Pi.
- **AbuseIPDB false positives.** Scores belong to addresses, and cloud addresses are shared. Use the ignore lists.
- **hailo-ollama quirks.** Version 5.1.1 answered HTTP 500 to several standard Ollama request fields, which is why the relay exists.
- **Small model.** `llama3.2:3b` was tried and was too slow on this hardware (minutes to load and answer).
- **The Wi-Fi Minecraft forward is untested.** The rules load and validate, but no Wi-Fi client was available to try it.
- **AbuseIPDB's free plan** has its own usage terms; check them before using this anywhere but home.

## Contributing

Questions, bug reports and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT, see [LICENSE](LICENSE). The software this project configures (Suricata, Pi-hole, Grafana, Open WebUI, Hailo's tools and others) keeps its own licences.
