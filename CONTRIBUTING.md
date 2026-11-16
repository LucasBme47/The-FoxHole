# Contributing

Thanks for taking an interest. This is a homelab project, so keep things simple.

## Questions and ideas

Open a thread in **Discussions**.

## Reporting a problem

Open an **Issue** and include:

- What you were trying to do, and what happened instead.
- The hardware and OS version (for example: Pi 5 8 GB, AI HAT+ 2, Debian 13).
- The exact error text or the relevant log lines.

**Remove private details before posting logs:** public IP addresses, email addresses, MAC addresses, host names, passwords and API keys.

## Proposing a change

1. Fork the repository and create a branch.
2. Make the change, and keep it to one topic per pull request.
3. Check it before sending:
   - Firewall: `sudo nft -c -f pi/nftables.conf`
   - Suricata rules: `sudo suricata -T -c /etc/suricata/suricata.yaml -S pi/local.rules -l /tmp`
   - Python: `python3 -m py_compile pi/foxhole_triage.py pi/llm_proxy.py`
   - Shell scripts: `bash -n pi/setup-*.sh pi/dashboard-internet`
4. In the pull request, say what you tested and on what hardware. "Not tested on a Pi" is a fine thing to say; it just needs saying.

## Ground rules

- **No secrets.** Never commit a filled-in `.env` file, a key or a password. Only the `.env.example` templates belong here.
- **Example values only.** Keep the placeholder names (AdminPC, GameServer, DashboardPC, `YOUR_PI_USER`) and private example addresses.
- **Unix line endings.** `.gitattributes` handles this; do not override it.
- Contributions are accepted under the project's MIT licence.

## Good first contributions

- Move the addresses that are repeated across four files into one settings file (see "Where the addresses live" in the README).
- Test the Wi-Fi Minecraft forward and report the result.
- Add install notes for other hardware or OS versions.
