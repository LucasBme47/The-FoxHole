#!/usr/bin/env python3
"""
TheFoxHole V3 triage daemon  ->  /usr/local/lib/foxhole/foxhole_triage.py

Reads Suricata's eve.json as it is written and:
  1. ALERTS  - every Suricata alert is looked up in AbuseIPDB, summarised by the
               on-device LLM (Hailo NPU via hailo-ollama) and written to triage.log.
               Severity 1-2 alerts are emailed.
  2. TRAFFIC - every finished connection (flow) to/from an internet address is looked
               up in AbuseIPDB (cached, daily budget). No Suricata alert is needed.
  3. URGENT  - if AbuseIPDB confidence is >= 80 %, an email tagged [URGENT] is sent
               with an LLM summary and suggested remediation steps.
  4. SSH brute force -> automatic 30-minute block (nftables BLOCKED_IPS), as before.

Tuning without touching this file - one entry per line, '#' starts a comment:
  /etc/foxhole/ignore-signatures.txt   text that, if found in a rule name, silences it
  /etc/foxhole/ignore-domains.txt      domains (and sub-domains) never emailed about
  /etc/foxhole/ignore-ips.txt          IP addresses or CIDR ranges never emailed about
After editing:  sudo systemctl restart foxhole-triage

Secrets come from /etc/suricata-triage.env (SMTP_USER, SMTP_PASS, ALERT_EMAIL, ABUSEIPDB_KEY).
"""
import ipaddress
import json
import os
import smtplib
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from email.mime.text import MIMEText

import requests

# --------------------------------------------------------------------------- settings
EVE_LOG = "/var/log/suricata/eve.json"
TRIAGE_LOG = "/var/log/suricata/triage.log"
STATE_DIR = "/var/lib/foxhole"
CACHE_FILE = os.path.join(STATE_DIR, "abuseipdb-cache.json")
CONF_DIR = "/etc/foxhole"

OLLAMA_URL = "http://127.0.0.1:8001/api/chat"   # via the FoxHole LLM relay (takes turns on the NPU)
MODEL = os.environ.get("FOXHOLE_MODEL", "qwen2.5-instruct:1.5b")
QUERY_TIMEOUT = 300

SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]
ALERT_EMAIL = os.environ["ALERT_EMAIL"]
ABUSEIPDB_KEY = os.environ["ABUSEIPDB_KEY"]

ABUSEIPDB_THRESHOLD = 80        # % confidence at which an URGENT email is sent
ABUSE_CACHE_HOURS = 24          # do not ask AbuseIPDB about the same address again for this long
ABUSE_DAILY_BUDGET = 900        # free plan allows 1000 lookups/day
ABUSE_ALERT_RESERVE = 150       # lookups held back for Suricata alerts (traffic checks stop first)
EMAIL_COOLDOWN = 6 * 3600       # at most one email per bad address per 6 hours
DEDUP_WINDOW = 60               # same Suricata rule within 60 s = one triage

# EXAMPLE VALUES - change the network and device list to match your own.
HOME_NET = ipaddress.ip_network("10.0.0.0/24")
DEVICES = {
    "10.0.0.1": "TheFoxHole (the Pi)",
    "10.0.0.2": "AdminPC (management laptop)",
    "10.0.0.18": "GameServer (Minecraft server)",
    "10.0.0.20": "DashboardPC (Dashboard Viewer)",
}

# SSH brute-force correlation -> auto-block via the nftables BLOCKED_IPS set
SSH_BRUTEFORCE_THRESHOLD = 10
SSH_BRUTEFORCE_WINDOW = 60
AUTOBLOCK_DURATION = 1800
AUTOBLOCK_EXEMPT_IPS = {"10.0.0.1", "10.0.0.2", "127.0.0.1"}

RED, RESET = "\033[91m", "\033[0m"

# --------------------------------------------------------------------------- state
_ssh_alert_times = defaultdict(deque)
_last_blocked = defaultdict(float)
_last_emailed = defaultdict(float)
_last_seen_sig = defaultdict(float)
_ip_hostname = {}                       # internet IP -> last TLS SNI / HTTP host seen
_abuse_cache = {}                       # ip -> {"t": epoch, "r": report}
_budget = {"day": "", "used": 0, "warned": False}
_cache_dirty = 0


def log(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------- ignore lists
def _read_list(name):
    path = os.path.join(CONF_DIR, name)
    items = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    items.append(line)
    except FileNotFoundError:
        pass
    return items


def load_ignore_lists():
    sigs = [s.lower() for s in _read_list("ignore-signatures.txt")]
    domains = [d.lower().lstrip("*.").strip(".") for d in _read_list("ignore-domains.txt")]
    nets = []
    for entry in _read_list("ignore-ips.txt"):
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log(f"[!] ignore-ips.txt: '{entry}' is not a valid address or range - skipped")
    return sigs, domains, nets


def sig_ignored(sig):
    s = sig.lower()
    return any(x in s for x in IGNORE_SIGS)


def domain_ignored(host):
    if not host:
        return False
    h = host.lower().strip(".")
    return any(h == d or h.endswith("." + d) for d in IGNORE_DOMAINS)


def ip_ignored(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in IGNORE_NETS)


# --------------------------------------------------------------------------- helpers
def is_internet_ip(ip):
    """True only for addresses that are routable on the public internet."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def device_name(ip):
    if ip in DEVICES:
        return f"{DEVICES[ip]} [{ip}]"
    try:
        if ipaddress.ip_address(ip) in HOME_NET:
            return f"unknown home device [{ip}]"
    except ValueError:
        pass
    return ip


def pick_sides(event):
    """Return (internet_ip, home_ip, direction_text) for an eve event."""
    src, dst = event.get("src_ip", ""), event.get("dest_ip", "")
    if is_internet_ip(dst):
        return dst, src, "home device connected OUT to the internet address"
    if is_internet_ip(src):
        return src, dst, "internet address connected IN toward the home device"
    return None, None, ""


# --------------------------------------------------------------------------- AbuseIPDB
def load_cache():
    global _abuse_cache
    try:
        with open(CACHE_FILE) as f:
            data = json.load(f)
        _abuse_cache = data.get("cache", {})
        _budget.update(data.get("budget", {}))
    except (FileNotFoundError, ValueError):
        pass


def save_cache(force=False):
    global _cache_dirty
    if not force and _cache_dirty < 20:
        return
    cutoff = time.time() - ABUSE_CACHE_HOURS * 3600
    for ip in [k for k, v in _abuse_cache.items() if v["t"] < cutoff]:
        del _abuse_cache[ip]
    tmp = CACHE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"cache": _abuse_cache, "budget": _budget}, f)
    os.replace(tmp, CACHE_FILE)
    _cache_dirty = 0


def check_abuseipdb(ip, for_alert):
    """Return an AbuseIPDB report dict, or None if no lookup was possible."""
    global _cache_dirty
    now = time.time()
    hit = _abuse_cache.get(ip)
    if hit and now - hit["t"] < ABUSE_CACHE_HOURS * 3600:
        return hit["r"]

    today = datetime.now().strftime("%Y-%m-%d")
    if _budget["day"] != today:
        _budget.update(day=today, used=0, warned=False)
    limit = ABUSE_DAILY_BUDGET if for_alert else ABUSE_DAILY_BUDGET - ABUSE_ALERT_RESERVE
    if _budget["used"] >= limit:
        if not _budget["warned"] and not for_alert:
            _budget["warned"] = True
            log(f"[!] AbuseIPDB daily budget for traffic checks used up ({_budget['used']} lookups). "
                f"Traffic checks pause until midnight; Suricata alerts are still checked.")
        return None

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        _budget["used"] += 1
        resp.raise_for_status()
        d = resp.json().get("data", {})
    except Exception as e:
        log(f"    -> [ABUSEIPDB ERROR for {ip}: {e}]")
        return None

    report = {
        "confidence": 0 if d.get("isWhitelisted") else d.get("abuseConfidenceScore", 0),
        "reports": d.get("totalReports", 0),
        "country": d.get("countryCode") or "?",
        "isp": d.get("isp") or "?",
        "usage": d.get("usageType") or "?",
        "domain": d.get("domain") or "?",
    }
    _abuse_cache[ip] = {"t": now, "r": report}
    _cache_dirty += 1
    save_cache()
    return report


# --------------------------------------------------------------------------- LLM
def query_llm(prompt):
    """Ask the on-device model for a short plain-text summary. Returns None on failure."""
    payload = {"model": MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False}
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=QUERY_TIMEOUT)
        resp.raise_for_status()
        text = resp.json()["message"]["content"]
    except Exception as e:
        log(f"    -> [LLM ERROR: {e}]")
        return None
    # A 1.5B model sometimes adds markdown or rambles: tidy and cap it.
    text = " ".join(text.replace("*", "").replace("#", "").split())
    if len(text) > 700:
        cut = text[:700]
        text = cut[:cut.rfind(".") + 1] if "." in cut else cut
    return text or None


def describe(event, ext_ip, home_ip, direction, abuse, hostname):
    """Plain-text facts about one event; used both for the LLM prompt and the email."""
    a = event.get("alert", {})
    flow = event.get("flow", {})
    lines = [
        f"Time: {event.get('timestamp', '?')}",
        f"Home device: {device_name(home_ip)}",
        f"Internet address: {ext_ip}" + (f" (hostname seen: {hostname})" if hostname else ""),
        f"Direction: {direction}",
        f"Traffic: {event.get('proto', '?')} {event.get('src_ip', '?')}:{event.get('src_port', '?')}"
        f" -> {event.get('dest_ip', '?')}:{event.get('dest_port', '?')}"
        + (f", application protocol {event['app_proto']}" if event.get("app_proto") else ""),
    ]
    if flow:
        lines.append(f"Volume: {flow.get('bytes_toserver', 0)} bytes sent, "
                     f"{flow.get('bytes_toclient', 0)} bytes received, "
                     f"connection state {flow.get('state', '?')}")
    if a:
        lines.append(f"Suricata rule: {a.get('signature', '?')}")
        lines.append(f"Suricata category: {a.get('category', '?')}; "
                     f"severity {a.get('severity', '?')} (1=critical, 3=low); "
                     f"action taken: {a.get('action', '?')}")
    if abuse:
        lines.append(f"AbuseIPDB: {abuse['confidence']}% confidence malicious, "
                     f"{abuse['reports']} reports in 90 days, ISP: {abuse['isp']}, "
                     f"country: {abuse['country']}, usage type: {abuse['usage']}")
    return "\n".join(lines)


def build_prompt(facts):
    return (
        "You are a SOC analyst triage assistant for a home network. Summarize this event "
        "in 2-3 sentences for the network owner: what happened, which home device was involved, "
        "and the likely threat. Use only the facts given. "
        "Plain text only - no markdown, no bullet points, no bold or asterisks.\n\n"
        + facts + "\n"
    )


def fallback_text(ext_ip, home_ip, abuse):
    """Used when the LLM is unavailable - the email must still be useful."""
    conf = abuse["confidence"] if abuse else 0
    return (
        f"{device_name(home_ip)} exchanged traffic with {ext_ip}"
        + (f", which AbuseIPDB rates {conf}% likely malicious." if abuse else ".")
        + " (The on-device AI summary was unavailable, so this is a standard message.)"
    )


def remediation_steps(ext_ip, home_ip, direction, abuse, urgent):
    """Fixed, accurate next steps. The small on-device model is not trusted to invent these."""
    dev = DEVICES.get(home_ip, f"the device at {home_ip}")
    if not urgent:
        return ("1. No immediate action needed unless this keeps repeating or you do not recognise the activity.\n"
                "2. If it is normal for your network, add the rule name to /etc/foxhole/ignore-signatures.txt.")
    steps = []
    if direction.startswith("home device"):
        steps.append(f"1. Go to {dev} and find out what was talking to {ext_ip} "
                     f"(a game server, a browser tab, a download?). Close it if nobody expected it.")
        steps.append(f"2. Run a full malware scan on {dev} and check for recently installed programs or browser extensions.")
    else:
        steps.append(f"1. {ext_ip} tried to reach {dev}. Nothing from the internet should be able to start a "
                     f"connection into the home network: check the router has no port forwarding rules.")
        steps.append(f"2. Check {dev} for services listening that should not be (remote desktop, game servers, file sharing).")
    steps.append(f"3. Block the address on the Pi for 30 minutes while you look into it:\n"
                 f"   sudo nft add element inet filter BLOCKED_IPS {{ {ext_ip} timeout 30m }}")
    steps.append("4. If the device also shows other alerts, unplug its network cable until it has been checked.")
    return "\n".join(steps)


# --------------------------------------------------------------------------- outputs
def write_triage(header, traffic, summary):
    with open(TRIAGE_LOG, "a") as f:
        f.write(f"\n[{datetime.now().isoformat()}]\n")
        f.write(f"  RULE:    {header}\n")
        f.write(f"  TRAFFIC: {traffic}\n")
        f.write(f"  SUMMARY: {summary}\n")


def send_email(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_EMAIL
    if subject.startswith("[URGENT]"):
        msg["X-Priority"] = "1"
        msg["Importance"] = "High"
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
        log(f"    -> Email sent: {subject}")
        return True
    except Exception as e:
        log(f"    -> [EMAIL ERROR: {e}]")
        return False


def email_body(facts, summary, steps, ext_ip):
    return (
        f"--- AI SUMMARY ({MODEL}, running on the Pi; may be imprecise) ---\n"
        f"{summary}\n"
        f"\n--- EVENT FACTS ---\n"
        f"{facts}\n"
        f"\n--- SUGGESTED REMEDIATION ---\n"
        f"{steps}\n"
        f"\n--- REFERENCE ---\n"
        f"Remove a block:   sudo nft delete element inet filter BLOCKED_IPS {{ {ext_ip} }}\n"
        f"AbuseIPDB page:   https://www.abuseipdb.com/check/{ext_ip}\n"
        f"If this is known-good, add it to /etc/foxhole/ignore-ips.txt or ignore-domains.txt\n"
        f"on the Pi and run: sudo systemctl restart foxhole-triage\n"
    )


# --------------------------------------------------------------------------- SSH auto-block
def check_ssh_bruteforce(src_ip):
    now = time.time()
    history = _ssh_alert_times[src_ip]
    while history and now - history[0] > SSH_BRUTEFORCE_WINDOW:
        history.popleft()
    history.append(now)
    return len(history) >= SSH_BRUTEFORCE_THRESHOLD


def block_ip(src_ip):
    result = subprocess.run(
        ["nft", "add", "element", "inet", "filter", "BLOCKED_IPS",
         f"{{ {src_ip} timeout {AUTOBLOCK_DURATION}s }}"],
        capture_output=True, text=True)
    if result.returncode == 0:
        log(f"    -> [AUTOBLOCK] {src_ip} blocked for {AUTOBLOCK_DURATION // 60} minutes")
        return True
    log(f"    -> [AUTOBLOCK ERROR] {result.stderr.strip()}")
    return False


def handle_ssh(event, sig):
    src_ip = event.get("src_ip", "")
    is_ssh = event.get("dest_port") == 22 or "ssh" in sig.lower()
    if not (is_ssh and src_ip) or src_ip in AUTOBLOCK_EXEMPT_IPS:
        return
    now = time.time()
    if check_ssh_bruteforce(src_ip) and now - _last_blocked[src_ip] > AUTOBLOCK_DURATION:
        _last_blocked[src_ip] = now
        if block_ip(src_ip):
            write_triage("AUTOBLOCK - SSH Brute Force Threshold Exceeded",
                         f"{src_ip} -> {event.get('dest_ip', '?')}:22",
                         f"{src_ip} exceeded {SSH_BRUTEFORCE_THRESHOLD} SSH alerts in "
                         f"{SSH_BRUTEFORCE_WINDOW}s. Blocked for {AUTOBLOCK_DURATION // 60} minutes. Trigger: {sig}")
            send_email(
                f"[AUTOBLOCK] SSH Brute Force - {src_ip}",
                "AUTOMATED RESPONSE: IP BLOCKED\n================================\n"
                f"BLOCKED IP:   {device_name(src_ip)}\n"
                f"BLOCK TIME:   {datetime.now().isoformat()}\n"
                f"DURATION:     {AUTOBLOCK_DURATION // 60} minutes (expires by itself)\n"
                f"TRIGGER RULE: {sig}\n"
                f"TARGET HOST:  {event.get('dest_ip', '?')}:{event.get('dest_port', '?')}\n"
                f"\nTo unblock now: sudo nft delete element inet filter BLOCKED_IPS {{ {src_ip} }}\n"
                f"To list blocks: sudo nft list set inet filter BLOCKED_IPS\n")


# --------------------------------------------------------------------------- event handlers
def urgent_or_ignored(ext_ip, hostname, abuse):
    """Decide whether a >=80% hit is emailed. Returns (send, reason_if_not)."""
    if ip_ignored(ext_ip):
        return False, "address is in ignore-ips.txt"
    if domain_ignored(hostname):
        return False, f"hostname {hostname} is in ignore-domains.txt"
    if time.time() - _last_emailed[ext_ip] < EMAIL_COOLDOWN:
        return False, "already emailed about this address recently"
    return True, ""


def handle_alert(event):
    a = event.get("alert", {})
    sig = a.get("signature", "")
    now = time.time()

    handle_ssh(event, sig)                      # runs on EVERY alert, before dedup

    if now - _last_seen_sig[sig] < DEDUP_WINDOW:
        return
    _last_seen_sig[sig] = now
    log(f"[+] Alert: {sig}")

    if sig_ignored(sig):
        log("    -> Ignored (matches ignore-signatures.txt). Logged only.")
        return

    ext_ip, home_ip, direction = pick_sides(event)
    hostname = (event.get("tls", {}).get("sni") or event.get("http", {}).get("hostname")
                or _ip_hostname.get(ext_ip))
    abuse = check_abuseipdb(ext_ip, for_alert=True) if ext_ip else None
    if abuse:
        hot = abuse["confidence"] >= ABUSEIPDB_THRESHOLD
        log(f"    -> AbuseIPDB: {RED if hot else ''}{abuse['confidence']}% ({abuse['isp']}){RESET if hot else ''}")

    if not ext_ip:
        # Neither side is an internet address (e.g. traffic to the router-side 192.168.0.x network)
        src, dst = event.get("src_ip", "?"), event.get("dest_ip", "?")
        in_home = lambda ip: ip in DEVICES or ip.startswith("10.0.0.")
        home_ip, peer = (src, dst) if in_home(src) else (dst, src)
        facts = describe(event, peer, home_ip, "between the home network and another local network "
                         "(not the internet)", abuse, hostname)
    else:
        facts = describe(event, ext_ip, home_ip, direction, abuse, hostname)

    severity = a.get("severity", 3)
    high = bool(abuse) and abuse["confidence"] >= ABUSEIPDB_THRESHOLD
    ignored_peer = bool(ext_ip) and (ip_ignored(ext_ip) or domain_ignored(hostname))

    # The NPU runs one request at a time and is shared with Open WebUI, so the AI is only
    # asked about events that will be emailed. Low-severity alerts are logged without it.
    if (high or severity <= 2) and not ignored_peer:
        summary = query_llm(build_prompt(facts)) or fallback_text(ext_ip or "?", home_ip or "?", abuse)
    else:
        summary = ("Low severity and not a known-bad address - logged only, not sent to the AI."
                   + (f" AbuseIPDB score {abuse['confidence']}%." if abuse else ""))
    write_triage(sig, f"{event.get('src_ip', '?')}:{event.get('src_port', '?')} -> "
                      f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}", summary)

    steps = remediation_steps(ext_ip or "?", home_ip or "?", direction, abuse, urgent=high or severity <= 2)
    if ignored_peer:
        log("    -> Ignored address/domain. Logged only.")
    elif high:
        ok, why = urgent_or_ignored(ext_ip, hostname, abuse)
        if ok:
            _last_emailed[ext_ip] = now
            send_email(f"[URGENT] [THREAT {abuse['confidence']}%] {sig}",
                       email_body(facts, summary, steps, ext_ip))
        else:
            log(f"    -> Not emailed: {why}")
    elif severity <= 2:
        send_email(f"[SURICATA Sev{severity}] {sig}", email_body(facts, summary, steps, ext_ip or "?"))
    log("    -> Summary written.")


def handle_flow(event):
    ext_ip, home_ip, direction = pick_sides(event)
    if not ext_ip:
        return
    if ext_ip in _abuse_cache and time.time() - _abuse_cache[ext_ip]["t"] < ABUSE_CACHE_HOURS * 3600:
        abuse = _abuse_cache[ext_ip]["r"]
        if abuse["confidence"] < ABUSEIPDB_THRESHOLD:
            return                               # already known, not bad - the common case
    else:
        abuse = check_abuseipdb(ext_ip, for_alert=False)
        if not abuse:
            return
    if abuse["confidence"] < ABUSEIPDB_THRESHOLD:
        return

    hostname = _ip_hostname.get(ext_ip)
    ok, why = urgent_or_ignored(ext_ip, hostname, abuse)
    if not ok:
        return
    _last_emailed[ext_ip] = time.time()
    log(f"[!] Traffic with known-bad address {RED}{ext_ip} ({abuse['confidence']}%, {abuse['isp']}){RESET} "
        f"<-> {device_name(home_ip)}")
    facts = describe(event, ext_ip, home_ip, direction, abuse, hostname)
    summary = query_llm(build_prompt(facts)) or fallback_text(ext_ip, home_ip, abuse)
    header = f"Known malicious address {ext_ip} ({abuse['confidence']}%)"
    write_triage(header, f"{event.get('src_ip', '?')}:{event.get('src_port', '?')} -> "
                         f"{event.get('dest_ip', '?')}:{event.get('dest_port', '?')}", summary)
    steps = remediation_steps(ext_ip, home_ip, direction, abuse, urgent=True)
    send_email(f"[URGENT] [THREAT {abuse['confidence']}%] {device_name(home_ip)} <-> {ext_ip}",
               email_body(facts, summary, steps, ext_ip))


def remember_hostname(event):
    name = event.get("tls", {}).get("sni") or event.get("http", {}).get("hostname")
    ip = event.get("dest_ip", "")
    if name and is_internet_ip(ip):
        if len(_ip_hostname) > 20000:
            _ip_hostname.clear()
        _ip_hostname[ip] = name


def handle_line(line):
    try:
        event = json.loads(line)
    except ValueError:
        return
    kind = event.get("event_type")
    if kind in ("tls", "http"):
        remember_hostname(event)
    elif kind == "alert":
        handle_alert(event)
    elif kind == "flow":
        handle_flow(event)


# --------------------------------------------------------------------------- main loop
def follow(path):
    """Yield new lines; survives logrotate (both rename and copytruncate)."""
    f = open(path, "rb")
    f.seek(0, 2)
    inode = os.fstat(f.fileno()).st_ino
    buf = b""
    while True:
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith(b"\n"):
                yield buf.decode("utf-8", errors="replace")
                buf = b""
            continue                             # partial line - keep reading for the rest
        time.sleep(1)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        if st.st_ino != inode:
            f.close()
            f = open(path, "rb")
            inode = st.st_ino
            buf = b""
            log("[*] eve.json was replaced - reopened.")
        elif st.st_size < f.tell():
            f.seek(0)
            buf = b""
            log("[*] eve.json was truncated - reading from the start.")


def main():
    os.makedirs(STATE_DIR, exist_ok=True)
    load_cache()
    log(f"[*] FoxHole triage started. Watching {EVE_LOG}; summaries -> {TRIAGE_LOG}")
    log(f"[*] LLM: {MODEL} | AbuseIPDB urgent threshold: {ABUSEIPDB_THRESHOLD}% | "
        f"lookups used today: {_budget['used']}/{ABUSE_DAILY_BUDGET}")
    log(f"[*] Ignoring {len(IGNORE_SIGS)} signature patterns, {len(IGNORE_DOMAINS)} domains, "
        f"{len(IGNORE_NETS)} address ranges")
    try:
        for line in follow(EVE_LOG):
            try:
                handle_line(line)
            except Exception as e:                # one bad event must never stop the daemon
                log(f"[!] Error handling event: {e!r}")
    finally:
        save_cache(force=True)


IGNORE_SIGS, IGNORE_DOMAINS, IGNORE_NETS = load_ignore_lists()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test-email":
        ok = send_email("[TEST] TheFoxHole triage email check",
                        "This is a test message from the FoxHole triage daemon on the Pi.\n"
                        "If you can read this, email alerts are working.\n")
        sys.exit(0 if ok else 1)
    main()
