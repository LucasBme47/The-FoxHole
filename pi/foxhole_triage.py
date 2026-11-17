#!/usr/bin/env python3
"""
TheFoxHole V3 triage daemon  ->  /usr/local/lib/foxhole/foxhole_triage.py

Reads Suricata's eve.json as it is written and:
  1. ALERTS  - every Suricata alert is looked up in AbuseIPDB, summarised by the
               on-device LLM (Hailo NPU via hailo-ollama) and written to triage.log.
               Severity 1-2 alerts are emailed.
  2. TRAFFIC - every finished connection (flow) to/from an internet address is checked
               against AbuseIPDB's daily worst-addresses list (free, local) and looked up
               in AbuseIPDB (remembered 1-7 days by score; the daily limit is read from
               AbuseIPDB's own answers). No Suricata alert is needed.
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
# How long an AbuseIPDB answer is remembered before the address is looked up again.
# Clean addresses (mostly Microsoft/Google/Akamai/Amazon) are kept longer; anything with
# a real score is re-checked daily so a worsening address is noticed quickly.
CACHE_TTL_CLEAN = 7 * 86400     # score 0 %
CACHE_TTL_LOW = 3 * 86400       # score 1-24 %
CACHE_TTL_RISKY = 86400         # score 25 % and up
FAILED_RETRY = 900              # after a failed lookup, leave that address alone for 15 minutes
# The free plan allows 1000 lookups a day. The remaining count is taken from AbuseIPDB's own
# answer headers (its day does not start at local midnight), so it is always accurate.
ABUSE_ALERT_RESERVE = 150       # when this few are left, traffic checks stop; Suricata alerts still get them
# AbuseIPDB's daily list of the worst addresses (free plan: 5 downloads/day, up to 10,000 IPs).
# Every connection is checked against it locally, which costs no lookups.
BLACKLIST_FILE = os.path.join(STATE_DIR, "abuseipdb-blacklist.txt")
BLACKLIST_REFRESH = 86400       # download once a day
BLACKLIST_RETRY = 6 * 3600      # after a failed download, wait 6 hours (stays well under 5/day)
STATS_INTERVAL = 3600           # write a usage summary line to the log every hour
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
_abuse_failed = {}                      # ip -> epoch of the last failed lookup
# remaining/reset come from AbuseIPDB's X-RateLimit-* headers; None = not known yet
_budget = {"remaining": None, "reset": 0, "paused_until": 0, "warned": False}
_blacklist = set()                      # AbuseIPDB's daily worst-addresses list
_bl_state = {"next_try": 0, "loaded_mtime": 0}
_stats = {"since": time.time(), "lookups": 0, "remembered": 0, "listed_hits": 0, "skipped": 0}
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
def cache_ttl(report):
    c = report.get("confidence", 0)
    if c == 0:
        return CACHE_TTL_CLEAN
    if c < 25:
        return CACHE_TTL_LOW
    return CACHE_TTL_RISKY


def cached_report(ip, now):
    hit = _abuse_cache.get(ip)
    if hit and now - hit["t"] < cache_ttl(hit["r"]):
        return hit["r"]
    return None


def load_cache():
    global _abuse_cache
    try:
        with open(CACHE_FILE) as f:
            data = json.load(f)
        _abuse_cache = data.get("cache", {})
        saved = data.get("budget", {})
        for k in ("remaining", "reset", "paused_until", "warned"):   # ignore older-format keys
            if k in saved:
                _budget[k] = saved[k]
    except (FileNotFoundError, ValueError):
        pass


def save_cache(force=False):
    global _cache_dirty
    if not force and _cache_dirty < 20:
        return
    now = time.time()
    for ip in [k for k, v in _abuse_cache.items() if now - v["t"] >= cache_ttl(v["r"])]:
        del _abuse_cache[ip]
    tmp = CACHE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"cache": _abuse_cache, "budget": _budget}, f)
    os.replace(tmp, CACHE_FILE)
    _cache_dirty = 0


def _int_header(resp, name):
    try:
        return int(float(resp.headers.get(name, "")))
    except (TypeError, ValueError):
        return None


def note_rate_headers(resp, now):
    """Take the remaining-lookups count and reset time from AbuseIPDB's own answer."""
    remaining = _int_header(resp, "X-RateLimit-Remaining")
    reset = _int_header(resp, "X-RateLimit-Reset")
    if remaining is not None:
        _budget["remaining"] = remaining
    if reset is not None and now < reset < now + 2 * 86400:
        _budget["reset"] = reset
    elif remaining is not None and not now < _budget["reset"] < now + 2 * 86400:
        _budget["reset"] = now + 3600          # no usable reset time: re-sync within the hour


def budget_open(now, for_alert):
    """False if a lookup now would be refused or would eat into the alert reserve."""
    if now < _budget["paused_until"]:
        return False
    if _budget["reset"] and now >= _budget["reset"]:
        _budget.update(remaining=None, reset=0, warned=False)   # new AbuseIPDB day
    remaining = _budget["remaining"]
    if remaining is None:
        return True
    if remaining <= 0:
        return False
    if not for_alert and remaining <= ABUSE_ALERT_RESERVE:
        if not _budget["warned"]:
            _budget["warned"] = True
            log(f"[!] Only {remaining} AbuseIPDB lookups left today. Traffic checks pause until "
                f"{when(_budget['reset'])}; Suricata alerts and the daily worst-addresses list are still checked.")
        return False
    return True


def when(epoch):
    return datetime.fromtimestamp(epoch).strftime("%H:%M on %b %d") if epoch else "AbuseIPDB's daily reset"


def check_abuseipdb(ip, for_alert):
    """Return an AbuseIPDB report dict, or None if no lookup was possible."""
    global _cache_dirty
    now = time.time()
    hit = cached_report(ip, now)
    if hit is not None:
        _stats["remembered"] += 1
        return hit
    if now - _abuse_failed.get(ip, 0) < FAILED_RETRY or not budget_open(now, for_alert):
        _stats["skipped"] += 1
        return None

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
    except Exception as e:
        _abuse_failed[ip] = now
        log(f"    -> [ABUSEIPDB ERROR for {ip}: {e}]")
        return None
    note_rate_headers(resp, now)
    if resp.status_code == 429:
        wait = _int_header(resp, "Retry-After") or 3600
        _budget["paused_until"] = now + wait
        _budget["remaining"] = 0
        save_cache(force=True)
        log(f"[!] AbuseIPDB says the daily lookup limit is used up. Lookups paused until "
            f"{when(now + wait)}; the daily worst-addresses list is still checked.")
        return None
    _stats["lookups"] += 1
    try:
        resp.raise_for_status()
        d = resp.json().get("data", {})
    except Exception as e:
        _abuse_failed[ip] = now
        if len(_abuse_failed) > 5000:
            _abuse_failed.clear()
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


# --------------------------------------------------------------------------- daily worst-addresses list
def _parse_blacklist(resp):
    """Accept either the plain-text answer (one IP per line) or the JSON answer."""
    text = resp.text.strip()
    if text.startswith("{"):
        lines = [row.get("ipAddress", "") for row in resp.json().get("data", [])]
    else:
        lines = text.splitlines()
    ips = set()
    for line in lines:
        line = line.strip()
        try:
            ipaddress.ip_address(line)
            ips.add(line)
        except ValueError:
            continue
    return ips


def load_blacklist_file():
    global _blacklist
    try:
        mtime = os.path.getmtime(BLACKLIST_FILE)
        with open(BLACKLIST_FILE) as f:
            _blacklist = {line.strip() for line in f if line.strip()}
        _bl_state["loaded_mtime"] = mtime
        return mtime
    except FileNotFoundError:
        return 0


def refresh_blacklist(now):
    """Download AbuseIPDB's worst-addresses list once a day. Cheap to call often."""
    global _blacklist
    if now < _bl_state["next_try"]:
        return
    try:
        mtime = os.path.getmtime(BLACKLIST_FILE)
    except FileNotFoundError:
        mtime = 0
    if now - mtime < BLACKLIST_REFRESH:          # the saved copy is still fresh
        if mtime != _bl_state["loaded_mtime"]:
            load_blacklist_file()
        _bl_state["next_try"] = mtime + BLACKLIST_REFRESH
        return
    _bl_state["next_try"] = now + BLACKLIST_RETRY  # unless the download below succeeds
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "text/plain"},
            params={"limit": 10000, "ipVersion": 4},
            timeout=60,
        )
        if resp.status_code == 429:
            wait = _int_header(resp, "Retry-After") or BLACKLIST_RETRY
            _bl_state["next_try"] = now + max(wait, 600)
            log(f"[!] Worst-addresses list: download limit reached, next try {when(_bl_state['next_try'])}.")
            return
        resp.raise_for_status()
        ips = _parse_blacklist(resp)
    except Exception as e:
        log(f"[!] Worst-addresses list download failed ({e}); keeping the previous copy "
            f"({len(_blacklist)} addresses), next try {when(_bl_state['next_try'])}.")
        return
    if len(ips) < 100:
        log(f"[!] Worst-addresses list download looked wrong ({len(ips)} addresses); keeping the previous copy.")
        return
    tmp = BLACKLIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(sorted(ips)) + "\n")
    os.replace(tmp, BLACKLIST_FILE)
    _blacklist = ips
    _bl_state["loaded_mtime"] = os.path.getmtime(BLACKLIST_FILE)
    _bl_state["next_try"] = now + BLACKLIST_REFRESH
    log(f"[*] Worst-addresses list updated from AbuseIPDB: {len(ips)} addresses.")


def reputation(ip, for_alert):
    """AbuseIPDB view of an address: the daily list first (free), then a lookup if needed."""
    listed = ip in _blacklist
    if listed:
        _stats["listed_hits"] += 1
    # An address on the worst-addresses list always gets a lookup for details, even from the reserve.
    abuse = check_abuseipdb(ip, for_alert=for_alert or listed)
    if not listed:
        return abuse
    merged = dict(abuse) if abuse else {"reports": "?", "country": "?", "isp": "?", "usage": "?", "domain": "?"}
    merged["confidence"] = max(merged.get("confidence", 0), 100)
    merged["listed"] = True
    return merged


def log_stats(now):
    if now - _stats["since"] < STATS_INTERVAL:
        return
    left = _budget["remaining"]
    log(f"[*] Past hour: {_stats['lookups']} AbuseIPDB lookups, {_stats['remembered']} answered from memory, "
        f"{_stats['skipped']} skipped (paused or recently failed), {_stats['listed_hits']} on the worst-addresses list. "
        f"Lookups left today: {'unknown' if left is None else left}. Remembered addresses: {len(_abuse_cache)}.")
    _stats.update(since=now, lookups=0, remembered=0, listed_hits=0, skipped=0)


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
                     f"country: {abuse['country']}, usage type: {abuse['usage']}"
                     + ("; the address is on AbuseIPDB's daily list of the worst 10,000 addresses"
                        if abuse.get("listed") else ""))
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
    abuse = reputation(ext_ip, for_alert=True) if ext_ip else None
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
    abuse = reputation(ext_ip, for_alert=False)
    if not abuse or abuse["confidence"] < ABUSEIPDB_THRESHOLD:
        return                                   # unknown or not bad - the common case

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
    now = time.time()
    refresh_blacklist(now)
    log_stats(now)
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
    load_blacklist_file()
    log(f"[*] FoxHole triage started. Watching {EVE_LOG}; summaries -> {TRIAGE_LOG}")
    left = _budget["remaining"]
    log(f"[*] LLM: {MODEL} | AbuseIPDB urgent threshold: {ABUSEIPDB_THRESHOLD}% | "
        f"lookups left today: {'unknown until the first lookup' if left is None else left} | "
        f"remembered addresses: {len(_abuse_cache)}")
    if time.time() < _budget["paused_until"]:
        log(f"[*] AbuseIPDB lookups are paused until {when(_budget['paused_until'])} (daily limit reached).")
    refresh_blacklist(time.time())
    log(f"[*] Worst-addresses list: {len(_blacklist)} addresses")
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
