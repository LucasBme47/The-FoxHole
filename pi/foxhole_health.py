#!/usr/bin/env python3
"""FoxHole health checks for the Grafana "FoxHole SOC" dashboard.

Runs once a minute (foxhole-health.timer) and writes Prometheus metrics to
/var/lib/prometheus/node-exporter/foxhole_health.prom. node-exporter's textfile
collector publishes that file, and Prometheus scrapes it from there.

Checks:
  NAS        - is the NAS disk mounted, free space, is Samba (SMB) answering,
               age of the newest FoxHole backup archive.
  Minecraft  - does the server PC answer ping, does the Minecraft server answer
               a Server List Ping (the same status request the game's server
               list sends), its response time, players online / max.
  Pi-hole    - running count of blocked DNS queries, read read-only from
               Pi-hole's query database. (Pi-hole's own "blocked today" figure is
               a rolling 24-hour total, so it cannot show blocks per time period.)
"""
import glob
import json
import os
import socket
import sqlite3
import struct
import subprocess
import time

OUT_DIR = "/var/lib/prometheus/node-exporter"
OUT_FILE = os.path.join(OUT_DIR, "foxhole_health.prom")
STATE_FILE = "/var/lib/foxhole-health/state.json"

NAS_MOUNT = "/mnt/nas"
BACKUP_GLOB = "/mnt/nas/FoxHole-Backups/foxhole-*.tar.gz"
SMB_ADDR = ("127.0.0.1", 445)

# EXAMPLE VALUES - your Minecraft server PC (GameServer) and its port.
MC_HOST = "10.0.0.18"
MC_PORT = 25565
TIMEOUT = 5

FTL_DB = "/etc/pihole/pihole-FTL.db"
# Pi-hole query status codes that mean "blocked" (docs.pi-hole.net/database/query-database)
BLOCKED_STATUS = (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18)


def tcp_up(addr):
    try:
        with socket.create_connection(addr, timeout=TIMEOUT):
            return 1
    except OSError:
        return 0


def ping_up(host):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", host],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=TIMEOUT)
        return 1 if r.returncode == 0 else 0
    except (OSError, subprocess.TimeoutExpired):
        return 0


def check_nas():
    m = {"foxhole_nas_mounted": 1 if os.path.ismount(NAS_MOUNT) else 0}
    if m["foxhole_nas_mounted"]:
        try:
            st = os.statvfs(NAS_MOUNT)
            m["foxhole_nas_size_bytes"] = st.f_blocks * st.f_frsize
            m["foxhole_nas_avail_bytes"] = st.f_bavail * st.f_frsize
        except OSError:
            pass
        try:
            newest = max((os.path.getmtime(p) for p in glob.glob(BACKUP_GLOB)), default=None)
            if newest is not None:
                m["foxhole_nas_last_backup_timestamp_seconds"] = int(newest)
        except OSError:
            pass
    m["foxhole_nas_smb_up"] = tcp_up(SMB_ADDR)
    return m


# --- Minecraft Server List Ping (Java edition, 1.7+) ---
def _varint(n):
    n &= 0xFFFFFFFF
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


def _read_varint(sock):
    value = 0
    for i in range(5):
        b = _recv_exact(sock, 1)[0]
        value |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return value
    raise OSError("bad varint")


def _packet(data):
    return _varint(len(data)) + data


def minecraft_status():
    host = MC_HOST.encode()
    handshake = (_varint(0) + _varint(767) + _varint(len(host)) + host
                 + struct.pack(">H", MC_PORT) + _varint(1))
    start = time.monotonic()
    with socket.create_connection((MC_HOST, MC_PORT), timeout=TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        s.sendall(_packet(handshake) + _packet(_varint(0)))
        _read_varint(s)                       # packet length
        if _read_varint(s) != 0:              # packet id
            raise OSError("unexpected packet")
        length = _read_varint(s)
        if length > 1_000_000:
            raise OSError("status too large")
        data = json.loads(_recv_exact(s, length).decode("utf-8", "replace"))
    return data, time.monotonic() - start


def check_minecraft():
    m = {"foxhole_minecraft_host_up": ping_up(MC_HOST),
         "foxhole_minecraft_up": 0,
         "foxhole_minecraft_players_online": 0}
    try:
        data, elapsed = minecraft_status()
        players = data.get("players", {}) if isinstance(data, dict) else {}
        m["foxhole_minecraft_up"] = 1
        m["foxhole_minecraft_response_seconds"] = round(elapsed, 4)
        m["foxhole_minecraft_players_online"] = int(players.get("online", 0))
        m["foxhole_minecraft_players_max"] = int(players.get("max", 0))
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return m


# --- Pi-hole blocked-query counter ---
def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def check_pihole(state):
    """Add newly stored blocked queries to a running total kept in the state file.
    FTL writes queries to its database about once a minute; counting by row id
    means late writes are still counted, just in the next run."""
    m = {"foxhole_pihole_db_ok": 0}
    try:
        con = sqlite3.connect(f"file:{FTL_DB}?mode=ro", uri=True, timeout=10)
        try:
            max_id = con.execute("SELECT MAX(id) FROM query_storage").fetchone()[0] or 0
            last_id = state.get("last_id")
            total = state.get("blocked_total", 0)
            if last_id is None or max_id < last_id:
                last_id = max_id            # first run, or the database was reset
            elif max_id > last_id:
                marks = ",".join("?" * len(BLOCKED_STATUS))
                new = con.execute(
                    f"SELECT COUNT(*) FROM query_storage WHERE id > ? AND id <= ? AND status IN ({marks})",
                    (last_id, max_id, *BLOCKED_STATUS)).fetchone()[0]
                total += new
                last_id = max_id
        finally:
            con.close()
        state["last_id"], state["blocked_total"] = last_id, total
        m["foxhole_pihole_db_ok"] = 1
    except sqlite3.Error:
        pass
    if "blocked_total" in state:
        m["foxhole_pihole_blocked_total"] = state["blocked_total"]
    return m


HELP = {
    "foxhole_health_last_run_timestamp_seconds": "When this check last ran (Unix time).",
    "foxhole_nas_mounted": "1 if the NAS disk is mounted at /mnt/nas.",
    "foxhole_nas_size_bytes": "NAS disk size.",
    "foxhole_nas_avail_bytes": "NAS free space.",
    "foxhole_nas_smb_up": "1 if Samba answers on port 445.",
    "foxhole_nas_last_backup_timestamp_seconds": "Time of the newest FoxHole backup archive.",
    "foxhole_minecraft_host_up": "1 if the Minecraft server PC answers ping.",
    "foxhole_minecraft_up": "1 if the Minecraft server answers a status request.",
    "foxhole_minecraft_response_seconds": "Minecraft status request round-trip time.",
    "foxhole_minecraft_players_online": "Players online.",
    "foxhole_minecraft_players_max": "Player slots.",
    "foxhole_pihole_db_ok": "1 if the Pi-hole query database could be read.",
    "foxhole_pihole_blocked_total": "Blocked DNS queries counted since this check was installed.",
}


def main():
    state = load_state()
    metrics = {}
    metrics.update(check_nas())
    metrics.update(check_minecraft())
    metrics.update(check_pihole(state))
    metrics["foxhole_health_last_run_timestamp_seconds"] = int(time.time())
    save_state(state)

    lines = []
    for name, value in metrics.items():
        kind = "counter" if name.endswith("_total") else "gauge"
        lines += [f"# HELP {name} {HELP.get(name, name)}", f"# TYPE {name} {kind}", f"{name} {value}"]
    tmp = OUT_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT_FILE)


if __name__ == "__main__":
    main()
