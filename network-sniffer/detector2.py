import time
from collections import defaultdict
import json

# Configurable thresholds (tweak these for testing)
PORT_SCAN_WINDOW = 10   # seconds window
PORT_SCAN_THRESHOLD = 10  # unique dst ports in window -> alert

RATE_WINDOW = 50 
RATE_THRESHOLD = 5    # packets in window -> alert

COOLDOWN = 15  # seconds to suppress repeated alert for same (rule,src)

_last_alert_ts = {}  # {(rule,src): last_ts}

def _cooldown_ok(rule, src):
    key = (rule, src)
    now = time.time()
    last = _last_alert_ts.get(key, 0)
    if now - last >= COOLDOWN:
        _last_alert_ts[key] = now
        return True
    return False

def detect_port_scan(db_module):
    rows = db_module.get_recent_packets(PORT_SCAN_WINDOW)
    by_src = {}
    for r in rows:
        ts, src, dst, proto, sport, dport, length, flags = r
        if not src:
            continue
        if src not in by_src:
            by_src[src] = set()
        if dport:
            try:
                by_src[src].add(int(dport))
            except Exception:
                pass
    alerts = []
    for src, ports in by_src.items():
        if len(ports) >= PORT_SCAN_THRESHOLD and _cooldown_ok("PORT_SCAN", src):
            meta = {"unique_ports": len(ports), "ports_sample": list(ports)[:10]}
            alerts.append(("PORT_SCAN", src, json.dumps(meta)))
    return alerts

def detect_high_rate(db_module):
    rows = db_module.get_recent_packets(RATE_WINDOW)
    counts = {}
    for r in rows:
        ts, src, *_ = r
        if not src:
            continue
        counts[src] = counts.get(src, 0) + 1
    alerts = []
    for src, cnt in counts.items():
        if cnt >= RATE_THRESHOLD and _cooldown_ok("HIGH_RATE", src):
            meta = {"count": cnt}
            alerts.append(("HIGH_RATE", src, json.dumps(meta)))
    return alerts
