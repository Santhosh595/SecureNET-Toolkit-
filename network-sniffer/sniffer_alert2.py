"""Advanced network sniffer with database-backed storage and live detection.

Captures packets via Scapy, stores them in SQLite, and runs detection
rules on a timer thread. Run as administrator/root for packet capture.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Optional

from scapy.all import sniff, IP, TCP, UDP

import db
import detector2

# --- Packet Processing ---


def pkt_to_tuple(pkt) -> tuple:
    """Extract structured data from a captured packet."""
    ts = time.time()
    src = pkt[IP].src if IP in pkt else None
    dst = pkt[IP].dst if IP in pkt else None
    proto = "OTHER"
    sport: Optional[int] = None
    dport: Optional[int] = None
    flags = ""

    if TCP in pkt:
        proto = "TCP"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        proto = "UDP"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)

    length = len(pkt)
    return (ts, src, dst, proto, sport, dport, length, flags)


def handle_packet(pkt) -> None:
    """Callback for each captured packet — store in database and print."""
    try:
        ts, src, dst, proto, sport, dport, length, flags = pkt_to_tuple(pkt)
        db.insert_packet(ts, src, dst, proto, sport, dport, length, flags)

        ts_str = time.strftime("%H:%M:%S", time.localtime(ts))
        print(f"{ts_str}  {src}:{sport} -> {dst}:{dport}  {proto}  len={length}  flags={flags}")
    except Exception as exc:
        print(f"[ERROR] Packet processing failed: {exc}")


# --- Detection Loop ---


def run_detectors_loop(interval: float = 5.0) -> None:
    """Start a background thread that runs detection rules periodically."""

    def _job() -> None:
        try:
            alerts = detector2.detect_port_scan(db) + detector2.detect_high_rate(db)
            for rule, src, meta in alerts:
                entry = {
                    "ts": time.time(),
                    "rule": rule,
                    "src": src,
                    "meta": json.loads(meta) if isinstance(meta, str) else meta,
                }
                log_path = Path("logs/alerts.log")
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(log_path, "a") as f:
                    f.write(json.dumps(entry) + "\n")

                db.insert_alert(rule, src, json.dumps(entry["meta"]))
                print(f"[ALERT] {rule} from {src}: {entry['meta']}")
        except Exception as exc:
            print(f"[ERROR] Detector loop: {exc}")

        threading.Timer(interval, _job).start()

    _job()


# --- Entry Point ---


def main() -> None:
    """Initialize database, start detection loop, and begin packet capture."""
    db.init_db()
    print("[*] Database initialized.")
    print("[*] Starting advanced sniffer with detection.")
    print("[*] Run as administrator/root for packet capture.")
    print("[*] Press Ctrl+C to stop.\n")

    run_detectors_loop(interval=5.0)

    try:
        sniff(filter="ip", prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped.")
        print(f"[*] Total packets: {db.count_packets()}")
        print(f"[*] Total alerts:  {db.count_alerts()}")
    except PermissionError:
        print("\n[ERROR] Permission denied. Run as administrator/root.")


if __name__ == "__main__":
    main()
