#!/usr/bin/env python3
# sniffer_alert2.py
from scapy.all import sniff, IP, TCP, UDP
import time, os, json
import db, detector2

# initialize DB
db.init_db()
os.makedirs("logs", exist_ok=True)

def pkt_to_tuple(pkt):
    ts = time.time()
    src = pkt[IP].src if IP in pkt else None
    dst = pkt[IP].dst if IP in pkt else None
    proto = "OTHER"
    sport = None; dport = None; flags = ""
    if TCP in pkt:
        proto = "TCP"
        sport = getattr(pkt[TCP], "sport", None)
        dport = getattr(pkt[TCP], "dport", None)
        flags = str(getattr(pkt[TCP], "flags", ""))
    elif UDP in pkt:
        proto = "UDP"
        sport = getattr(pkt[UDP], "sport", None)
        dport = getattr(pkt[UDP], "dport", None)
    length = len(pkt)
    return (ts, src, dst, proto, sport, dport, length, flags)

def handle_packet(pkt):
    try:
        ts, src, dst, proto, sport, dport, length, flags = pkt_to_tuple(pkt)
        db.insert_packet(ts, src, dst, proto, sport, dport, length, flags)
        # live console output (short)
        print(time.strftime("%H:%M:%S", time.localtime(ts)), src, "->", dst, proto, f"{sport}->{dport}", f"len={length}")
    except Exception as e:
        print("pkt store error:", e)

def run_detectors_loop(interval=5):
    import threading
    def job():
        try:
            alerts = []
            alerts += detector2.detect_port_scan(db)
            alerts += detector2.detect_high_rate(db)
            for rule, src, meta in alerts:
                entry = {"ts": time.time(), "rule": rule, "src": src, "meta": json.loads(meta) if isinstance(meta, str) else meta}
                # write to jsonl log
                with open("logs/alerts.log", "a") as f:
                    f.write(json.dumps(entry) + "\n")
                # record into DB
                db.insert_alert(rule, src, json.dumps(entry["meta"]))
                print("!!! ALERT:", entry)
        except Exception as e:
            print("detector loop error:", e)
        threading.Timer(interval, job).start()
    job()

if __name__ == "__main__":
    print("Starting advanced sniffer (db-backed). Run as root/admin.")
    run_detectors_loop(5)  # run detectors every 5 seconds
    sniff(filter="ip", prn=handle_packet, store=False)
