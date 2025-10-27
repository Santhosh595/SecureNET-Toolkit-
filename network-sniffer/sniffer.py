#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP
import time

def summarize_packet(pkt):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    src = pkt[IP].src if IP in pkt else "N/A"
    dst = pkt[IP].dst if IP in pkt else "N/A"

    if TCP in pkt:
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        flags = pkt[TCP].flags
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        flags = ""
    else:
        proto, sport, dport, flags = pkt.payload.name, "-", "-", ""

    length = len(pkt)
    return f"{ts}  {src}:{sport} -> {dst}:{dport}  {proto}  len={length}  flags={flags}"

def handle_packet(pkt):
    try:
        info = summarize_packet(pkt)
        print(info)
        with open("packets_log.txt","a") as log:
            log.write(info+"\n")
    except Exception as e:
        print("Error:", e)

def main():
    print("Starting sniffer... (Ctrl+C to stop)")
    sniff(filter="ip", prn=handle_packet, store=False)

if __name__ == "__main__":
    main()
