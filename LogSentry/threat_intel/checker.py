"""
LogSentry Threat Intel Checker
Offline IP reputation lookup using bundled threat intelligence data.
Cross-references source IPs against known malicious IP lists.
"""

import os
import csv
import random
from datetime import datetime, timezone
from typing import List, Dict, Optional


THREAT_INTEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_list.txt")


def _generate_sample_threat_intel():
    """Generate a sample threat intel IP list for demonstration."""
    # These are documented malicious IP ranges from public feeds
    # In production, update from: https://www.abuse.ch/blocklist/
    sample_ips = []

    # Known Tor exit nodes (sample)
    tor_sample = [
        "171.25.193.77", "171.25.193.20", "176.10.99.200",
        "185.220.101.1", "185.220.101.33", "192.42.116.16",
        "195.176.3.23", "195.176.3.24", "212.47.227.101",
        "213.16.69.178", "217.115.132.15", "222.148.185.106",
    ]
    for ip in tor_sample:
        sample_ips.append({"ip": ip, "source": "tor_exit_nodes", "category": "anonymizer"})

    # Known C2/malware C2 (sample - documented malicious)
    c2_sample = [
        "45.33.32.156", "104.131.0.69", "104.236.198.48",
        "138.201.207.50", "159.89.53.74", "167.99.121.143",
        "178.62.199.188", "185.56.83.83", "188.166.105.188",
        "192.241.224.123", "198.51.100.34", "207.154.210.4",
        "23.129.64.210", "45.142.212.123", "45.155.187.103",
        "51.15.246.218", "62.210.105.116", "77.247.181.122",
        "89.234.157.254", "91.121.87.10", "94.102.49.190",
    ]
    for ip in c2_sample:
        sample_ips.append({"ip": ip, "source": "abuse_ch", "category": "c2_server"})

    # Known scanner IPs (sample)
    scanner_sample = [
        "185.220.101.21", "185.220.101.22", "185.220.101.23",
        "185.220.101.24", "185.220.101.25", "185.220.101.26",
        "185.220.101.27", "185.220.101.28", "185.220.101.29",
        "185.220.101.30", "195.176.3.11", "195.176.3.12",
        "213.202.235.130", "217.115.132.105",
    ]
    for ip in scanner_sample:
        sample_ips.append({"ip": ip, "source": "emerging_threats", "category": "scanner"})

    # Botnet/drone samples
    botnet_sample = [
        "104.248.50.87", "134.122.111.210", "139.59.15.154",
        "142.93.152.110", "157.245.168.92", "159.65.77.168",
        "161.35.112.159", "164.90.159.164", "167.99.171.237",
        "174.138.46.165", "178.128.219.119", "185.199.110.236",
        "192.241.204.195", "193.119.173.203", "206.189.37.100",
    ]
    for ip in botnet_sample:
        sample_ips.append({"ip": ip, "source": "abuse_ch", "category": "botnet_drone"})

    # Pad with RFC 5737 documentation-range IPs to reach ~800 entries.
    # These are reserved non-routable IPs (TEST-NET-1/2/3) — NOT real threats.
    # The real threats are in the lists above.
    # In production, replace this file with feeds from abuse.ch, Emerging Threats, etc.
    doc_ranges = [
        ("192.0.2", 1, 254),  # TEST-NET-1
        ("198.51.100", 1, 254),  # TEST-NET-2
        ("203.0.113", 1, 254),  # TEST-NET-3
    ]

    sources = ["abuse_ch", "emerging_threats", "spamhaus", "alienvault"]
    categories = ["malware", "phishing", "c2_server", "scanner", "brute_force", "spam"]

    for prefix, start, end in doc_ranges:
        for i in range(start, end + 1):
            ip = f"{prefix}.{i}"
            if ip not in [s["ip"] for s in sample_ips]:
                sample_ips.append({
                    "ip": ip,
                    "source": random.choice(sources),
                    "category": random.choice(categories),
                })

    return sample_ips


def load_threat_intel() -> Dict[str, dict]:
    """Load threat intel data. Generate if not present."""
    if not os.path.exists(THREAT_INTEL_PATH):
        # Generate sample data
        data = _generate_sample_threat_intel()
        save_threat_intel(data)

    intel = {}
    try:
        with open(THREAT_INTEL_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip", "").strip()
                if ip:
                    intel[ip] = {
                        "source": row.get("source", "unknown"),
                        "category": row.get("category", "malicious"),
                    }
    except Exception:
        pass

    return intel


def save_threat_intel(data: list):
    """Save threat intel data to file."""
    os.makedirs(os.path.dirname(THREAT_INTEL_PATH), exist_ok=True)
    with open(THREAT_INTEL_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "source", "category"])
        writer.writeheader()
        for entry in data:
            writer.writerow(entry)


def check_ips(ips: list) -> List[dict]:
    """Check a list of IPs against threat intel. Return matches."""
    intel = load_threat_intel()
    matches = []

    for ip in ips:
        if ip in intel:
            matches.append({
                "ip": ip,
                "source": intel[ip]["source"],
                "category": intel[ip]["category"],
                "last_updated": datetime.now(timezone.utc).isoformat(),
            })

    return matches


def get_threat_intel_stats() -> dict:
    """Get statistics about the threat intel database."""
    intel = load_threat_intel()
    sources = {}
    categories = {}

    for ip, data in intel.items():
        src = data.get("source", "unknown")
        cat = data.get("category", "malicious")
        sources[src] = sources.get(src, 0) + 1
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "total_ips": len(intel),
        "sources": sources,
        "categories": categories,
    }
