"""
LogSentry Cross-Source Correlation Engine
Correlates events across multiple log sources by IP and timestamp.
Builds attacker profiles and detects kill chain stages.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict


# Kill chain stage mapping
KILL_CHAIN_STAGES = {
    "Reconnaissance": ["T1595", "T1046", "T1083", "T1087", "T1018", "T1082"],
    "Initial Access": ["T1078", "T1110", "T1110.001", "T1110.003", "T1190", "T1200"],
    "Execution": ["T1059", "T1059.007", "T1203", "T1547"],
    "Persistence": ["T1078", "T1543.003", "T1547", "T1548", "T1574"],
    "Privilege Escalation": ["T1078.002", "T1078.003", "T1548", "T1134"],
    "Defense Evasion": ["T1070", "T1202", "T1036", "T1027"],
    "Credential Access": ["T1110", "T1110.001", "T1110.003", "T1003", "T1558"],
    "Discovery": ["T1083", "T1046", "T1087", "T1018", "T1082", "T1049"],
    "Lateral Movement": ["T1021", "T1570", "T1080"],
    "Collection": ["T1005", "T1074", "T1030", "T1123"],
    "Exfiltration": ["T1030", "T1048", "T1041", "T1567"],
    "Impact": ["T1486", "T1490", "T1491", "T1498"],
}


def correlate_events(events: list, alerts: list) -> list:
    """Cross-reference events across log sources. Build attacker profiles."""
    # Group events by source IP
    events_by_ip = defaultdict(list)
    alerts_by_ip = defaultdict(list)

    for event in events:
        ip = event.get("src_ip", "")
        if ip:
            events_by_ip[ip].append(event)

    for alert in alerts:
        ip = alert.get("src_ip", "")
        if ip:
            alerts_by_ip[ip].append(alert)

    # Build profiles for each IP
    profiles = []
    all_ips = set(events_by_ip.keys()) | set(alerts_by_ip.keys())

    for ip in all_ips:
        ip_events = events_by_ip.get(ip, [])
        ip_alerts = alerts_by_ip.get(ip, [])

        if not ip_events and not ip_alerts:
            continue

        # Sort events by timestamp
        ip_events.sort(key=lambda e: e.get("timestamp", ""))

        # Determine sources seen
        sources = set()
        for event in ip_events:
            sources.add(event.get("log_type", "unknown"))

        # Rules triggered
        rules_triggered = set()
        for alert in ip_alerts:
            rules_triggered.add(alert.get("rule_name", ""))

        # Determine kill chain stages
        mitre_ids = set()
        for alert in ip_alerts:
            mid = alert.get("mitre_id", "")
            if mid:
                mitre_ids.add(mid)

        kill_chain = _map_to_kill_chain(mitre_ids)

        # First/last seen
        timestamps = [e["timestamp"] for e in ip_events if isinstance(e.get("timestamp"), datetime)]
        first_seen = min(timestamps) if timestamps else datetime.now(timezone.utc)
        last_seen = max(timestamps) if timestamps else datetime.now(timezone.utc)

        profile = {
            "ip": ip,
            "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else str(first_seen),
            "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen),
            "event_count": len(ip_events),
            "alert_count": len(ip_alerts),
            "rules_triggered": ", ".join(rules_triggered),
            "sources_seen": ", ".join(sources),
            "kill_chain": " → ".join(kill_chain) if kill_chain else "",
            "mitre_ids": ", ".join(mitre_ids),
            "priority": _calculate_priority(len(sources), len(ip_alerts), len(rules_triggered)),
        }
        profiles.append(profile)

    # Sort by priority (high first) then event count
    profiles.sort(key=lambda p: (-ord(p["priority"][0]), -p["event_count"]))

    return profiles


def _map_to_kill_chain(mitre_ids: set) -> list:
    """Map MITRE ATT&CK technique IDs to kill chain stages."""
    stages = []
    for stage_name, technique_ids in KILL_CHAIN_STAGES.items():
        for tid in mitre_ids:
            if tid in technique_ids:
                if stage_name not in stages:
                    stages.append(stage_name)
                break
    return stages


def _calculate_priority(sources_count: int, alert_count: int, rules_count: int) -> str:
    """Calculate priority level for an IP."""
    score = sources_count * 2 + alert_count + rules_count
    if sources_count >= 3 or score >= 10:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    return "LOW"


def get_attack_chain_summary(profiles: list) -> dict:
    """Generate a summary of detected attack chains."""
    summary = {
        "total_attackers": len(profiles),
        "critical": sum(1 for p in profiles if p.get("priority") == "CRITICAL"),
        "high": sum(1 for p in profiles if p.get("priority") == "HIGH"),
        "medium": sum(1 for p in profiles if p.get("priority") == "MEDIUM"),
        "low": sum(1 for p in profiles if p.get("priority") == "LOW"),
        "kill_chains_detected": sum(1 for p in profiles if p.get("kill_chain")),
        "multi_source_attackers": sum(1 for p in profiles if "," in p.get("sources_seen", "")),
    }
    return summary
