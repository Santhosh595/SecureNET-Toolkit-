"""
UFW/iptables Firewall Log Parser
Parses Linux firewall logs from UFW and iptables.
"""

import re
from datetime import datetime, timezone
from typing import Generator, Optional


# UFW log format:
# Jun 24 14:30:00 hostname kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1 LEN=60 ...
UFW_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+kernel:\s+"
    r"\[UFW\s+(?P<action>\w+)\]\s+"
    r"(?:IN=(?P<in_iface>\S+)\s+)?"
    r"(?:OUT=(?P<out_iface>\S+)\s+)?"
    r"(?:MAC=(?P<mac>\S+)\s+)?"
    r"SRC=(?P<src_ip>[\d.]+)\s+"
    r"DST=(?P<dst_ip>[\d.]+)\s+"
    r"LEN=(?P<len>\d+)\s+"
    r"TOS=(?P<tos>\S+)\s+"
    r"PREC=(?P<prec>\S+)\s+"
    r"TTL=(?P<ttl>\d+)\s+"
    r"ID=(?P<id>\d+)\s+"
    r"(?:DF\s+)?"
    r"PROTO=(?P<protocol>\S+)\s+"
    r"(?:SPT=(?P<src_port>\d+)\s+)?"
    r"(?:DPT=(?P<dst_port>\d+)\s+)?"
    r"(?:WINDOW=(?P<window>\d+)\s+)?"
    r"(?:RES=(?P<res>\S+)\s+)?"
    r"(?P<flags>\S+)*"
)

# Simplified UFW (less detail)
UFW_SIMPLE = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+"
    r".*?UFW\s+(?P<action>\w+)\s+"
    r"SRC=(?P<src_ip>[\d.]+)\s+"
    r"DST=(?P<dst_ip>[\d.]+)\s+"
    r".*?(?:SPT=(?P<src_port>\d+))?\s*"
    r".*?(?:DPT=(?P<dst_port>\d+))?\s*"
    r".*?PROTO=(?P<protocol>\S+)?"
)

# iptables log format:
# ... IN=eth0 OUT=eth0 SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=12345 DPT=80
IPTABLES_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+"
    r".*?(?:kernel|iptables)?.*?"
    r"IN=(?P<in_iface>\S+)\s+"
    r"OUT=(?P<out_iface>\S+)\s+"
    r"SRC=(?P<src_ip>[\d.]+)\s+"
    r"DST=(?P<dst_ip>[\d.]+)\s+"
    r".*?PROTO=(?P<protocol>\S+)\s+"
    r"SPT=(?P<src_port>\d+)\s+"
    r"DPT=(?P<dst_port>\d+)"
)

# Simplified iptables
IPTABLES_SIMPLE = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+"
    r".*?SRC=(?P<src_ip>[\d.]+)\s+"
    r"DST=(?P<dst_ip>[\d.]+)\s+"
    r".*?PROTO=(?P<protocol>\S+)"
    r"(?:.*?SPT=(?P<src_port>\d+))?"
    r"(?:.*?DPT=(?P<dst_port>\d+))?"
)


def _parse_syslog_ts(ts_str: str) -> datetime:
    """Parse syslog timestamp."""
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return now


def _normalize_action(action: str) -> str:
    """Normalize firewall action."""
    action = action.upper().strip()
    if action in ("BLOCK", "DROP", "DENY", "REJECT"):
        return "BLOCKED"
    if action in ("ALLOW", "ACCEPT", "PERMIT", "PASS"):
        return "ALLOWED"
    if action in ("LOG",):
        return "LOGGED"
    return action


def _extract_protocol(proto_str: str) -> str:
    """Extract and normalize protocol name."""
    proto = proto_str.upper().strip()
    if proto in ("TCP", "UDP", "ICMP", "IGMP", "GRE", "ESP", "AH", "SCTP"):
        return proto
    # Try common proto numbers
    proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP", "47": "GRE", "50": "ESP", "51": "AH"}
    return proto_map.get(proto, proto or "UNKNOWN")


def parse_firewall_line(line: str) -> Optional[dict]:
    """Parse a single firewall log line."""
    line = line.strip()
    if not line:
        return None

    # Try UFW full pattern
    match = UFW_PATTERN.match(line)
    if not match:
        match = UFW_SIMPLE.match(line)
    if not match:
        match = IPTABLES_PATTERN.match(line)
    if not match:
        match = IPTABLES_SIMPLE.match(line)

    if match:
        g = match.groupdict()
        ts = _parse_syslog_ts(g.get("timestamp", ""))
        action_raw = g.get("action", "")
        action = _normalize_action(action_raw) if action_raw else "BLOCKED"

        src_port = g.get("src_port", "0")
        dst_port = g.get("dst_port", "0")
        try:
            src_port = int(src_port) if src_port else 0
        except ValueError:
            src_port = 0
        try:
            dst_port = int(dst_port) if dst_port else 0
        except ValueError:
            dst_port = 0

        # Determine status based on action
        status = "BLOCKED" if action == "BLOCKED" else "SUCCESS"

        return {
            "timestamp": ts,
            "hostname": g.get("hostname", ""),
            "src_ip": g.get("src_ip", ""),
            "dst_ip": g.get("dst_ip", ""),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": _extract_protocol(g.get("protocol", "")),
            "action": f"firewall_{action.lower()}",
            "status": status,
            "in_interface": g.get("in_iface", ""),
            "out_interface": g.get("out_iface", ""),
            "raw": line,
        }

    # Fallback: look for SRC= and DST= patterns
    src_match = re.search(r"SRC=([\d.]+)", line)
    dst_match = re.search(r"DST=([\d.]+)", line)
    if src_match and dst_match:
        ts_match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
        ts = _parse_syslog_ts(ts_match.group(1)) if ts_match else _parse_syslog_ts("")

        action = "BLOCKED"
        action_match = re.search(r"(UFW|iptables).*?(BLOCK|DROP|REJECT|ALLOW|ACCEPT|DENY)", line, re.IGNORECASE)
        if action_match:
            action = _normalize_action(action_match.group(2))
        elif "BLOCK" in line or "DROP" in line or "REJECT" in line:
            action = "BLOCKED"
        elif "ACCEPT" in line or "ALLOW" in line:
            action = "ALLOWED"

        proto_match = re.search(r"PROTO=(\S+)", line)
        proto = _extract_protocol(proto_match.group(1)) if proto_match else "UNKNOWN"

        spt_match = re.search(r"SPT=(\d+)", line)
        dpt_match = re.search(r"DPT=(\d+)", line)

        return {
            "timestamp": ts,
            "hostname": "",
            "src_ip": src_match.group(1),
            "dst_ip": dst_match.group(1),
            "src_port": int(spt_match.group(1)) if spt_match else 0,
            "dst_port": int(dpt_match.group(1)) if dpt_match else 0,
            "protocol": proto,
            "action": f"firewall_{action.lower()}",
            "status": "BLOCKED" if action == "BLOCKED" else "SUCCESS",
            "raw": line,
        }

    return None


def parse_firewall_file(filepath: str, from_lines: list = None) -> Generator[dict, None, None]:
    """Parse a firewall log file."""
    if from_lines is not None:
        for line in from_lines:
            parsed = parse_firewall_line(line)
            if parsed:
                yield parsed
        return

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_firewall_line(line)
            if parsed:
                yield parsed
