"""
Windows Event Log Parser
Handles exported Windows Event Logs in CSV or JSON format.
Key Event IDs: 4624, 4625, 4648, 4720, 4722, 4724, 4728, 4732, 4756, 4768, 4769, 4771, 4776, 4946, 7045
"""

import re
import csv
import json
from datetime import datetime, timezone
from typing import Generator, Optional


# Windows Event ID descriptions
EVENT_DESCRIPTIONS = {
    4624: "Successful logon",
    4625: "Failed logon",
    4626: "User logoff",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned",
    4720: "User account created",
    4722: "User account enabled",
    4723: "Password change attempt",
    4724: "Password reset attempt",
    4725: "User account disabled",
    4726: "User account deleted",
    4728: "User added to security group",
    4732: "User added to local group",
    4756: "User added to universal group",
    4768: "Kerberos ticket requested (TGT)",
    4769: "Kerberos service ticket requested (TGS)",
    4771: "Kerberos pre-authentication failed",
    4776: "NTLM authentication attempt",
    4946: "Firewall rule added",
    7045: "New service installed",
    7040: "Service start type changed",
    4616: "System time changed",
    4697: "Service installed on system",
    4698: "Scheduled task created",
}

# Security-critical event IDs
CRITICAL_EVENT_IDS = {4625, 4648, 4720, 4722, 4724, 4728, 4732, 4756, 4769, 4771, 4776, 4946, 7045}


def _parse_windows_ts(ts_str: str) -> datetime:
    """Parse Windows event log timestamp formats."""
    if not ts_str:
        return datetime.now(timezone.utc)

    ts_str = ts_str.strip().strip('"')

    # Try ISO format first
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return datetime.now(timezone.utc)


def _extract_username(message: str) -> str:
    """Extract username from Windows event message."""
    patterns = [
        r"Account Name:\s+(\S+)",
        r"User Name:\s+(\S+)",
        r"TargetUserName:\s+(\S+)",
        r"Subject:.*Account Name:\s+(\S+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            name = match.group(1).strip()
            if name and name not in ("-", "ANONYMOUS", "LOCAL SERVICE", "NETWORK SERVICE"):
                return name
    return ""


def _extract_ip(message: str) -> str:
    """Extract IP address from Windows event message."""
    match = re.search(
        r"(?:Source Network Address|Client IP|Workstation IP|Address):\s+([\d.]+)",
        message, re.IGNORECASE
    )
    if match:
        ip = match.group(1).strip()
        if ip not in ("-", "::1", "127.0.0.1", "localhost"):
            return ip

    # Fallback: find any IPv4
    match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", message)
    if match:
        ip = match.group(1)
        if ip not in ("0.0.0.0", "127.0.0.1"):
            return ip
    return ""


def _determine_status(event_id: int, message: str) -> str:
    """Determine event status from event ID and message."""
    if event_id in (4625, 4723, 4771, 4776):
        return "FAILURE"
    if event_id in (4624, 4626, 4720, 4722, 4724, 4728, 4732, 4756, 4768, 4769, 4946, 7045):
        return "SUCCESS"
    if "fail" in message.lower() or "error" in message.lower():
        return "FAILURE"
    return "UNKNOWN"


def _determine_action(event_id: int) -> str:
    """Map event ID to action string."""
    return EVENT_DESCRIPTIONS.get(event_id, f"Event_{event_id}")


def parse_event_line(line: str) -> Optional[dict]:
    """Parse a single Windows event log line (JSON or CSV format)."""
    line = line.strip()
    if not line:
        return None

    # Try JSON first
    if line.startswith("{"):
        try:
            data = json.loads(line)
            event_id = int(data.get("EventID", data.get("EventID", 0)))
            ts_str = data.get("TimeCreated", data.get("Timestamp", data.get("Date", "")))
            message = data.get("Message", data.get("Description", ""))

            return {
                "timestamp": _parse_windows_ts(ts_str),
                "event_id": event_id,
                "source": data.get("Provider", data.get("Source", "")),
                "username": _extract_username(message),
                "computer": data.get("Computer", ""),
                "src_ip": _extract_ip(message),
                "action": _determine_action(event_id),
                "status": _determine_status(event_id, message),
                "message": message,
                "raw": line[:500],
            }
        except (json.JSONDecodeError, ValueError):
            pass

    # Try CSV format: EventID,TimeCreated,Source,User,Computer,Message
    try:
        reader = csv.reader([line])
        fields = next(reader)
        if len(fields) >= 2:
            try:
                event_id = int(fields[0].strip())
                ts_str = fields[1].strip()
                source = fields[2].strip() if len(fields) > 2 else ""
                user = fields[3].strip() if len(fields) > 3 else ""
                computer = fields[4].strip() if len(fields) > 4 else ""
                message = fields[5].strip() if len(fields) > 5 else ""

                return {
                    "timestamp": _parse_windows_ts(ts_str),
                    "event_id": event_id,
                    "source": source,
                    "username": user or _extract_username(message),
                    "computer": computer,
                    "src_ip": _extract_ip(message),
                    "action": _determine_action(event_id),
                    "status": _determine_status(event_id, message),
                    "message": message,
                    "raw": line[:500],
                }
            except (ValueError, IndexError):
                pass
    except Exception:
        pass

    return None


def parse_windows_file(filepath: str, from_lines: list = None) -> Generator[dict, None, None]:
    """Parse a Windows Event Log file (JSON or CSV)."""
    if from_lines is not None:
        for line in from_lines:
            parsed = parse_event_line(line)
            if parsed:
                yield parsed
        return

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        # Check if it's a JSON array
        first_char = f.read(1)
        f.seek(0)

        if first_char == "[":
            # JSON array
            try:
                data = json.load(f)
                for entry in data:
                    event_id = int(entry.get("EventID", entry.get("EventId", 0)))
                    ts_str = entry.get("TimeCreated", entry.get("Timestamp", entry.get("Date", "")))
                    message = entry.get("Message", entry.get("Description", ""))

                    yield {
                        "timestamp": _parse_windows_ts(ts_str),
                        "event_id": event_id,
                        "source": entry.get("Provider", entry.get("Source", "")),
                        "username": _extract_username(message),
                        "computer": entry.get("Computer", ""),
                        "src_ip": _extract_ip(message),
                        "action": _determine_action(event_id),
                        "status": _determine_status(event_id, message),
                        "message": message,
                        "raw": str(entry)[:500],
                    }
            except (json.JSONDecodeError, ValueError):
                # Fall through to line-by-line
                f.seek(0)

        # Line-by-line parsing
        for line in f:
            parsed = parse_event_line(line)
            if parsed:
                yield parsed
