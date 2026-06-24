"""
LogSentry Normalizer
Maps all parsed log formats into a unified schema.
All timestamps normalized to UTC internally.
"""

from datetime import datetime, timezone
from typing import Optional
import re


NORMALIZED_FIELDS = [
    "timestamp", "source_file", "log_type", "src_ip", "dst_ip",
    "src_port", "dst_port", "username", "action", "status", "raw"
]

LOG_TYPES = {
    "auth": "linux_auth",
    "apache_access": "web_access",
    "apache_error": "web_error",
    "windows": "windows_event",
    "firewall": "firewall",
    "generic": "generic",
}

STATUS_MAP = {
    "success": "SUCCESS",
    "successful": "SUCCESS",
    "accepted": "SUCCESS",
    "granted": "SUCCESS",
    "allowed": "SUCCESS",
    "failure": "FAILURE",
    "failed": "FAILURE",
    "failure": "FAILURE",
    "denied": "FAILURE",
    "rejected": "FAILURE",
    "block": "BLOCKED",
    "blocked": "BLOCKED",
    "drop": "BLOCKED",
    "dropped": "BLOCKED",
}


def normalize_timestamp(ts_str: str, fmt_hint: str = None) -> Optional[datetime]:
    """Parse various timestamp formats to UTC datetime."""
    if not ts_str:
        return None

    ts_str = ts_str.strip().strip("[]")

    formats = [
        "%Y/%b/%d:%H:%M:%S %z",      # Apache: 10/Oct/2024:13:55:36 +0000
        "%Y-%m-%dT%H:%M:%S%z",        # ISO 8601
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%b %d %H:%M:%S",              # Syslog (no year)
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %Y %H:%M:%S",
    ]

    if fmt_hint:
        formats.insert(0, fmt_hint)

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    # Try extracting with regex as fallback
    ts_clean = re.sub(r"\.\d+", "", ts_str)
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_clean, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def normalize_status(status_str: str) -> str:
    """Normalize status string to standard values."""
    if not status_str:
        return "UNKNOWN"
    lower = status_str.lower().strip()
    return STATUS_MAP.get(lower, "UNKNOWN")


def safe_int(value) -> int:
    """Safely convert to int, return 0 on failure."""
    if value is None:
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def normalize_event(parsed: dict, source_file: str, log_type: str) -> Optional[dict]:
    """Map a parsed log entry to the normalized schema."""
    if not parsed:
        return None

    timestamp = normalize_timestamp(
        parsed.get("timestamp", ""),
        parsed.get("_timestamp_fmt")
    )

    if not timestamp:
        timestamp = datetime.now(timezone.utc)

    return {
        "timestamp": timestamp,
        "source_file": source_file,
        "log_type": log_type,
        "src_ip": parsed.get("src_ip", "") or "",
        "dst_ip": parsed.get("dst_ip", "") or "",
        "src_port": safe_int(parsed.get("src_port")),
        "dst_port": safe_int(parsed.get("dst_port")),
        "username": parsed.get("username", "") or "",
        "action": parsed.get("action", "") or "",
        "status": normalize_status(parsed.get("status", "")),
        "raw": parsed.get("raw", "") or "",
    }


def deduplicate_events(events: list, window_seconds: int = 1) -> list:
    """Remove identical events within a time window."""
    if not events:
        return events

    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
    deduped = [sorted_events[0]]

    for event in sorted_events[1:]:
        prev = deduped[-1]
        time_diff = (event["timestamp"] - prev["timestamp"]).total_seconds()

        if time_diff > window_seconds:
            deduped.append(event)
        elif (event.get("src_ip") != prev.get("src_ip") or
              event.get("action") != prev.get("action") or
              event.get("raw") != prev.get("raw")):
            deduped.append(event)

    return deduped
