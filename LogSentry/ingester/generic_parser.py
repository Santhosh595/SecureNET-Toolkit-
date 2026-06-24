"""
Generic Log Parser (JSON/CSV fallback)
Auto-maps common field names to the normalized schema.
"""

import re
import csv
import json
from datetime import datetime, timezone
from typing import Generator, Optional


# Common field name mappings
FIELD_MAPPINGS = {
    "timestamp": ["timestamp", "time", "date", "datetime", "@timestamp", "ts", "event_time", "created_at", "log_time"],
    "src_ip": ["ip", "src_ip", "source_ip", "src", "source", "client_ip", "remote_addr", "remote_ip", "origin_ip"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "dst", "destination", "target_ip"],
    "src_port": ["src_port", "source_port", "sport", "client_port"],
    "dst_port": ["dst_port", "dest_port", "dport", "destination_port", "target_port", "port"],
    "username": ["user", "username", "user_name", "usr", "login", "account", "subject"],
    "action": ["action", "event", "action_type", "event_type", "method", "verb", "operation"],
    "status": ["status", "result", "outcome", "response_code", "state"],
    "hostname": ["host", "hostname", "server", "computer", "device"],
    "message": ["message", "msg", "description", "log", "text", "content"],
}


def _find_field(data: dict, target_field: str) -> Optional[str]:
    """Find a field value in the data using common name mappings."""
    mappings = FIELD_MAPPINGS.get(target_field, [target_field])

    for key in mappings:
        if key in data:
            return str(data[key]) if data[key] is not None else ""
        # Case-insensitive search
        for data_key in data:
            if data_key.lower() == key.lower():
                return str(data_key) if data_key is not None else ""

    return None


def _parse_generic_ts(ts_str: str) -> datetime:
    """Parse various timestamp formats."""
    if not ts_str:
        return datetime.now(timezone.utc)

    ts_str = str(ts_str).strip()

    # Try Unix timestamp
    try:
        ts_float = float(ts_str)
        if ts_float > 1e12:  # milliseconds
            ts_float /= 1000
        return datetime.fromtimestamp(ts_float, tz=timezone.utc)
    except (ValueError, OSError):
        pass

    # Try common formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return datetime.now(timezone.utc)


def _normalize_status(status_val) -> str:
    """Normalize status from various formats."""
    if status_val is None:
        return "UNKNOWN"

    status_str = str(status_val).lower().strip()

    success_terms = ["success", "successful", "ok", "200", "201", "204", "accepted", "granted", "allowed", "true", "1"]
    failure_terms = ["fail", "failed", "failure", "error", "denied", "rejected", "401", "403", "404", "500", "503", "false", "0"]
    blocked_terms = ["block", "blocked", "drop", "dropped", "denied", "rejected"]

    if status_str in blocked_terms:
        return "BLOCKED"
    if status_str in success_terms:
        return "SUCCESS"
    if status_str in failure_terms:
        return "FAILURE"

    # Check numeric codes
    try:
        code = int(status_str)
        if 200 <= code < 300:
            return "SUCCESS"
        elif code in (401, 403, 404, 429, 500, 502, 503):
            return "FAILURE"
    except ValueError:
        pass

    return "UNKNOWN"


def parse_json_line(line: str) -> Optional[dict]:
    """Parse a JSON log line."""
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    ts_str = _find_field(data, "timestamp") or ""
    ts = _parse_generic_ts(ts_str) if ts_str else datetime.now(timezone.utc)

    src_ip = _find_field(data, "src_ip") or ""
    dst_ip = _find_field(data, "dst_ip") or ""
    src_port_str = _find_field(data, "src_port") or "0"
    dst_port_str = _find_field(data, "dst_port") or "0"
    username = _find_field(data, "username") or ""
    action = _find_field(data, "action") or ""
    status_raw = _find_field(data, "status") or ""
    message = _find_field(data, "message") or ""

    try:
        src_port = int(float(src_port_str)) if src_port_str else 0
    except ValueError:
        src_port = 0
    try:
        dst_port = int(float(dst_port_str)) if dst_port_str else 0
    except ValueError:
        dst_port = 0

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "username": username,
        "action": action or "unknown",
        "status": _normalize_status(status_raw),
        "message": message,
        "raw": line[:500],
    }


def parse_csv_file(filepath: str) -> Generator[dict, None, None]:
    """Parse a CSV log file with auto field detection."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        # Detect dialect
        sample = f.read(8192)
        f.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)

        for row in reader:
            if not row:
                continue

            ts_str = _find_field(row, "timestamp") or ""
            ts = _parse_generic_ts(ts_str) if ts_str else datetime.now(timezone.utc)

            src_ip = _find_field(row, "src_ip") or ""
            dst_ip = _find_field(row, "dst_ip") or ""
            src_port_str = _find_field(row, "src_port") or "0"
            dst_port_str = _find_field(row, "dst_port") or "0"
            username = _find_field(row, "username") or ""
            action = _find_field(row, "action") or ""
            status_raw = _find_field(row, "status") or ""

            try:
                src_port = int(float(src_port_str)) if src_port_str else 0
            except ValueError:
                src_port = 0
            try:
                dst_port = int(float(dst_port_str)) if dst_port_str else 0
            except ValueError:
                dst_port = 0

            yield {
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "username": username,
                "action": action or "unknown",
                "status": _normalize_status(status_raw),
                "raw": str(row)[:500],
            }


def parse_generic_file(filepath: str, from_lines: list = None) -> Generator[dict, None, None]:
    """Parse a generic log file (JSON or CSV)."""
    if from_lines is not None:
        for line in from_lines:
            parsed = parse_json_line(line)
            if parsed:
                yield parsed
        return

    # Detect file type from extension
    ext = filepath.lower().split(".")[-1] if "." in filepath else ""

    if ext == "csv":
        yield from parse_csv_file(filepath)
        return

    # Try line-by-line JSON (JSONL format)
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        first_line = f.readline().strip()
        f.seek(0)

        if first_line.startswith("{"):
            # JSONL format
            for line in f:
                parsed = parse_json_line(line)
                if parsed:
                    yield parsed
        elif first_line.startswith("["):
            # JSON array
            try:
                data = json.load(f)
                for entry in data:
                    if isinstance(entry, dict):
                        ts_str = _find_field(entry, "timestamp") or ""
                        ts = _parse_generic_ts(ts_str) if ts_str else datetime.now(timezone.utc)

                        yield {
                            "timestamp": ts,
                            "src_ip": _find_field(entry, "src_ip") or "",
                            "dst_ip": _find_field(entry, "dst_ip") or "",
                            "src_port": int(float(_find_field(entry, "src_port") or "0")),
                            "dst_port": int(float(_find_field(entry, "dst_port") or "0")),
                            "username": _find_field(entry, "username") or "",
                            "action": _find_field(entry, "action") or "unknown",
                            "status": _normalize_status(_find_field(entry, "status")),
                            "raw": str(entry)[:500],
                        }
            except json.JSONDecodeError:
                # Fall through to CSV attempt
                f.seek(0)
                yield from parse_csv_file(filepath)
        else:
            # Try CSV
            yield from parse_csv_file(filepath)
