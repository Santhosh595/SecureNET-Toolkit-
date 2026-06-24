"""
Apache/Nginx Access & Error Log Parser
Supports:
- Combined Log Format (CLF)
- Common Log Format  
- Nginx access log
- Apache/Nginx error log
"""

import re
from datetime import datetime, timezone
from typing import Generator, Optional


# Apache/Nginx Combined Log Format
# 127.0.0.1 - frank [10/Oct/2024:13:55:36 +0000] "GET /api/user HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"
ACCESS_PATTERN = re.compile(
    r'^(?P<src_ip>[\d.]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<auth_user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+|-)\s+'
    r'"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

# Simplified access log (without referrer/user-agent)
SIMPLE_ACCESS = re.compile(
    r'^(?P<src_ip>[\d.]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<auth_user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+|-)'
)

# Apache error log: [Mon Jun 24 14:30:00.123456 2024] [auth_basic:error] [pid 1234] ...
ERROR_PATTERN = re.compile(
    r'^\[(?P<timestamp>[^\]]+)\]\s+'
    r'\[(?P<level>[^\]]+)\]\s+'
    r'(?:\[pid\s+(?P<pid>\d+)\]\s+)?'
    r'(?:\[client\s+(?P<client_ip>[\d.]+)\]\s+)?'
    r'(?P<message>.+)'
)

# Nginx error log: 2024/06/24 14:30:00 [error] 1234#0: *1 ...
NGINX_ERROR_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#\d+:\s+\*\d+\s+(?P<message>.+),?\s+client:\s+(?P<client_ip>[\d.]+)'
)

# Nginx error without client IP
NGINX_ERROR_SIMPLE = re.compile(
    r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#\d+:\s+\*\d+\s+(?P<message>.+)'
)

# Timestamp formats
APACHE_TS = re.compile(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]?\d{4})')


def _parse_apache_ts(ts_str: str) -> datetime:
    """Parse Apache-style timestamp: 10/Oct/2024:13:55:36 +0000."""
    try:
        dt = datetime.strptime(ts_str.strip(), "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    # Without timezone
    try:
        # Extract just the core part
        match = re.match(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', ts_str)
        if match:
            dt = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    return datetime.now(timezone.utc)


def _parse_nginx_ts(ts_str: str) -> datetime:
    """Parse Nginx-style timestamp: 2024/06/24 14:30:00."""
    try:
        dt = datetime.strptime(ts_str.strip(), "%Y/%m/%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _parse_error_ts(ts_str: str) -> datetime:
    """Parse Apache error timestamp: Mon Jun 24 14:30:00.123456 2024."""
    # Remove microseconds
    ts_clean = re.sub(r'\.\d+', '', ts_str.strip())
    try:
        dt = datetime.strptime(ts_clean, "%a %b %d %H:%M:%S %Y")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def parse_access_line(line: str) -> Optional[dict]:
    """Parse a single access log line."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = ACCESS_PATTERN.match(line)
    if not match:
        match = SIMPLE_ACCESS.match(line)

    if match:
        g = match.groupdict()
        ts_str = g.get("timestamp", "")
        ts = _parse_apache_ts(ts_str) if "/" in ts_str and ":" in ts_str else _parse_nginx_ts(ts_str)

        size = g.get("size", "0")
        try:
            size = int(size) if size != "-" else 0
        except ValueError:
            size = 0

        return {
            "timestamp": ts,
            "src_ip": g.get("src_ip", ""),
            "username": g.get("auth_user", "") if g.get("auth_user", "") != "-" else "",
            "method": g.get("method", ""),
            "path": g.get("path", ""),
            "status_code": int(g.get("status", 0)),
            "size": size,
            "referrer": g.get("referrer", ""),
            "user_agent": g.get("user_agent", ""),
            "action": "http_request",
            "status": "SUCCESS",
            "raw": line,
        }

    return None


def parse_error_line(line: str) -> Optional[dict]:
    """Parse a single error log line."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Try Apache error format
    match = ERROR_PATTERN.match(line)
    if match:
        g = match.groupdict()
        ts = _parse_error_ts(g.get("timestamp", ""))
        return {
            "timestamp": ts,
            "src_ip": g.get("client_ip", ""),
            "level": g.get("level", ""),
            "pid": g.get("pid", ""),
            "message": g.get("message", ""),
            "action": "error_log",
            "status": "FAILURE" if "error" in g.get("level", "").lower() else "UNKNOWN",
            "raw": line,
        }

    # Try Nginx error format
    match = NGINX_ERROR_PATTERN.match(line)
    if not match:
        match = NGINX_ERROR_SIMPLE.match(line)
    if match:
        g = match.groupdict()
        ts = _parse_nginx_ts(g.get("timestamp", ""))
        return {
            "timestamp": ts,
            "src_ip": g.get("client_ip", ""),
            "level": g.get("level", ""),
            "pid": g.get("pid", ""),
            "message": g.get("message", ""),
            "action": "error_log",
            "status": "FAILURE" if "error" in g.get("level", "").lower() else "UNKNOWN",
            "raw": line,
        }

    return None


def parse_access_file(filepath: str, from_lines: list = None) -> Generator[dict, None, None]:
    """Parse an access log file."""
    if from_lines is not None:
        for line in from_lines:
            parsed = parse_access_line(line)
            if parsed:
                yield parsed
        return

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_access_line(line)
            if parsed:
                yield parsed


def parse_error_file(filepath: str, from_lines: list = None) -> Generator[dict, None, None]:
    """Parse an error log file."""
    if from_lines is not None:
        for line in from_lines:
            parsed = parse_error_line(line)
            if parsed:
                yield parsed
        return

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_error_line(line)
            if parsed:
                yield parsed
