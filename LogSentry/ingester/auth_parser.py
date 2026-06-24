"""
Linux Auth Log Parser
Parses /var/log/auth.log and /var/log/secure format.
Extracts: SSH logins, sudo usage, user creation, PAM failures, su attempts.
"""

import re
import os
from datetime import datetime, timezone
from typing import Generator, Optional


# Auth log patterns
PATTERNS = {
    "ssh_failed": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
        r"(?:Failed password|Failed publickey|Authentication failure)\s+for\s+"
        r"(?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
    ),
    "ssh_accepted": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
        r"(?:Accepted password|Accepted publickey|Accepted keyboard-interactive)\s+for\s+"
        r"(?P<username>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
    ),
    "ssh_disconnect": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
        r"Disconnected from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
    ),
    "sudo_command": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sudo:\s+"
        r"(?P<username>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)"
    ),
    "sudo_auth_failure": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sudo:\s+"
        r"(?P<attempts>\d+)\s+incorrect password attempts?\s+for\s+(?P<username>\S+)"
    ),
    "useradd": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+useradd\[\d+\]:\s+"
        r"new user:\s+name=(?P<username>\S+).*?UID=(?P<uid>\d+)"
    ),
    "usermod": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+usermod\[\d+\]:\s+"
        r"add\s+'(?P<username>\S+)'\s+to\s+group\s+(?P<group>\S+)"
    ),
    "pam_failure": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+.*?"
        r"pam_\w+\S*\s+(?P<service>\S+)\s+\S+:\s+(?:auth|authentication)\s+failure.*?user=(?P<username>\S+)"
    ),
    "su_attempt": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+su\[\d+\]:\s+"
        r"(?:\(\S+\s+to\s+(?P<target_user>\S+)\)|FAILED\s+for\s+(?P<username>\S+))"
    ),
    "ssh_invalid_user": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
        r"(?:Invalid user|Did not receive identification string)\s+(?P<username>\S+)?\s*from\s+(?P<src_ip>\S+)"
    ),
    "ssh_root": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+sshd\[\d+\]:\s+"
        r"(?:Failed password|Accepted password|Accepted publickey)\s+for\s+(?:root|Administrator)\s+"
        r"from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
    ),
    "pam_session": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+.*?"
        r"pam_\w+\S*\((?P<service>\S+):\s*(?P<action>session_open|session_close)\).*?user=(?P<username>\S+)"
    ),
    "generic_auth": re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+"
        r"(?P<service>\S+)\[\d+\]:\s+(?P<message>.+)"
    ),
}

# Syslog timestamp: "Jun 24 14:30:00" — no year, assume current
SYSLOG_TS = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def _parse_syslog_ts(ts_str: str) -> datetime:
    """Parse syslog timestamp (no year) to datetime, assume current year."""
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return now


def parse_line(line: str) -> Optional[dict]:
    """Parse a single auth.log line."""
    line = line.strip()
    if not line:
        return None

    for pattern_name, pattern in PATTERNS.items():
        match = pattern.match(line)
        if match:
            groups = match.groupdict()
            ts = _parse_syslog_ts(groups.get("timestamp", ""))

            result = {
                "timestamp": ts,
                "hostname": groups.get("hostname", ""),
                "service": groups.get("service", "sshd"),
                "src_ip": groups.get("src_ip", ""),
                "src_port": int(groups.get("src_port", 0)),
                "username": groups.get("username", ""),
                "raw": line,
                "_event_type": pattern_name,
            }

            # Determine action and status
            if pattern_name in ("ssh_failed", "sudo_auth_failure", "pam_failure"):
                result["action"] = "auth_failure"
                result["status"] = "FAILURE"
            elif pattern_name in ("ssh_accepted",):
                result["action"] = "ssh_login"
                result["status"] = "SUCCESS"
            elif pattern_name == "ssh_root":
                result["action"] = "root_login"
                result["status"] = "SUCCESS" if "Accepted" in line else "FAILURE"
            elif pattern_name == "sudo_command":
                result["action"] = "sudo_command"
                result["status"] = "SUCCESS"
            elif pattern_name == "useradd":
                result["action"] = "user_created"
                result["status"] = "SUCCESS"
            elif pattern_name == "usermod":
                result["action"] = "group_membership_changed"
                result["status"] = "SUCCESS"
            elif pattern_name == "su_attempt":
                result["action"] = "su_attempt"
                result["status"] = "SUCCESS" if "to" in line else "FAILURE"
            elif pattern_name == "ssh_invalid_user":
                result["action"] = "invalid_user"
                result["status"] = "FAILURE"
            else:
                result["action"] = pattern_name
                result["status"] = "UNKNOWN"

            return result

    # Fallback: extract timestamp and basic info
    ts_match = SYSLOG_TS.match(line)
    if ts_match:
        ts = _parse_syslog_ts(ts_match.group(1))
        return {
            "timestamp": ts,
            "hostname": "",
            "service": "",
            "src_ip": "",
            "src_port": 0,
            "username": "",
            "action": "unknown",
            "status": "UNKNOWN",
            "raw": line,
            "_event_type": "unparsed",
        }

    return None


def parse_auth_file(filepath: str, from_lines: list = None) -> Generator[dict, None, None]:
    """Parse an entire auth.log file, yielding normalized events."""
    if from_lines is not None:
        for line in from_lines:
            parsed = parse_line(line)
            if parsed:
                yield parsed
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed = parse_line(line)
                if parsed:
                    yield parsed
    except (IOError, OSError) as e:
        return
