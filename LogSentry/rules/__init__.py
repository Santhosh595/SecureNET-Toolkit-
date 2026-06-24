"""
LogSentry Detection Rules
All 15 rules for SOC-level threat detection.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any


class DetectionRule:
    """Base class for detection rules."""

    def __init__(self, name: str, severity: str, mitre_id: str, description: str):
        self.name = name
        self.severity = severity
        self.mitre_id = mitre_id
        self.description = description
        self.enabled = True

    def check(self, events: list) -> list:
        """Run the rule against events. Return list of alerts."""
        raise NotImplementedError

    def _make_alert(self, src_ip: str, username: str, timestamp, details: str) -> dict:
        return {
            "rule_name": self.name,
            "severity": self.severity,
            "mitre_id": self.mitre_id,
            "src_ip": src_ip,
            "username": username,
            "timestamp": timestamp if isinstance(timestamp, str) else timestamp.isoformat(),
            "details": details,
        }


# ═══════════════════════════════════════════════════════════════
# Rule 1: SSH Brute Force
# ═══════════════════════════════════════════════════════════════

class Rule01_SSHBruteForce(DetectionRule):
    """5+ failed SSH logins from same IP within 60 seconds."""

    def __init__(self, threshold: int = 5, time_window: int = 60):
        super().__init__(
            name="SSH Brute Force",
            severity="HIGH",
            mitre_id="T1110.001",
            description="Multiple failed SSH login attempts from single IP"
        )
        self.threshold = threshold
        self.time_window = time_window

    def check(self, events: list) -> list:
        # Group failed SSH events by IP
        failed_by_ip = defaultdict(list)
        for event in events:
            if event.get("log_type") == "linux_auth" and event.get("status") == "FAILURE":
                ip = event.get("src_ip", "")
                if ip and ("ssh" in event.get("action", "") or "pam" in event.get("action", "")):
                    failed_by_ip[ip].append(event)

        alerts = []
        for ip, ip_events in failed_by_ip.items():
            ip_events.sort(key=lambda e: e.get("timestamp", ""))
            for i, event in enumerate(ip_events):
                window_start = event["timestamp"]
                count = 0
                for j in range(i, len(ip_events)):
                    diff = (ip_events[j]["timestamp"] - window_start).total_seconds()
                    if diff <= self.time_window:
                        count += 1
                    else:
                        break
                if count >= self.threshold:
                    username = event.get("username", "")
                    alerts.append(self._make_alert(
                        src_ip=ip,
                        username=username,
                        timestamp=event["timestamp"],
                        details=f"{count} failed SSH attempts in {self.time_window}s from {ip}"
                    ))
                    break  # One alert per IP

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 2: SSH Successful After Failures
# ═══════════════════════════════════════════════════════════════

class Rule02_SSHSuccessAfterFail(DetectionRule):
    """Successful SSH login from IP that had 3+ failures."""

    def __init__(self, failure_threshold: int = 3):
        super().__init__(
            name="SSH Success After Failures",
            severity="CRITICAL",
            mitre_id="T1078",
            description="Successful login after multiple failed attempts"
        )
        self.failure_threshold = failure_threshold

    def check(self, events: list) -> list:
        failed_ips = set()
        alerts = []

        # Find IPs with enough failures
        failure_counts = defaultdict(int)
        for event in events:
            if event.get("log_type") == "linux_auth" and event.get("status") == "FAILURE":
                ip = event.get("src_ip", "")
                if ip and "ssh" in event.get("action", ""):
                    failure_counts[ip] += 1

        for ip, count in failure_counts.items():
            if count >= self.failure_threshold:
                failed_ips.add(ip)

        # Check for successful logins from those IPs
        for event in events:
            if event.get("log_type") == "linux_auth" and event.get("status") == "SUCCESS":
                ip = event.get("src_ip", "")
                if ip in failed_ips:
                    alerts.append(self._make_alert(
                        src_ip=ip,
                        username=event.get("username", ""),
                        timestamp=event["timestamp"],
                        details=f"Successful SSH login from {ip} after {failure_counts[ip]} failures"
                    ))
                    failed_ips.discard(ip)  # One alert

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 3: Multiple Account Brute Force (Credential Stuffing)
# ═══════════════════════════════════════════════════════════════

class Rule03_MultiAccountBruteForce(DetectionRule):
    """Same IP attempting login to 5+ different usernames."""

    def __init__(self, threshold: int = 5):
        super().__init__(
            name="Credential Stuffing",
            severity="HIGH",
            mitre_id="T1110.003",
            description="Login attempts against multiple accounts from single IP"
        )
        self.threshold = threshold

    def check(self, events: list) -> list:
        usernames_by_ip = defaultdict(set)
        timestamps_by_ip = {}

        for event in events:
            if event.get("log_type") == "linux_auth" and event.get("status") == "FAILURE":
                ip = event.get("src_ip", "")
                username = event.get("username", "")
                if ip and username:
                    usernames_by_ip[ip].add(username)
                    if ip not in timestamps_by_ip:
                        timestamps_by_ip[ip] = event["timestamp"]

        alerts = []
        for ip, usernames in usernames_by_ip.items():
            if len(usernames) >= self.threshold:
                alerts.append(self._make_alert(
                    src_ip=ip,
                    username="",
                    timestamp=timestamps_by_ip.get(ip, datetime.now(timezone.utc)),
                    details=f"Login attempts against {len(usernames)} different accounts from {ip}: {', '.join(list(usernames)[:5])}"
                ))

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 4: Off-Hours Login
# ═══════════════════════════════════════════════════════════════

class Rule04_OffHoursLogin(DetectionRule):
    """Successful login between 11PM - 6AM."""

    def __init__(self, start_hour: int = 23, end_hour: int = 6):
        super().__init__(
            name="Off-Hours Login",
            severity="MEDIUM",
            mitre_id="T1078",
            description="Login activity outside business hours"
        )
        self.start_hour = start_hour
        self.end_hour = end_hour

    def check(self, events: list) -> list:
        alerts = []
        seen = set()

        for event in events:
            if event.get("status") != "SUCCESS":
                continue
            if event.get("log_type") not in ("linux_auth", "windows_event"):
                continue

            ts = event.get("timestamp")
            if not isinstance(ts, datetime):
                continue

            hour = ts.hour
            if self.start_hour <= hour or hour < self.end_hour:
                ip = event.get("src_ip", "")
                key = (ip, ts.strftime("%Y-%m-%d %H"))
                if key not in seen:
                    seen.add(key)
                    alerts.append(self._make_alert(
                        src_ip=ip,
                        username=event.get("username", ""),
                        timestamp=ts,
                        details=f"Login at {ts.strftime('%H:%M')} (off-hours) from {ip}"
                    ))

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 5: Root Login Attempt
# ═══════════════════════════════════════════════════════════════

class Rule05_RootLogin(DetectionRule):
    """Any direct root login attempt via SSH."""

    def __init__(self):
        super().__init__(
            name="Root Login Attempt",
            severity="HIGH",
            mitre_id="T1078.003",
            description="Direct root login attempt via SSH"
        )

    def check(self, events: list) -> list:
        alerts = []
        seen_ips = set()

        for event in events:
            if event.get("log_type") != "linux_auth":
                continue
            if event.get("src_ip", "") in seen_ips:
                continue

            username = event.get("username", "").lower()
            action = event.get("action", "")
            raw = event.get("raw", "").lower()

            if username == "root" or "root" in raw:
                if "ssh" in action or "pam" in action or "root" in raw:
                    seen_ips.add(event.get("src_ip", ""))
                    alerts.append(self._make_alert(
                        src_ip=event.get("src_ip", ""),
                        username="root",
                        timestamp=event["timestamp"],
                        details=f"Direct root login attempt from {event.get('src_ip', '')} — {'SUCCESS' if event.get('status') == 'SUCCESS' else 'FAILED'}"
                    ))

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 6: Web Scanner Detection
# ═══════════════════════════════════════════════════════════════

class Rule06_WebScanner(DetectionRule):
    """User agent matching known scanner signatures."""

    def __init__(self):
        super().__init__(
            name="Web Scanner Detection",
            severity="MEDIUM",
            mitre_id="T1595",
            description="User agent matching known scanner signatures"
        )

    SCANNER_SIGNATURES = [
        "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
        "gobuster", "burpsuite", "nessus", "openvas", "zgrab",
        "wfuzz", "arachni", "skipfish", "w3af", "acunetix",
        "netsparker", "appscan", "inspect", "scanbot"
    ]

    def check(self, events: list) -> list:
        alerts = []
        seen_ips = set()

        for event in events:
            if event.get("log_type") not in ("web_access", "web_error"):
                continue

            # Check user_agent in raw log
            raw = event.get("raw", "").lower()
            ua = ""
            # Extract user agent from raw
            ua_match = None
            for sig in self.SCANNER_SIGNATURES:
                if sig in raw:
                    ua_match = sig
                    break

            if ua_match:
                ip = event.get("src_ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    alerts.append(self._make_alert(
                        src_ip=ip,
                        username="",
                        timestamp=event["timestamp"],
                        details=f"Web scanner detected: {ua_match} from {ip}"
                    ))

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 7: Directory Traversal Attempt
# ═══════════════════════════════════════════════════════════════

class Rule07_DirectoryTraversal(DetectionRule):
    """HTTP request containing path traversal patterns."""

    def __init__(self):
        super().__init__(
            name="Directory Traversal",
            severity="HIGH",
            mitre_id="T1083",
            description="HTTP request containing path traversal patterns"
        )

    TRAVERSAL_PATTERNS = [
        "../", "..\\", "%2e%2e", "%252e", "....//",
        "%2e%2e%2f", "..%2f", "%2e%2e/", "/../",
        "..../", "%c0%af", "%c1%9c"
    ]

    def check(self, events: list) -> list:
        alerts = []
        seen_requests = set()

        for event in events:
            if event.get("log_type") not in ("web_access", "web_error"):
                continue

            raw = event.get("raw", "")
            path = ""
            # Try to extract path from raw
            parts = raw.split('"')
            if len(parts) >= 2:
                request = parts[1]  # "GET /path HTTP/1.1"
                path_parts = request.split(" ")
                if len(path_parts) >= 2:
                    path = path_parts[1]

            if not path:
                path = raw

            path_lower = path.lower()
            for pattern in self.TRAVERSAL_PATTERNS:
                if pattern.lower() in path_lower:
                    ip = event.get("src_ip", "")
                    req_key = (ip, pattern)
                    if req_key not in seen_requests:
                        seen_requests.add(req_key)
                        alerts.append(self._make_alert(
                            src_ip=ip,
                            username="",
                            timestamp=event["timestamp"],
                            details=f"Directory traversal attempt: {pattern} from {ip}"
                        ))
                    break

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 8: SQL Injection Attempt
# ═══════════════════════════════════════════════════════════════

class Rule08_SQLInjection(DetectionRule):
    """HTTP request containing SQL injection patterns."""

    def __init__(self):
        super().__init__(
            name="SQL Injection",
            severity="HIGH",
            mitre_id="T1190",
            description="HTTP request containing SQL injection patterns"
        )

    SQLI_PATTERNS = [
        "union+select", "union%20select", "union all select",
        "1=1", "' or '1'='1", "\" or \"1\"=\"1",
        "or+1=1", "or%201=1", "' or 1=1--",
        "drop+table", "drop%20table",
        "exec(", "xp_cmdshell", "exec%28",
        "information_schema", "information%20schema",
        "waitfor+delay", "benchmark(",
        "'; shutdown--", "'; drop table",
        "1'; --", "' UNION SELECT",
        "extractvalue(", "updatexml(",
        "load_file(", "into outfile",
    ]

    def check(self, events: list) -> list:
        alerts = []
        seen_requests = set()

        for event in events:
            if event.get("log_type") not in ("web_access", "web_error"):
                continue

            raw = event.get("raw", "").lower()
            # Extract path and query string
            path = raw
            parts = raw.split('"')
            if len(parts) >= 2:
                request = parts[1]
                path_parts = request.split(" ")
                if len(path_parts) >= 2:
                    path = path_parts[1]

            for pattern in self.SQLI_PATTERNS:
                if pattern.lower() in path:
                    ip = event.get("src_ip", "")
                    req_key = (ip, pattern[:20])
                    if req_key not in seen_requests:
                        seen_requests.add(req_key)
                        alerts.append(self._make_alert(
                            src_ip=ip,
                            username="",
                            timestamp=event["timestamp"],
                            details=f"SQL injection attempt: {pattern} from {ip}"
                        ))
                    break

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 9: XSS Attempt
# ═══════════════════════════════════════════════════════════════

class Rule09_XSSAttempt(DetectionRule):
    """HTTP request containing XSS patterns."""

    def __init__(self):
        super().__init__(
            name="XSS Attempt",
            severity="MEDIUM",
            mitre_id="T1059.007",
            description="HTTP request containing XSS patterns"
        )

    XSS_PATTERNS = [
        "<script", "javascript:", "onerror=", "onload=",
        "alert(", "document.cookie", "eval(", "fromcharcode",
        "onmouseover=", "onfocus=", "onclick=",
        "<img src=x", "<svg/onload", "<body onload",
        "prompt(", "confirm(", "expression(",
    ]

    def check(self, events: list) -> list:
        alerts = []
        seen_requests = set()

        for event in events:
            if event.get("log_type") not in ("web_access", "web_error"):
                continue

            raw = event.get("raw", "").lower()
            # Extract path/query
            path = raw
            parts = raw.split('"')
            if len(parts) >= 2:
                request = parts[1]
                path_parts = request.split(" ")
                if len(path_parts) >= 2:
                    path = path_parts[1]

            for pattern in self.XSS_PATTERNS:
                if pattern.lower() in path:
                    ip = event.get("src_ip", "")
                    req_key = (ip, pattern[:20])
                    if req_key not in seen_requests:
                        seen_requests.add(req_key)
                        alerts.append(self._make_alert(
                            src_ip=ip,
                            username="",
                            timestamp=event["timestamp"],
                            details=f"XSS attempt: {pattern} from {ip}"
                        ))
                    break

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 10: Port Scan from Firewall Logs
# ═══════════════════════════════════════════════════════════════

class Rule10_PortScan(DetectionRule):
    """Same IP hitting 10+ different ports within 30 seconds."""

    def __init__(self, port_threshold: int = 10, time_window: int = 30):
        super().__init__(
            name="Port Scan Detected",
            severity="HIGH",
            mitre_id="T1046",
            description="Multiple port access attempts from single IP"
        )
        self.port_threshold = port_threshold
        self.time_window = time_window

    def check(self, events: list) -> list:
        # Group firewall events by IP
        ports_by_ip = defaultdict(list)
        for event in events:
            if event.get("log_type") != "firewall":
                continue
            ip = event.get("src_ip", "")
            dst_port = event.get("dst_port", 0)
            if ip and dst_port:
                ports_by_ip[ip].append((event["timestamp"], dst_port))

        alerts = []
        for ip, port_events in ports_by_ip.items():
            port_events.sort(key=lambda x: x[0])
            # Sliding window
            for i in range(len(port_events)):
                window_ports = set()
                window_ports.add(port_events[i][1])
                for j in range(i + 1, len(port_events)):
                    diff = (port_events[j][0] - port_events[i][0]).total_seconds()
                    if diff <= self.time_window:
                        window_ports.add(port_events[j][1])
                    else:
                        break
                if len(window_ports) >= self.port_threshold:
                    alerts.append(self._make_alert(
                        src_ip=ip,
                        username="",
                        timestamp=port_events[i][0],
                        details=f"Port scan: {len(window_ports)} unique ports in {self.time_window}s from {ip}"
                    ))
                    break  # One alert per IP

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 11: Privilege Escalation (Windows)
# ═══════════════════════════════════════════════════════════════

class Rule11_PrivilegeEscalation(DetectionRule):
    """EventID 4728/4732/4756 — user added to admin group."""

    def __init__(self):
        super().__init__(
            name="Privilege Escalation (Windows)",
            severity="CRITICAL",
            mitre_id="T1078.002",
            description="User added to privileged group via Windows Event Log"
        )

    PRIV_ESC_EVENTS = {4728, 4732, 4756}

    def check(self, events: list) -> list:
        alerts = []

        for event in events:
            if event.get("log_type") != "windows_event":
                continue

            event_id = event.get("event_id", 0)
            if event_id in self.PRIV_ESC_EVENTS:
                alerts.append(self._make_alert(
                    src_ip=event.get("src_ip", ""),
                    username=event.get("username", ""),
                    timestamp=event["timestamp"],
                    details=f"Privilege escalation: EventID {event_id} — {event.get('action', '')}"
                ))

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 12: New Service Installation (Windows)
# ═══════════════════════════════════════════════════════════════

class Rule12_NewServiceInstalled(DetectionRule):
    """EventID 7045 — new service installed."""

    def __init__(self):
        super().__init__(
            name="New Service Installed",
            severity="HIGH",
            mitre_id="T1543.003",
            description="New service installed via Windows Event Log"
        )

    def check(self, events: list) -> list:
        alerts = []

        for event in events:
            if event.get("log_type") != "windows_event":
                continue

            event_id = event.get("event_id", 0)
            if event_id == 7045:
                alerts.append(self._make_alert(
                    src_ip=event.get("src_ip", ""),
                    username=event.get("username", ""),
                    timestamp=event["timestamp"],
                    details=f"New service installed: {event.get('message', 'EventID 7045')[:100]}"
                ))

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 13: Repeated 403/401 Responses
# ═══════════════════════════════════════════════════════════════

class Rule13_Repeated403(DetectionRule):
    """Same IP receiving 20+ 403 or 401 responses in 5 minutes."""

    def __init__(self, threshold: int = 20, time_window: int = 300):
        super().__init__(
            name="Repeated 403/401 Responses",
            severity="MEDIUM",
            mitre_id="T1110",
            description="Excessive forbidden/unauthorized responses from single IP"
        )
        self.threshold = threshold
        self.time_window = time_window

    def check(self, events: list) -> list:
        # Group 403/401 events by IP
        error_events_by_ip = defaultdict(list)
        for event in events:
            if event.get("log_type") not in ("web_access", "web_error"):
                continue

            # Check for 403/401 in raw log
            raw = event.get("raw", "")
            if "403" in raw or "401" in raw:
                ip = event.get("src_ip", "")
                if ip:
                    error_events_by_ip[ip].append(event)

        alerts = []
        for ip, ip_events in error_events_by_ip.items():
            ip_events.sort(key=lambda e: e.get("timestamp", ""))
            for i in range(len(ip_events)):
                count = 0
                for j in range(i, len(ip_events)):
                    diff = (ip_events[j]["timestamp"] - ip_events[i]["timestamp"]).total_seconds()
                    if diff <= self.time_window:
                        count += 1
                    else:
                        break
                if count >= self.threshold:
                    alerts.append(self._make_alert(
                        src_ip=ip,
                        username="",
                        timestamp=ip_events[i]["timestamp"],
                        details=f"{count} forbidden/unauthorized responses in {self.time_window}s from {ip}"
                    ))
                    break

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 14: Large Data Transfer
# ═══════════════════════════════════════════════════════════════

class Rule14_LargeDataTransfer(DetectionRule):
    """Single HTTP response > 10MB (possible data exfiltration)."""

    def __init__(self, size_threshold: int = 10 * 1024 * 1024):
        super().__init__(
            name="Large Data Transfer",
            severity="HIGH",
            mitre_id="T1030",
            description="Unusually large HTTP response size"
        )
        self.size_threshold = size_threshold

    def check(self, events: list) -> list:
        alerts = []

        for event in events:
            if event.get("log_type") != "web_access":
                continue

            # Try to extract size from raw log
            raw = event.get("raw", "")
            size = 0

            # Apache/Nginx: size is the field after status code
            parts = raw.split('"')
            if len(parts) >= 3:
                # After the request line, fields are separated by spaces
                after_request = parts[2].strip().split()
                if len(after_request) >= 2:
                    try:
                        size = int(after_request[1])
                    except ValueError:
                        size = 0

            if size == 0:
                # Try to find size in event
                size = event.get("size", 0)

            if size >= self.size_threshold:
                alerts.append(self._make_alert(
                    src_ip=event.get("src_ip", ""),
                    username="",
                    timestamp=event["timestamp"],
                    details=f"Large response: {size / (1024*1024):.1f}MB from {event.get('src_ip', '')}"
                ))

        return alerts


# ═══════════════════════════════════════════════════════════════
# Rule 15: Geo Anomaly (offline)
# ═══════════════════════════════════════════════════════════════

class Rule15_GeoAnomaly(DetectionRule):
    """IP geolocation — flag if login from country different from baseline."""

    def __init__(self, baseline_days: int = 7):
        super().__init__(
            name="Geographic Anomaly",
            severity="MEDIUM",
            mitre_id="T1078",
            description="Login from unusual geographic location"
        )
        self.baseline_days = baseline_days

    def check(self, events: list) -> list:
        try:
            import geoip2.database
        except ImportError:
            return []  # geoip2 not installed, skip

        geo_db_path = None
        import os
        possible_paths = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "GeoLite2-City.mmdb"),
            "/var/lib/GeoIP/GeoLite2-City.mmdb",
            os.path.expanduser("~/.local/share/GeoIP/GeoLite2-City.mmdb"),
        ]
        for p in possible_paths:
            if os.path.exists(p):
                geo_db_path = p
                break

        if not geo_db_path:
            return []

        try:
            reader = geoip2.database.Reader(geo_db_path)
        except Exception:
            return []

        # Build baseline from successful logins
        baseline_countries = set()
        anomaly_events = []

        for event in events:
            if event.get("status") != "SUCCESS":
                continue
            ip = event.get("src_ip", "")
            if not ip:
                continue

            try:
                response = reader.city(ip)
                country = response.country.iso_code
                if country:
                    baseline_countries.add(country)
            except Exception:
                pass

        # Second pass: flag anomalies
        alerts = []
        seen_ips = set()
        for event in events:
            if event.get("status") != "SUCCESS":
                continue
            ip = event.get("src_ip", "")
            if not ip or ip in seen_ips:
                continue

            try:
                response = reader.city(ip)
                country = response.country.iso_code
                if country and country not in baseline_countries:
                    seen_ips.add(ip)
                    alerts.append(self._make_alert(
                        src_ip=ip,
                        username=event.get("username", ""),
                        timestamp=event["timestamp"],
                        details=f"Login from {country} (not in baseline countries: {', '.join(baseline_countries)})"
                    ))
            except Exception:
                pass

        reader.close()
        return alerts


# ═══════════════════════════════════════════════════════════════
# Export all rules
# ═══════════════════════════════════════════════════════════════

ALL_RULES = [
    Rule01_SSHBruteForce(),
    Rule02_SSHSuccessAfterFail(),
    Rule03_MultiAccountBruteForce(),
    Rule04_OffHoursLogin(),
    Rule05_RootLogin(),
    Rule06_WebScanner(),
    Rule07_DirectoryTraversal(),
    Rule08_SQLInjection(),
    Rule09_XSSAttempt(),
    Rule10_PortScan(),
    Rule11_PrivilegeEscalation(),
    Rule12_NewServiceInstalled(),
    Rule13_Repeated403(),
    Rule14_LargeDataTransfer(),
    Rule15_GeoAnomaly(),
]
