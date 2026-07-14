"""APIGuard — Response analysis engine.

For every test response, analyze: status code, timing, content-type,
body size, sensitive fields, error messages, input reflection, headers.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

# Sensitive field patterns (JSON keys that indicate data leaks)
_SENSITIVE_FIELDS: Set[str] = {
    "password", "password_hash", "passwd", "secret", "private_key",
    "ssn", "credit_card", "cc_number", "cvv", "card_number",
    "internal_id", "admin_flag", "is_admin", "role", "roles",
    "permissions", "token", "api_key", "apikey", "api_secret",
    "access_token", "refresh_token", "bearer", "auth_token",
    "session_token", "csrf_token", "xsrf_token",
    "phone", "phone_number", "mobile",
    "dob", "date_of_birth", "birth_date",
}

# SQL error patterns
_SQL_ERRORS: List[str] = [
    "sql syntax", "mysql_fetch", "unclosed quotation mark",
    "odbc_", "sqlite", "postgresql", "ora-", "ora-",
    "driver error", "db2 ", "microsoft ole db",
    "unexpected end of sql", "syntax error",
    "warning: mysql", "warning: sql",
    "division by zero", "pg_query",
]

# Stack trace patterns
_STACK_PATTERNS: List[str] = [
    r"Traceback \(most recent call last\)",
    r"at\s+[\w.]+\([\w./]+:\d+\)",  # Java
    r"in\s+[/\w.]+\s+line\s+\d+",  # Python
    r"Stack trace:",
    r"Exception in thread",
    r"\.\w+Error\b",
    r"\s+at\s+[\w.$]+\.[\w<>]+\([\w./]+:\d+\)",  # Java stack
]


@dataclass
class AnalysisResult:
    findings: List[Dict] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    sensitive_fields_found: List[str] = field(default_factory=list)
    has_stack_trace: bool = False
    has_sql_error: bool = False
    input_reflected: bool = False
    content_type_missing: bool = False
    content_type_wrong: bool = False


class ResponseAnalyzer:
    """Analyze HTTP responses for security issues."""

    def __init__(self) -> None:
        self.baseline = None  # Optional BaselineTracker

    def analyze(
        self,
        status: int,
        headers: Dict[str, str],
        body: str,
        input_sent: str = "",
        expected_status: int = 200,
        baseline_status: Optional[int] = None,
    ) -> AnalysisResult:
        result = AnalysisResult()

        # Content-Type check
        ct = headers.get("Content-Type", headers.get("content-type", "")).lower()
        if not ct:
            result.content_type_missing = True
            result.findings.append({
                "type": "missing-content-type",
                "severity": "LOW",
                "detail": "Response has no Content-Type header",
            })
        elif "json" not in ct and "xml" not in ct and "text" not in ct:
            result.content_type_wrong = True

        # Sensitive fields in JSON
        if "json" in ct:
            fields = self._check_sensitive_fields(body)
            result.sensitive_fields_found = fields
            if fields:
                result.findings.append({
                    "type": "excessive-data",
                    "severity": "HIGH" if any(f in ("password", "ssn", "credit_card", "private_key") for f in fields) else "MEDIUM",
                    "detail": f"Sensitive fields exposed: {', '.join(fields[:5])}",
                })

        # Stack traces
        result.has_stack_trace = self._check_stack_trace(body)
        if result.has_stack_trace:
            result.findings.append({
                "type": "stack-trace",
                "severity": "HIGH",
                "detail": "Stack trace exposed in response body",
            })

        # SQL errors
        result.has_sql_error = self._check_sql_error(body)
        if result.has_sql_error:
            result.findings.append({
                "type": "sql-error",
                "severity": "HIGH",
                "detail": "SQL error message disclosed in response",
            })

        # Input reflection (XSS probe)
        if input_sent and input_sent in body:
            result.input_reflected = True
            # Only flag if it looks like XSS probe
            if "<script" in input_sent.lower() or "alert(" in input_sent.lower():
                result.findings.append({
                    "type": "xss-reflection",
                    "severity": "HIGH",
                    "detail": "XSS payload reflected in response unescaped",
                })

        # Unexpected success (e.g., got 200 when should be 401)
        if baseline_status and status == 200 and baseline_status != 200:
            result.anomalies.append(f"Got 200 when baseline was {baseline_status}")
            result.findings.append({
                "type": "auth-bypass",
                "severity": "CRITICAL",
                "detail": f"Endpoint returned 200 when expected {baseline_status}",
            })

        return result

    def _check_sensitive_fields(self, body: str) -> List[str]:
        """Scan JSON body for sensitive field names."""
        found: List[str] = []
        if not body or not body.strip():
            return found
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            # Regex fallback
            for field in _SENSITIVE_FIELDS:
                pattern = r'"' + re.escape(field) + r'"\s*:'
                if re.search(pattern, body, re.IGNORECASE):
                    found.append(field)
            return found
        # Walk JSON tree
        def _walk(obj, depth=0):
            if depth > 5:
                return
            if isinstance(obj, dict):
                for k in obj:
                    if k.lower() in _SENSITIVE_FIELDS:
                        found.append(k)
                    _walk(obj[k], depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item, depth + 1)
        _walk(data)
        return sorted(set(found))

    def _check_stack_trace(self, body: str) -> bool:
        for pat in _STACK_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                return True
        return False

    def _check_sql_error(self, body: str) -> bool:
        body_lower = body.lower()
        for pat in _SQL_ERRORS:
            if pat.lower() in body_lower:
                return True
        return False
