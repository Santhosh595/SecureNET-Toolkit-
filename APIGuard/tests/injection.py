"""APIGuard — Bonus injection tests (SQLi, XSS, Path Traversal, NoSQL)."""
from __future__ import annotations
import json
import re
import time
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "INJECTION"
CWE = "CWE-89"

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    string_params = _find_string_params(endpoints)
    if not string_params:
        return findings
    seen = set()
    for ep, param in string_params[:10]:
        path = ep.get("path","")
        method = ep.get("method","GET")
        uid = f"{method}:{path}:{param}"
        if uid in seen:
            continue
        seen.add(uid)
        # Phase 1: single char probes (safe)
        single_probes = ["'", "\"", ";", "\\"]
        for probe in single_probes:
            resp = requester.request(method, path, params={param: probe})
            if resp is None:
                continue
            code = resp.status_code
            body = (resp.content or b"").decode(errors="replace")
            if code == 500:
                # SQL error likely
                findings.append({
                    "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                    "test_name": f"SQL injection (single quote probe on {param})",
                    "severity": "CRITICAL" if re.search(r"sql|syntax|unclosed|mysql|postgresql|ora-", body, re.I) else "HIGH",
                    "evidence": f"Single quote probe ({probe}) on param {param} → 500",
                    "request_sent": f"{method} {path}?{param}={probe}",
                    "response_received": f"HTTP {code}",
                    "remediation": "Use parameterized queries. Never concatenate user input into SQL.",
                    "cvss_score": 9.8,
                    "cwe_ref": CWE,
                })
                break  # Stop probing this endpoint after 500
        # Phase 2: XSS probes
        xss_probes = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
        for xss in xss_probes:
            resp = requester.request(method, path, params={param: xss})
            if resp and xss in (resp.content or b"").decode(errors="replace"):
                findings.append({
                    "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                    "test_name": f"XSS reflection on {param}",
                    "severity": "HIGH",
                    "evidence": f"XSS payload reflected unescaped in response",
                    "request_sent": f"{method} {path}?{param}={xss}",
                    "response_received": "Payload visible in response body",
                    "remediation": "HTML-encode all user inputs before reflecting them. Use Content-Security-Policy headers.",
                    "cvss_score": 7.5,
                    "cwe_ref": "CWE-79",
                })
                break
        # Phase 3: Path traversal
        traversal_probes = ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "..\\..\\..\\windows\\win.ini"]
        for trav in traversal_probes:
            resp = requester.request(method, path, params={param: trav})
            if resp:
                body = (resp.content or b"").decode(errors="replace")
                if "root:x:" in body or "[extensions]" in body.lower() or "boot loader" in body.lower():
                    findings.append({
                        "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                        "test_name": f"Path traversal on {param}",
                        "severity": "CRITICAL",
                        "evidence": f"File contents returned via {param}={trav}",
                        "request_sent": f"{method} {path}?{param}={trav}",
                        "response_received": "System file contents in response",
                        "remediation": "Validate file paths. Use allowlist of allowed filenames. Do not accept user input for file paths.",
                        "cvss_score": 9.8,
                        "cwe_ref": "CWE-22",
                    })
                    break
        # Phase 4: NoSQL injection
        nosql_probes = [json.dumps({"$gt": ""}), json.dumps({"$ne": None})]
        for nosql in nosql_probes:
            resp = requester.request(method, path, params={param: nosql})
            if resp and resp.status_code == 200:
                # Check if response contains unexpected data
                findings.append({
                    "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                    "test_name": f"Potential NoSQL injection on {param}",
                    "severity": "HIGH",
                    "evidence": f"NoSQL operator {nosql} → 200 (unexpected success)",
                    "request_sent": f"{method} {path}?{param}={nosql}",
                    "response_received": f"HTTP 200",
                    "remediation": "Sanitize JSON inputs. Use parameterized queries for NoSQL databases.",
                    "cvss_score": 7.5,
                    "cwe_ref": "CWE-943",
                })
                break
    return findings

def _find_string_params(endpoints: List[Dict]) -> List[tuple]:
    """Find endpoints with string query parameters worth testing."""
    params: List[tuple] = []
    for ep in endpoints:
        path = ep.get("path","")
        pars = ep.get("parameters","")
        method = ep.get("method","GET")
        if pars:
            for p in pars.split(","):
                p = p.strip()
                if p and p not in ("id","ID","Id","limit","offset","page","count","sort","order"):
                    params.append((ep, p))
        # Also try common params even if not in spec
        if not pars:
            for common in ["q", "query", "name", "email", "search", "filter", "where", "value"]:
                params.append((ep, common))
    return params
