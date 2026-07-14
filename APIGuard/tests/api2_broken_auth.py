"""APIGuard — API2:2023 Broken Authentication."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from tests import ApiRequester, check_auth_bypass, cvss_for

OWASP_CAT = "API2"
CWE = "CWE-287"

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    for ep in endpoints[:15]:
        path = ep.get("path","")
        method = ep.get("method","GET")
        # 1. Unauthenticated access
        bypass = check_auth_bypass(requester, path, method)
        if bypass:
            findings.append({
                "owasp_category": OWASP_CAT,
                "endpoint": path, "method": method,
                "test_name": "Auth bypass (no token)",
                "severity": "CRITICAL",
                "evidence": bypass["evidence"],
                "request_sent": f"{method} {path} (no auth headers)",
                "response_received": f"HTTP {bypass['status']}",
                "remediation": "Reject unauthenticated requests with 401. Add auth middleware.",
                "cvss_score": 9.8, "cwe_ref": CWE,
            })
        # 2. Empty Bearer token
        resp = requester.request(method, path, headers={"Authorization": "Bearer "})
        if resp and resp.status_code == 200:
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                "test_name": "Empty Bearer token accepted",
                "severity": "HIGH",
                "evidence": f"Auth with empty Bearer token → {resp.status_code}",
                "request_sent": f"{method} {path} [Authorization: Bearer ]",
                "response_received": f"HTTP {resp.status_code}",
                "remediation": "Reject empty Bearer tokens. Validate token format before passing to auth handler.",
                "cvss_score": 7.5, "cwe_ref": CWE,
            })
        # 3. Case sensitivity on auth header
        resp = requester.request(method, path, headers={"authorization": requester.auth.get_headers().get("Authorization","")})
        if resp and resp.status_code == 200:
            # It worked with lowercase — that's fine, just informational
            pass
        # 4. Token in URL parameter
        token = requester.auth.auth_value
        if token:
            resp = requester.request(method, path + f"?token={token}")
            if resp and resp.status_code == 200:
                findings.append({
                    "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                    "test_name": "Token accepted in URL parameter",
                    "severity": "MEDIUM",
                    "evidence": f"?token= in URL → {resp.status_code}",
                    "request_sent": f"{method} {path}?token=[REDACTED]",
                    "response_received": f"HTTP {resp.status_code}",
                    "remediation": "Do not accept authentication tokens via URL parameters (logged in server logs).",
                    "cvss_score": 5.3, "cwe_ref": CWE,
                })
        # 5. Null byte in token
        if token:
            resp = requester.request(method, path, headers={"Authorization": f"Bearer {token}\x00injected"})
            if resp and resp.status_code == 200:
                findings.append({
                    "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                    "test_name": "Null byte in token accepted",
                    "severity": "CRITICAL",
                    "evidence": f"Token with null byte → {resp.status_code}",
                    "request_sent": f"{method} {path} [Authorization: Bearer TOKEN\\\\x00injected]",
                    "response_received": f"HTTP {resp.status_code}",
                    "remediation": "Validate token format strictly. Strip null bytes before processing.",
                    "cvss_score": 9.1, "cwe_ref": CWE,
                })
    return findings
