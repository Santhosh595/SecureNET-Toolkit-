"""APIGuard — API10:2023 Unsafe Consumption of APIs."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "API10"
CWE = "CWE-20"

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    # Look for webhook/callback/redirect params
    hook_eps = [e for e in endpoints if any(k in e.get("path","").lower() for k in ["webhook","callback","redirect","proxy","fetch","notify"])]
    for ep in hook_eps[:5]:
        path = ep.get("path","")
        # Injection test in webhook data
        payloads = [
            {"url":"javascript:alert(1)","event":"<script>alert(1)</script>"},
            {"payload":"'; DROP TABLE users; --","callback":"data:text/html,<script>alert(1)</script>"},
        ]
        for payload in payloads:
            resp = requester.request("POST", path, json=payload)
            if resp is None:
                continue
            body = (resp.content or b"").decode(errors="replace")
            if "<script>" in body or "alert(1)" in body:
                findings.append({
                    "owasp_category": OWASP_CAT, "endpoint": path, "method": "POST",
                    "test_name": "Injection via webhook data",
                    "severity": "HIGH",
                    "evidence": "Webhook payload reflected or executed in response",
                    "request_sent": f"POST {path} [injection payload]",
                    "response_received": body[:150],
                    "remediation": "Sanitize webhook/callback data before processing. Do not trust third-party data.",
                    "cvss_score": 7.5, "cwe_ref": CWE,
                })
                break
        # Also just flag for manual review
        findings.append({
            "owasp_category": OWASP_CAT, "endpoint": path, "method": ep.get("method","POST"),
            "test_name": "Manual review recommended (API consumption)",
            "severity": "LOW",
            "evidence": "Webhook/callback endpoint detected — requires manual review",
            "request_sent": f"Detected: {path}",
            "response_received": "Automated testing limited — see OWASP API10 notes",
            "remediation": "Sanitize all third-party data. Validate webhook payloads. Do not blindly trust integrated API responses.",
            "cvss_score": 2.5, "cwe_ref": CWE,
        })
    return findings
