"""APIGuard — API4:2023 Unrestricted Resource Consumption."""
from __future__ import annotations
import time
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "API4"
CWE = "CWE-770"

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    if not endpoints:
        return findings
    # Pick first GET endpoint for rate limit testing
    target = None
    for ep in endpoints:
        if ep.get("method") == "GET":
            target = ep
            break
    if not target:
        return findings
    path = target.get("path","/")
    # 1. Rate limit detection — send 20 rapid requests
    rate_limited = False
    has_ratelimit_headers = False
    for _ in range(20):
        resp = requester.get(path)
        if resp is None:
            continue
        if resp.status_code == 429:
            rate_limited = True
        # Check for rate limit headers
        for h in resp.headers:
            if "ratelimit" in h.lower():
                has_ratelimit_headers = True
                break
        if rate_limited:
            break
        time.sleep(0.05)
    if not rate_limited:
        findings.append({
            "owasp_category": OWASP_CAT, "endpoint": path, "method": "GET",
            "test_name": "Rate limiting missing",
            "severity": "MEDIUM",
            "evidence": "20 rapid requests to same endpoint — no 429 received",
            "request_sent": "GET " + path + " (×20 rapid)",
            "response_received": "All 200 — no rate limit enforced",
            "remediation": "Implement rate limiting (e.g., 100 req/min per IP/token). Return 429 with Retry-After header.",
            "cvss_score": 5.3, "cwe_ref": CWE,
        })
    if not has_ratelimit_headers:
        findings.append({
            "owasp_category": OWASP_CAT, "endpoint": path, "method": "GET",
            "test_name": "Rate limit headers absent",
            "severity": "LOW",
            "evidence": "No X-RateLimit-* or Retry-After headers in response",
            "request_sent": f"GET {path}",
            "response_received": "Headers checked: no rate limit info",
            "remediation": "Add X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers.",
            "cvss_score": 2.5, "cwe_ref": CWE,
        })
    # 2. Large payload test
    large_body = "A" * 1024 * 1024  # 1MB
    post_eps = [e for e in endpoints if e.get("method") in ("POST","PUT")]
    for ep in post_eps[:2]:
        p = ep.get("path","")
        resp = requester.request("POST", p, data=large_body)
        if resp and resp.status_code not in (413, 400):
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": p, "method": "POST",
                "test_name": "Large payload not rejected",
                "severity": "MEDIUM",
                "evidence": f"1MB payload → {resp.status_code} (expected 413 Payload Too Large)",
                "request_sent": f"POST {p} [1MB body]",
                "response_received": f"HTTP {resp.status_code}",
                "remediation": "Enforce maximum request body size (e.g., 1MB). Return 413 Payload Too Large.",
                "cvss_score": 5.3, "cwe_ref": CWE,
            })
    # 3. Pagination abuse
    resp = requester.get(path, params={"limit":"99999","offset":"0"})
    if resp and resp.status_code == 200:
        size = len(resp.content) if resp.content else 0
        if size > 50000:
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": path, "method": "GET",
                "test_name": "Pagination abuse possible",
                "severity": "MEDIUM",
                "evidence": f"limit=99999 returned {size} bytes",
                "request_sent": f"GET {path}?limit=99999&offset=0",
                "response_received": f"HTTP 200, size={size}",
                "remediation": "Enforce maximum page size (e.g., limit=100). Paginate large result sets.",
                "cvss_score": 5.3, "cwe_ref": CWE,
            })
    return findings
