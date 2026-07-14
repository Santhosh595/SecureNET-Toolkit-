"""APIGuard — API5:2023 Broken Function Level Authorization."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from tests import ApiRequester, check_auth_bypass, cvss_for

OWASP_CAT = "API5"
CWE = "CWE-285"
ADMIN_PATHS = ["/api/admin","/api/internal","/api/manage","/api/debug","/api/management","/api/console"]

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    # Look for admin/internal endpoints
    admin_eps = [e for e in endpoints if any(ap in e.get("path","").lower() for ap in ADMIN_PATHS)]
    # Also try common admin ops
    ops = ["/api/users","/api/users/1","/api/users/1/delete","/api/users/1/role"]
    for path in ops:
        resp = requester.get(path)
        if resp and resp.status_code == 200:
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": path, "method": "GET",
                "test_name": "Admin-level endpoint accessible to regular user",
                "severity": "CRITICAL",
                "evidence": f"{path} returned {resp.status_code}",
                "request_sent": f"GET {path} (regular user token)",
                "response_received": f"HTTP {resp.status_code}",
                "remediation": "Enforce role-based access control. Verify user has admin role before serving admin endpoints.",
                "cvss_score": 9.8, "cwe_ref": CWE,
            })
    # HTTP method override
    for ep in admin_eps[:5]:
        path = ep.get("path","")
        resp = requester.request("GET", path, headers={"X-HTTP-Method-Override": "DELETE"})
        if resp and resp.status_code == 200:
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": path, "method": "GET",
                "test_name": "HTTP method override accepted",
                "severity": "HIGH",
                "evidence": f"X-HTTP-Method-Override: DELETE on GET → {resp.status_code}",
                "request_sent": f"GET {path} [X-HTTP-Method-Override: DELETE]",
                "response_received": f"HTTP {resp.status_code}",
                "remediation": "Disable X-HTTP-Method-Override header. Route requests by actual HTTP method.",
                "cvss_score": 7.5, "cwe_ref": CWE,
            })
    return findings
