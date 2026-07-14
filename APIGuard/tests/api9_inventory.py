"""APIGuard — API9:2023 Improper Inventory Management."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "API9"
CWE = "CWE-1104"
ENV_PATHS = ["/api-staging","/api-dev","/api-test","/api-v1","/api-old","/api-deprecated","/api/legacy","/api/beta","/api/experimental","/api/sandbox"]

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    # 1. Version enumeration
    versions_found = set()
    for ep in endpoints:
        path = ep.get("path","")
        for ver in ["/v1","/v2","/v3","/v4"]:
            if ver in path:
                versions_found.add(ver)
    if len(versions_found) > 1:
        # Multiple versions accessible
        findings.append({
            "owasp_category": OWASP_CAT, "endpoint": ", ".join(sorted(versions_found)),
            "method": "GET",
            "test_name": "Multiple API versions accessible",
            "severity": "MEDIUM",
            "evidence": f"Versions found: {', '.join(sorted(versions_found))}",
            "request_sent": "API version enumeration",
            "response_received": f"Active versions: {', '.join(sorted(versions_found))}",
            "remediation": "Deprecate and remove old API versions. If needed, apply same security controls to all versions.",
            "cvss_score": 5.3, "cwe_ref": CWE,
        })
    # 2. Shadow APIs (endpoints not in spec)
    if hasattr(requester, '_spec_endpoints'):
        spec_paths = set(requester._spec_endpoints)
        discovered_paths = {e.get("path","") for e in endpoints}
        shadow = discovered_paths - spec_paths
        if shadow:
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": list(shadow)[:5],
                "method": "GET",
                "test_name": "Shadow API endpoints detected",
                "severity": "HIGH",
                "evidence": f"Endpoints not in spec: {', '.join(list(shadow)[:5])}",
                "request_sent": "Endpoint discovery",
                "response_received": f"{len(shadow)} undocumented endpoints",
                "remediation": "Document all API endpoints. Audit undocumented endpoints for security controls.",
                "cvss_score": 7.5, "cwe_ref": CWE,
            })
    # 3. Environment exposure
    for env_path in ENV_PATHS:
        resp = requester.get(env_path)
        if resp and resp.status_code in (200, 401, 403):
            # Accessible (even if auth required)
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": env_path, "method": "GET",
                "test_name": "Non-production environment exposed",
                "severity": "HIGH" if resp.status_code == 200 else "MEDIUM",
                "evidence": f"GET {env_path} → {resp.status_code}",
                "request_sent": f"GET {env_path}",
                "response_received": f"HTTP {resp.status_code}",
                "remediation": "Remove staging/dev endpoints from production. Use network-level isolation.",
                "cvss_score": 7.5 if resp.status_code == 200 else 5.3,
                "cwe_ref": CWE,
            })
    return findings
