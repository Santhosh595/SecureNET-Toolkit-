"""APIGuard — API7:2023 Server Side Request Forgery."""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "API7"
CWE = "CWE-918"
SSRF_PARAM_NAMES = ["url","callback","redirect","fetch","webhook","image_url","src","href","link","path","file","download","proxy","dest","destination"]
INTERNAL_PROBES = ["http://127.0.0.1/","http://localhost/","http://169.254.169.254/","http://[::1]/","http://0.0.0.0/"]

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    # Find endpoints with URL-like parameters
    for ep in endpoints[:15]:
        path = ep.get("path","")
        method = ep.get("method","GET")
        # Try URL parameters in query
        for param_name in SSRF_PARAM_NAMES:
            for internal_url in INTERNAL_PROBES:
                resp = requester.request(method, path, params={param_name: internal_url})
                if resp is None:
                    continue
                # Check for internal content in response
                body = (resp.content or b"").decode(errors="replace")
                internal_signals = ["root:x:0:0", "cloud-init", "meta-data", "127.0.0.1", "localhost"]
                for sig in internal_signals:
                    if sig in body.lower():
                        findings.append({
                            "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                            "test_name": f"SSRF via {param_name}",
                            "severity": "CRITICAL",
                            "evidence": f"Internal content '{sig}' reflected when {param_name}={internal_url}",
                            "request_sent": f"{method} {path}?{param_name}={internal_url}",
                            "response_received": f"HTTP {resp.status_code}, body contains '{sig}'",
                            "remediation": "Validate URL parameters against an allowlist. Block private IP ranges. Use a URL parser to reject internal addresses.",
                            "cvss_score": 9.8, "cwe_ref": CWE,
                        })
                        break
                # Unusual response time (potential SSRF delay)
                if resp.elapsed and resp.elapsed.total_seconds() > 3:
                    findings.append({
                        "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                        "test_name": f"SSRF timing anomaly via {param_name}",
                        "severity": "MEDIUM",
                        "evidence": f"Request with {param_name}={internal_url} took {resp.elapsed.total_seconds():.1f}s",
                        "request_sent": f"{method} {path}?{param_name}={internal_url}",
                        "response_received": f"HTTP {resp.status_code} in {resp.elapsed.total_seconds():.1f}s (unusual delay)",
                        "remediation": "Set short timeouts on outbound requests. Block private IP ranges at the network level.",
                        "cvss_score": 5.3, "cwe_ref": CWE,
                    })
                break  # One probe per param is enough
    return findings
