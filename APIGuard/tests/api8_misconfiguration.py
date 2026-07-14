"""APIGuard — API8:2023 Security Misconfiguration."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "API8"
SEVERITY = "HIGH"
CWE = "CWE-16"
DEBUG_PATHS = ["/api/debug","/api/test","/api/dev","/__debug__","/api/internal/test","/api/actuator","/api/actuator/health","/api/actuator/info","/api/actuator/env"]

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    # 1. CORS misconfiguration
    resp = requester.options("/", headers={"Origin": "https://evil.com"})
    if resp:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao in ("*", "https://evil.com") and acac.lower() == "true":
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": "/", "method": "OPTIONS",
                "test_name": "CORS misconfiguration (wildcard + credentials)",
                "severity": "CRITICAL",
                "evidence": f"ACAO: {acao}, ACAC: {acac}",
                "request_sent": "OPTIONS / [Origin: https://evil.com]",
                "response_received": f"ACAO: {acao}, ACAC: {acac}",
                "remediation": "Do not use Access-Control-Allow-Origin: * with Allow-Credentials: true. Whitelist specific origins.",
                "cvss_score": 9.8, "cwe_ref": "CWE-942",
            })
        elif acao in ("*", "https://evil.com"):
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": "/", "method": "OPTIONS",
                "test_name": "CORS misconfiguration (reflects origin)",
                "severity": "HIGH",
                "evidence": f"ACAO reflected: {acao}",
                "request_sent": "OPTIONS / [Origin: https://evil.com]",
                "response_received": f"ACAO: {acao}",
                "remediation": "Whitelist specific origins. Do not echo the Origin header.",
                "cvss_score": 7.5, "cwe_ref": "CWE-942",
            })
    # 2. Debug endpoints
    for dp in DEBUG_PATHS:
        resp = requester.get(dp)
        if resp and resp.status_code == 200:
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": dp, "method": "GET",
                "test_name": "Debug/actuator endpoint exposed",
                "severity": "HIGH",
                "evidence": f"GET {dp} → {resp.status_code}",
                "request_sent": f"GET {dp}",
                "response_received": f"HTTP {resp.status_code}",
                "remediation": "Disable debug endpoints in production. If needed, restrict to internal network + authentication.",
                "cvss_score": 7.5, "cwe_ref": CWE,
            })
    # 3. TRACE method
    resp = requester.request("TRACE", "/")
    if resp and resp.status_code == 200:
        findings.append({
            "owasp_category": OWASP_CAT, "endpoint": "/", "method": "TRACE",
            "test_name": "TRACE method enabled",
            "severity": "MEDIUM",
            "evidence": f"TRACE / → {resp.status_code}",
            "request_sent": "TRACE /",
            "response_received": f"HTTP {resp.status_code}",
            "remediation": "Disable TRACE method. It exposes internal headers via XST attacks.",
            "cvss_score": 5.3, "cwe_ref": "CWE-16",
        })
    # 4. Stack traces from malformed input
    malformed_bodies = ["not-json-at-all", "{broken json", "<xml>", "null"]
    for ep in endpoints[:5]:
        path = ep.get("path","")
        for body in malformed_bodies:
            resp = requester.request("POST", path, data=body, headers={"Content-Type":"application/json"})
            if resp:
                body_text = (resp.content or b"").decode(errors="replace")
                if "Traceback" in body_text or "at " in body_text or "Exception" in body_text:
                    findings.append({
                        "owasp_category": OWASP_CAT, "endpoint": path, "method": "POST",
                        "test_name": "Stack trace disclosed",
                        "severity": "HIGH",
                        "evidence": "Stack trace in response body to malformed input",
                        "request_sent": f"POST {path} [malformed JSON]",
                        "response_received": f"HTTP {resp.status_code}, body contains stack trace",
                        "remediation": "Configure error handling to return generic error messages. Never expose internal stack traces.",
                        "cvss_score": 7.5, "cwe_ref": "CWE-209",
                    })
                    break
    return findings
