"""APIGuard — API6:2023 Unrestricted Access to Sensitive Business Flows."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "API6"
CWE = "CWE-799"
HIGH_VALUE_ENDPOINTS = ["/api/register","/api/login","/api/signup","/api/checkout","/api/forgot-password","/api/reset-password","/api/coupon","/api/promo","/api/discount"]

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    found_hv = [e for e in endpoints if any(hv in e.get("path","") for hv in HIGH_VALUE_ENDPOINTS)]
    for ep in found_hv:
        path = ep.get("path","")
        # Check for bot protection signals
        resp = requester.get(path)
        if resp is None:
            continue
        # If no CAPTCHA/bot detection headers visible
        headers_lower = {k.lower():v for k,v in resp.headers.items()}
        has_captcha = any("captcha" in h or "recaptcha" in h or "turnstile" in h or "cf-" in h for h in headers_lower)
        if not has_captcha:
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": path, "method": "GET",
                "test_name": "No bot protection on high-value endpoint",
                "severity": "LOW",
                "evidence": f"No CAPTCHA or bot detection headers on {path}",
                "request_sent": f"GET {path}",
                "response_received": f"HTTP {resp.status_code}, headers checked",
                "remediation": "Add CAPTCHA (reCAPTCHA, Turnstile) or rate limiting to registration, login, and checkout endpoints.",
                "cvss_score": 2.5, "cwe_ref": CWE,
            })
            break  # Only flag once
    # Account enumeration check
    login_eps = [e for e in endpoints if "login" in e.get("path","").lower() or "forgot" in e.get("path","").lower() or "reset" in e.get("path","").lower()]
    for ep in login_eps[:3]:
        path = ep.get("path","")
        # Try with a valid-looking email vs invalid
        resp1 = requester.request("POST", path, json={"email":"nonexistent@test123456.com","password":"WrongPass1!"})
        resp2 = requester.request("POST", path, json={"email":"real@test123456.com","password":"WrongPass1!"})
        if resp1 and resp2:
            body1 = (resp1.content or b"").decode(errors="replace")[:200]
            body2 = (resp2.content or b"").decode(errors="replace")[:200]
            if body1 != body2 and resp1.status_code == resp2.status_code:
                # Different response bodies = potential enumeration
                findings.append({
                    "owasp_category": OWASP_CAT, "endpoint": path, "method": "POST",
                    "test_name": "Account enumeration possible",
                    "severity": "MEDIUM",
                    "evidence": f"Different responses for valid vs invalid email (same status {resp1.status_code})",
                    "request_sent": f"POST {path} [email: valid vs invalid]",
                    "response_received": f"Body differs: {body1[:60]} vs {body2[:60]}",
                    "remediation": "Return identical error messages for valid and invalid accounts. Use constant-time comparison.",
                    "cvss_score": 5.3, "cwe_ref": CWE,
                })
    return findings
