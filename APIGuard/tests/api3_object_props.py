"""APIGuard — API3:2023 Broken Object Property Level Authorization."""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "API3"
CWE = "CWE-913"

SENSITIVE_FIELDS = {"password","password_hash","ssn","credit_card","secret","private_key","internal_id","admin_flag","is_admin","role","permissions","token","api_key"}

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    # 1. Excessive data exposure — scan GET responses
    for ep in endpoints[:20]:
        path = ep.get("path","")
        method = ep.get("method","GET")
        if method != "GET":
            continue
        resp = requester.get(path)
        if resp is None or not resp.content:
            continue
        ct = resp.headers.get("Content-Type","")
        if "json" not in ct.lower():
            continue
        try:
            data = json.loads(resp.content)
        except (json.JSONDecodeError, ValueError):
            continue
        found = _scan_sensitive(data)
        if found:
            findings.append({
                "owasp_category": OWASP_CAT, "endpoint": path, "method": "GET",
                "test_name": f"Excessive data: {', '.join(found[:4])}",
                "severity": "HIGH",
                "evidence": f"Response contains sensitive fields: {', '.join(found[:6])}",
                "request_sent": f"GET {path}",
                "response_received": f"HTTP {resp.status_code}, fields={found}",
                "remediation": "Apply response filtering. Return only fields the caller is authorized to see. Consider using GraphQL or sparse field sets.",
                "cvss_score": 7.5, "cwe_ref": CWE,
            })
    # 2. Mass assignment — POST/PUT endpoints
    post_endpoints = [e for e in endpoints if e.get("method") in ("POST","PUT","PATCH")]
    for ep in post_endpoints[:5]:
        path = ep.get("path","")
        method = ep.get("method","POST")
        payloads = [
            {"name":"test","role":"admin","is_admin":True,"credit":99999},
            {"email":"test@x.com","role":"superadmin","permissions":"*"},
            {"name":"x","admin":True,"balance":999999},
        ]
        for payload in payloads:
            resp = requester.request(method, path, json=payload)
            if resp is None:
                continue
            if resp.status_code in (200, 201):
                # Check if the extra field was accepted by re-fetching
                get_resp = requester.get(path)
                if get_resp and get_resp.content:
                    try:
                        get_data = json.loads(get_resp.content)
                        for k in payload:
                            if k in ("name", "email"):
                                continue
                            val = _deep_get(get_data, k)
                            if val is not None:
                                findings.append({
                                    "owasp_category": OWASP_CAT, "endpoint": path, "method": method,
                                    "test_name": f"Mass assignment: {k}={val}",
                                    "severity": "HIGH",
                                    "evidence": f"Extra field '{k}' was accepted ({method} {path} → {resp.status_code}) and persisted (GET returned {k}={val})",
                                    "request_sent": f"{method} {path} [body with extra field: {k}={payload[k]}]",
                                    "response_received": f"HTTP {resp.status_code}",
                                    "remediation": "Use a whitelist of allowed fields (DTO pattern). Do not auto-bind request body to model.",
                                    "cvss_score": 7.5, "cwe_ref": CWE,
                                })
                                break
                    except (json.JSONDecodeError, ValueError):
                        pass
    return findings

def _scan_sensitive(data: Any, depth: int = 0) -> List[str]:
    if depth > 5:
        return []
    found: List[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in SENSITIVE_FIELDS:
                found.append(k)
            found.extend(_scan_sensitive(v, depth+1))
    elif isinstance(data, list):
        for item in data:
            found.extend(_scan_sensitive(item, depth+1))
    return found

def _deep_get(data: Any, key: str) -> Any:
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for v in data.values():
            r = _deep_get(v, key)
            if r is not None:
                return r
    elif isinstance(data, list):
        for item in data:
            r = _deep_get(item, key)
            if r is not None:
                return r
    return None
