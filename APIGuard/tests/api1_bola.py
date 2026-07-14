"""APIGuard — API1:2023 Broken Object Level Authorization (BOLA)."""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from tests import ApiRequester, cvss_for

OWASP_CAT = "API1"
SEVERITY = "CRITICAL"
CWE = "CWE-639"

def run(requester: ApiRequester, endpoints: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    id_endpoints = [e for e in endpoints if "{" in e.get("path","") or any(c.isdigit() for c in e.get("path","").rstrip("/").split("/")[-1])]
    tested = set()
    for ep in id_endpoints[:10]:  # limit to 10 endpoints
        path = ep.get("path","")
        method = ep.get("method","GET")
        if (method, path) in tested:
            continue
        tested.add((method, path))
        # Try to get the resource
        resp = requester.request(method, path, params=ep.get("parameters",""))
        if resp is None:
            continue
        baseline_body_size = len(resp.content) if resp.content else 0
        # ID fuzzing: own_id ±1, ±2, random, common IDs
        id_candidates = ["1", "2", "100", "9999", "0000", "abc-def-123"]
        base_path = path.split("{")[0].rstrip("/") if "{" in path else path
        # Try to find numeric ID in path and modify
        parts = path.strip("/").split("/")
        for i, part in enumerate(parts):
            if part.isdigit():
                for delta in [1, -1, 2, -2]:
                    new_id = int(part) + delta
                    if new_id <= 0:
                        continue
                    mod_parts = list(parts)
                    mod_parts[i] = str(new_id)
                    mod_path = "/" + "/".join(mod_parts)
                    probe = requester.request(method, mod_path)
                    if probe and probe.status_code == 200:
                        probe_size = len(probe.content) if probe.content else 0
                        # Check if response is different from baseline
                        if abs(probe_size - baseline_body_size) > 50 or probe.content != resp.content:
                            findings.append({
                                "owasp_category": OWASP_CAT,
                                "endpoint": mod_path,
                                "method": method,
                                "test_name": f"BOLA ID fuzz ({part}->{new_id})",
                                "severity": SEVERITY,
                                "evidence": f"Accessed {mod_path} with ID {new_id} → 200 OK",
                                "request_sent": f"{method} {mod_path}",
                                "response_received": f"HTTP {probe.status_code}, size={probe_size}",
                                "remediation": "Implement object-level authorization checks. Verify the authenticated user owns the requested resource.",
                                "cvss_score": cvss_for(SEVERITY),
                                "cwe_ref": CWE,
                            })
    return findings
