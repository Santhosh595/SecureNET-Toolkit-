"""ImgScan core — container/dependency CVE scanner (Trivy-style).

Two modes:
  1. dependency scan  -> uses `pip-audit` (if available) on a requirements file
  2. image scan       -> parses an image's SBOM/Packages from a tarball or a
     local directory of package manifests and matches against a small built-in
     CVE rule set (offline, illustrative).

All checks are read-only and offline-first.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class Finding:
    component: str
    version: str
    cve: str
    severity: str
    source: str
    detail: str = ""


# Small illustrative offline CVE rule set (id -> component, version range, severity).
# In production this is fed by the NVD/Trivy DB; kept tiny here for portability.
CVE_RULES = [
    ("CVE-2023-32681", "requests", "<2.31.0", "high", "Proxy-Authorization leak on redirect"),
    ("CVE-2024-35195", "requests", "<2.32.0", "medium", "Session persistence across requests"),
    ("CVE-2023-37920", "certifi", "<2023.7.22", "critical", "Malicious CA certificate included"),
    ("CVE-2021-33503", "urllib3", "<1.26.5", "high", "CRLF injection via method parameter"),
    ("CVE-2023-43804", "urllib3", "<2.0.7", "medium", "Cookie leak across redirect"),
    ("CVE-2024-37891", "urllib3", "<2.2.2", "medium", "Proxy-auth header leak on redirect"),
    ("CVE-2023-50447", "Pillow", "<10.2.0", "high", "Arbitrary code execution via TIFF"),
    ("CVE-2024-28219", "Flask", "<3.0.3", "medium", "Possible XSS via error page"),
]


def _parse_version(v: str) -> tuple:
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums[:4]) + (0,) * (4 - min(4, len(nums)))


def _version_in_range(version: str, rng: str) -> bool:
    """rng like '<2.31.0' -> True if version < 2.31.0."""
    m = re.match(r"^\s*<\s*([0-9.]+)", rng)
    if not m:
        return False
    return _parse_version(version) < _parse_version(m.group(1))


def scan_dependencies(req_path: str) -> list[Finding]:
    """Scan a requirements-style file. Uses pip-audit if present, else regex rules."""
    findings: list[Finding] = []
    if not os.path.isfile(req_path):
        return findings
    deps: dict[str, str] = {}
    for line in open(req_path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=)?\s*([0-9][0-9A-Za-z.\-]*)?", line)
        if not m:
            continue
        name = m.group(1).lower()
        ver = m.group(3) or ""
        deps[name] = ver

    if shutil.which("pip-audit"):
        try:
            res = subprocess.run(
                ["pip-audit", "-r", req_path, "--progress-spinner", "off", "-f", "json"],
                capture_output=True, text=True, timeout=120,
            )
            try:
                data = json.loads(res.stdout)
                for dep in data.get("dependencies", []):
                    name = (dep.get("name") or "").lower()
                    for vuln in dep.get("vulns", []):
                        findings.append(Finding(
                            component=name, version=dep.get("version", ""),
                            cve=vuln.get("id", "UNKNOWN"),
                            severity=str(vuln.get("severity", "unknown")).lower(),
                            source="pip-audit",
                            detail=vuln.get("description", "")[:120],
                        ))
            except (json.JSONDecodeError, KeyError):
                pass
            if findings:
                return findings
        except (subprocess.SubprocessError, OSError):
            pass

    # Fallback: offline rule matching
    for cve, comp, rng, sev, desc in CVE_RULES:
        have = deps.get(comp.lower())
        if have and _version_in_range(have, rng):
            findings.append(Finding(comp, have, cve, sev, "offline-rules", desc))
    return findings


def scan_image_sbom(sbom_path: str) -> list[Finding]:
    """Scan a CycloneDX/SPDX-ish JSON SBOM against offline rules."""
    findings: list[Finding] = []
    if not os.path.isfile(sbom_path):
        return findings
    try:
        data = json.loads(open(sbom_path).read())
    except (json.JSONDecodeError, OSError):
        return findings
    pkgs = data.get("packages") or data.get("components") or []
    for pkg in pkgs:
        name = (pkg.get("name") or "").lower()
        version = pkg.get("version", "")
        for cve, comp, rng, sev, desc in CVE_RULES:
            if name == comp.lower() and version and _version_in_range(version, rng):
                findings.append(Finding(comp, version, cve, sev, "offline-rules", desc))
    return findings


def summarize(findings: list[Finding]) -> dict:
    sev: dict[str, int] = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return {"total": len(findings), "by_severity": sev}
