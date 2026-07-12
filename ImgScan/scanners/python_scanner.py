"""ImgScan — Python dependency scanner (pip-audit + offline CVE rules)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Dict, List

from .common import (VulnFinding, load_offline_rules, enrich, upgrade_cmd,
                    SEV_ORDER)
from parsers.version_matcher import match_version

PIP_AUDIT_HINT = ("pip-audit not found, using offline CVE rules. "
                 "For better coverage: pip install pip-audit")


def parse_requirements(path: str) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # name==ver ; markers
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|<|>)?\s*([0-9][0-9A-Za-z.\-\_]*)?",
                          line)
            if not m:
                continue
            name = m.group(1).lower()
            ver = m.group(3) or ""
            deps[name] = ver
    return deps


def scan_with_pip_audit(req_path: str) -> List[VulnFinding]:
    if not shutil.which("pip-audit"):
        return []
    try:
        res = subprocess.run(
            ["pip-audit", "-r", req_path, "--progress-spinner", "off",
             "-f", "json", "--no-deps"],
            capture_output=True, text=True, timeout=180,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    findings: List[VulnFinding] = []
    try:
        data = json.loads(res.stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    for dep in data.get("dependencies", []) or []:
        name = (dep.get("name") or "").lower()
        version = dep.get("version", "") or ""
        for vuln in dep.get("vulns", []) or []:
            cve = vuln.get("id", "UNKNOWN")
            sev = str(vuln.get("severity", "unknown")).upper()
            fixed = ""
            for fix in vuln.get("fix_versions", []) or []:
                fixed = fix
                break
            f = VulnFinding(package=name, version=version, ecosystem="python",
                            cve_id=cve, severity=sev,
                            description=(vuln.get("description") or "")[:200],
                            fixed_version=fixed,
                            reference=f"https://nvd.nist.gov/vuln/detail/{cve}",
                            source="pip-audit")
            findings.append(enrich(f))
    return findings


def scan_offline(deps: Dict[str, str]) -> List[VulnFinding]:
    rules = load_offline_rules()
    py_rules = rules.get("python", [])
    findings: List[VulnFinding] = []
    for rule in py_rules:
        pkg = rule["package"].lower()
        if pkg not in deps:
            continue
        ver = deps[pkg]
        if not ver:
            continue
        if match_version(ver, rule["affected_versions"]):
            f = VulnFinding(
                package=pkg, version=ver, ecosystem="python",
                cve_id=rule["cve_id"], severity=rule["severity"].upper(),
                cvss_score=rule.get("cvss_score", 0.0),
                description=rule.get("description", ""),
                fixed_version=rule.get("fixed_version", ""),
                reference=rule.get("reference", ""),
                source="offline",
            )
            findings.append(enrich(f))
    return findings


def scan_requirements(req_path: str) -> List[VulnFinding]:
    """Full Python scan: pip-audit if available, else offline rules."""
    if not os.path.isfile(req_path):
        return []
    deps = parse_requirements(req_path)
    live = scan_with_pip_audit(req_path)
    if live:
        return live
    return scan_offline(deps)


def check_package(name: str, version: str) -> List[VulnFinding]:
    """Single-package check (Mode 5) across all ecosystems."""
    from scanners.java_scanner import scan_offline as java_offline
    from scanners.ruby_scanner import RUBY_RULES
    from .common import enrich, VulnFinding
    findings = scan_offline({name.lower(): version})
    # Java rules (maven coordinates)
    findings += java_offline([{"name": name.lower(), "version": version,
                               "coordinate": ""}])
    # Ruby rules
    from parsers.version_matcher import match_version
    for (pkg, aff, cve, sev, cvss, fixed, desc, ref) in RUBY_RULES:
        if pkg.lower() == name.lower() and version and match_version(version, aff):
            f = VulnFinding(package=name, version=version, ecosystem="ruby",
                            cve_id=cve, severity=sev.upper(), cvss_score=cvss,
                            description=desc, fixed_version=fixed,
                            reference=ref, source="offline")
            findings.append(enrich(f))
    return findings


def scan_python_dir(path: str) -> List[VulnFinding]:
    """Auto-detect python manifests in a directory."""
    findings: List[VulnFinding] = []
    for fname in ("requirements.txt", "Pipfile.lock", "pyproject.toml",
                  "setup.py", "poetry.lock"):
        fp = os.path.join(path, fname)
        if os.path.isfile(fp):
            if fname in ("requirements.txt", "poetry.lock"):
                findings += scan_requirements(fp)
            elif fname == "Pipfile.lock":
                findings += _scan_pipfile_lock(fp)
            elif fname == "pyproject.toml":
                findings += _scan_pyproject(fp)
    return findings


def _scan_pipfile_lock(fp: str) -> List[VulnFinding]:
    try:
        data = json.load(open(fp))
    except (json.JSONDecodeError, OSError):
        return []
    deps: Dict[str, str] = {}
    for section in ("default", "develop"):
        for name, meta in (data.get(section, {}) or {}).items():
            ver = (meta or {}).get("version", "").lstrip("==")
            deps[name.lower()] = ver
    return scan_offline(deps)


def _scan_pyproject(fp: str) -> List[VulnFinding]:
    # minimal: look for dependencies = [...] under [project]
    text = open(fp, encoding="utf-8", errors="ignore").read()
    deps: Dict[str, str] = {}
    m = re.search(r"dependencies\s*=\s*\[([^\]]*)\]", text, re.S)
    if m:
        for line in m.group(1).splitlines():
            mm = re.match(r'["\']([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=)?\s*([0-9][0-9A-Za-z.\-]*)?', line)
            if mm:
                deps[mm.group(1).lower()] = mm.group(2) or ""
    return scan_offline(deps)
