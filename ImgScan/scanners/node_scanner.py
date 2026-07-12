"""ImgScan — Node.js dependency scanner (npm audit + offline CVE rules)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Dict, List

from .common import (VulnFinding, load_offline_rules, enrich, upgrade_cmd)
from parsers.version_matcher import match_version

NPM_AUDIT_HINT = ("npm not found, using offline CVE rules. "
                 "For better coverage: npm install -g npm")


def parse_package_lock(path: str) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    try:
        data = json.load(open(path))
    except (json.JSONDecodeError, OSError):
        return deps
    # npm v2/v3 lockfile: packages["node_modules/name"].version
    pkgs = data.get("packages", {})
    if pkgs:
        for key, meta in pkgs.items():
            if key.startswith("node_modules/"):
                name = key.split("node_modules/")[-1].split("node_modules/")[-1]
                ver = meta.get("version", "")
                deps[name.lower()] = ver
    # legacy: dependencies[name].version
    for name, meta in (data.get("dependencies", {}) or {}).items():
        deps[name.lower()] = meta.get("version", "")
    return deps


def parse_yarn_lock(path: str) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    text = open(path, encoding="utf-8", errors="ignore").read()
    # entries like: "lodash@^4.17.0":\n  version "4.17.21"
    blocks = re.split(r'\n\n+', text)
    for b in blocks:
        m = re.search(r'^"([^"@]+)@', b, re.M)
        v = re.search(r'^\s+version "([^"]+)"', b, re.M)
        if m and v:
            deps[m.group(1).lower()] = v.group(1)
    return deps


def scan_with_npm_audit(project_dir: str) -> List[VulnFinding]:
    if not shutil.which("npm"):
        return []
    try:
        res = subprocess.run(["npm", "audit", "--json"],
                             cwd=project_dir, capture_output=True,
                             text=True, timeout=180)
    except (subprocess.SubprocessError, OSError):
        return []
    findings: List[VulnFinding] = []
    try:
        data = json.loads(res.stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    # npm v7+ format: "vulnerabilities": { name: {severity, via:[{title,cve,url}],range} }
    vulns = data.get("vulnerabilities", {})
    for name, meta in vulns.items():
        cve = "UNKNOWN"
        for via in meta.get("via", []) or []:
            if isinstance(via, dict) and via.get("cve"):
                cve = via["cve"]
                break
        f = VulnFinding(package=name.lower(), version="",
                        ecosystem="npm",
                        cve_id=cve,
                        severity=str(meta.get("severity", "medium")).upper(),
                        description=meta.get("title", "")[:200],
                        source="npm-audit")
        findings.append(enrich(f))
    return findings


def scan_offline(deps: Dict[str, str]) -> List[VulnFinding]:
    rules = load_offline_rules().get("npm", [])
    findings: List[VulnFinding] = []
    for rule in rules:
        pkg = rule["package"].lower()
        if pkg not in deps:
            continue
        ver = deps[pkg]
        if not ver:
            continue
        if match_version(ver, rule["affected_versions"]):
            f = VulnFinding(package=pkg, version=ver, ecosystem="npm",
                            cve_id=rule["cve_id"],
                            severity=rule["severity"].upper(),
                            cvss_score=rule.get("cvss_score", 0.0),
                            description=rule.get("description", ""),
                            fixed_version=rule.get("fixed_version", ""),
                            reference=rule.get("reference", ""),
                            source="offline")
            findings.append(enrich(f))
    return findings


def scan_node_dir(path: str) -> List[VulnFinding]:
    findings: List[VulnFinding] = []
    live = scan_with_npm_audit(path)
    if live:
        return live
    for fname in ("package-lock.json", "yarn.lock"):
        fp = os.path.join(path, fname)
        if os.path.isfile(fp):
            deps = (parse_package_lock(fp) if fname.endswith(".json")
                    else parse_yarn_lock(fp))
            findings += scan_offline(deps)
    return findings
