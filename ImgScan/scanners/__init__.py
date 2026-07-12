"""ImgScan — scanners package aggregator."""

from __future__ import annotations

import os
from typing import List

from .common import VulnFinding, DockerFinding
from .python_scanner import (scan_requirements, scan_python_dir, check_package,
                             PIP_AUDIT_HINT)
from .node_scanner import scan_node_dir, NPM_AUDIT_HINT
from .java_scanner import scan_java_dir
from .ruby_scanner import scan_ruby_dir
from .dockerfile_auditor import audit_dockerfile

MANIFESTS = {
    "python": ("requirements.txt", "Pipfile.lock", "pyproject.toml",
               "setup.py", "poetry.lock"),
    "node": ("package.json", "package-lock.json", "yarn.lock"),
    "java": ("pom.xml", "build.gradle"),
    "ruby": ("Gemfile.lock",),
}


def scan_directory(path: str) -> List[VulnFinding]:
    """Auto-detect all manifests in `path` and run the right scanner per ecosystem."""
    findings: List[VulnFinding] = []
    if os.path.isfile(path):
        # single manifest passed
        base = os.path.basename(path)
        if base in MANIFESTS["python"]:
            findings += scan_requirements(path)
        return findings
    findings += scan_python_dir(path)
    findings += scan_node_dir(path)
    findings += scan_java_dir(path)
    findings += scan_ruby_dir(path)
    return findings


def scan_component_list(components) -> List[VulnFinding]:
    """Scan a list of (name, version, ecosystem) — used by SBOM scan mode."""
    findings: List[VulnFinding] = []
    from parsers.sbom_parser import Component
    for c in components:
        eco = getattr(c, "ecosystem", "unknown")
        if eco == "python":
            findings += check_package(c.name, c.version)
        elif eco == "npm":
            findings += _check_node(c.name, c.version)
        elif eco == "java":
            findings += _check_java(c.name, c.version, getattr(c, "coordinate", ""))
        elif eco == "ruby":
            findings += _check_ruby(c.name, c.version)
    return findings


def _check_node(name, version):
    from .node_scanner import scan_offline  # noqa
    from .common import load_offline_rules, enrich, VulnFinding
    from parsers.version_matcher import match_version
    out = []
    for rule in load_offline_rules().get("npm", []):
        if rule["package"].lower() == name.lower() and version and \
           match_version(version, rule["affected_versions"]):
            f = VulnFinding(package=name, version=version, ecosystem="npm",
                            cve_id=rule["cve_id"], severity=rule["severity"].upper(),
                            cvss_score=rule.get("cvss_score", 0.0),
                            description=rule.get("description", ""),
                            fixed_version=rule.get("fixed_version", ""),
                            reference=rule.get("reference", ""),
                            source="offline")
            out.append(enrich(f))
    return out


def _check_java(name, version, coord):
    from .java_scanner import scan_offline
    return scan_offline([{"name": name.lower(), "version": version,
                          "coordinate": coord}])


def _check_ruby(name, version):
    from .ruby_scanner import RUBY_RULES
    from .common import enrich, VulnFinding
    from parsers.version_matcher import match_version
    out = []
    for (pkg, aff, cve, sev, cvss, fixed, desc, ref) in RUBY_RULES:
        if pkg.lower() == name.lower() and match_version(version, aff):
            f = VulnFinding(package=name, version=version, ecosystem="ruby",
                            cve_id=cve, severity=sev.upper(), cvss_score=cvss,
                            description=desc, fixed_version=fixed,
                            reference=ref, source="offline")
            out.append(enrich(f))
    return out


__all__ = [
    "scan_directory", "scan_requirements", "scan_python_dir", "check_package",
    "scan_node_dir", "scan_java_dir", "scan_ruby_dir", "audit_dockerfile",
    "scan_component_list", "VulnFinding", "DockerFinding",
    "PIP_AUDIT_HINT", "NPM_AUDIT_HINT", "MANIFESTS",
]
