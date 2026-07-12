"""ImgScan — Java dependency scanner (pom.xml + JAR MANIFEST.MF)."""

from __future__ import annotations

import os
import re
import zipfile
from typing import Dict, List

import xml.etree.ElementTree as ET

from .common import (VulnFinding, load_java_rules, enrich, upgrade_cmd)
from parsers.version_matcher import match_version

_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def parse_pom(path: str) -> List[Dict[str, str]]:
    """Return list of {name, version, coordinate} for direct + managed deps."""
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return []
    root = tree.getroot()
    out: List[Dict[str, str]] = []
    # dependencies
    for dep in root.iter("{http://maven.apache.org/POM/4.0.0}dependency"):
        gid = (dep.findtext("{http://maven.apache.org/POM/4.0.0}groupId") or "")
        aid = (dep.findtext("{http://maven.apache.org/POM/4.0.0}artifactId") or "")
        ver = (dep.findtext("{http://maven.apache.org/POM/4.0.0}version") or "")
        if aid:
            out.append({"name": aid.lower(), "version": ver.strip(),
                        "coordinate": f"{gid}:{aid}"})
    return out


def scan_offline(deps: List[Dict[str, str]]) -> List[VulnFinding]:
    rules = load_java_rules()
    findings: List[VulnFinding] = []
    for rule in rules:
        coord = rule.get("coordinate", "").lower()
        pkg = rule["package"].lower()
        for d in deps:
            match = (d.get("coordinate", "").lower() == coord) or \
                    (d["name"] == pkg)
            if not match or not d.get("version"):
                continue
            if match_version(d["version"], rule["affected_versions"]):
                f = VulnFinding(package=rule["package"], version=d["version"],
                                ecosystem="java", cve_id=rule["cve_id"],
                                severity=rule["severity"].upper(),
                                cvss_score=rule.get("cvss_score", 0.0),
                                description=rule.get("description", ""),
                                fixed_version=rule.get("fixed_version", ""),
                                reference=rule.get("reference", ""),
                                source="offline")
                findings.append(enrich(f))
    return findings


def _jar_version(jar_path: str) -> Dict[str, str]:
    try:
        with zipfile.ZipFile(jar_path) as z:
            if "META-INF/MANIFEST.MF" not in z.namelist():
                return {}
            data = z.read("META-INF/MANIFEST.MF").decode("utf-8", "ignore")
    except (zipfile.BadZipFile, OSError):
        return {}
    info: Dict[str, str] = {}
    name = ""
    for line in data.splitlines():
        if line.startswith("Implementation-Title:"):
            name = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Implementation-Version:"):
            info["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("Bundle-Version:"):
            info.setdefault("version", line.split(":", 1)[1].strip())
    if name:
        info["name"] = name
    return info


def scan_java_dir(path: str) -> List[VulnFinding]:
    deps: List[Dict[str, str]] = []
    for fname in ("pom.xml", "build.gradle"):
        fp = os.path.join(path, fname)
        if os.path.isfile(fp) and fname == "pom.xml":
            deps += parse_pom(fp)
    # scan jars for Implementation-Version
    for root, _dirs, files in os.walk(path):
        for fn in files:
            if fn.endswith(".jar"):
                info = _jar_version(os.path.join(root, fn))
                if info.get("name") and info.get("version"):
                    deps.append({"name": info["name"],
                                 "version": info["version"],
                                 "coordinate": ""})
    return scan_offline(deps)
