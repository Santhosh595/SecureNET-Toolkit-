"""ImgScan — shared data access + findings model."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(HERE), "data")  # ImgScan/data


@dataclass
class VulnFinding:
    package: str
    version: str
    ecosystem: str
    cve_id: str
    severity: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    fixed_version: str = ""
    reference: str = ""
    in_kev: bool = False
    upgrade_command: str = ""
    source: str = "offline"  # offline | pip-audit | npm-audit


@dataclass
class DockerFinding:
    check_id: str
    line_number: int
    severity: str
    description: str = ""
    remediation: str = ""


def load_json(name: str):
    with open(os.path.join(DATA_DIR, name), "r", encoding="utf-8") as f:
        return json.load(f)


def load_offline_rules() -> dict:
    return load_json("offline_cve_rules.json")


def load_java_rules() -> list:
    return load_json("java_cve_rules.json")


def load_kev() -> set:
    return set(load_json("kev_list.json").get("cves", []))


def load_enrichment() -> dict:
    return load_json("cve_enrichment.json")


_KEV = None
_ENR = None


def kev_for(cve_id: str) -> bool:
    global _KEV
    if _KEV is None:
        _KEV = load_kev()
    return cve_id in _KEV


def enrichment_for(cve_id: str) -> dict:
    global _ENR
    if _ENR is None:
        _ENR = load_enrichment()
    return _ENR.get(cve_id, {})


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def enrich(f: VulnFinding) -> VulnFinding:
    enr = enrichment_for(f.cve_id)
    if f.cvss_score == 0.0 and enr.get("cvss_score"):
        f.cvss_score = enr["cvss_score"]
    if not f.cvss_vector and enr.get("cvss_vector"):
        f.cvss_vector = enr["cvss_vector"]
    f.in_kev = kev_for(f.cve_id)
    return f


def upgrade_cmd(ecosystem: str, package: str, fixed_version: str) -> str:
    if ecosystem == "python":
        return f"pip install {package}=={fixed_version}"
    if ecosystem == "npm":
        return f"npm install {package}@{fixed_version}"
    if ecosystem == "java":
        return f"Update pom.xml / build.gradle {package} to {fixed_version}"
    if ecosystem == "ruby":
        return f"bundle update {package}"
    return f"upgrade {package} to {fixed_version}"
