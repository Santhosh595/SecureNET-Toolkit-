"""ImgScan — SBOM parsing (CycloneDX + SPDX)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Component:
    name: str
    version: str
    ecosystem: str = "unknown"
    purl: str = ""
    license: str = ""
    coordinate: str = ""  # maven group:artifact


def _norm_ecosystem(purl: str) -> str:
    """Infer ecosystem from a purl type."""
    if purl.startswith("pkg:pypi/"):
        return "python"
    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith("pkg:maven/"):
        return "java"
    if purl.startswith("pkg:gem/"):
        return "ruby"
    return "unknown"


def parse_cyclonedx(data: dict) -> List[Component]:
    comps: List[Component] = []
    for c in data.get("components", []) or []:
        name = c.get("name", "")
        version = c.get("version", "")
        purl = c.get("purl", "")
        eco = _norm_ecosystem(purl) if purl else (c.get("type") or "unknown")
        lic = ""
        lic_obj = c.get("licenses")
        if lic_obj:
            first = lic_obj[0] if isinstance(lic_obj, list) else lic_obj
            lic = (first.get("license", {}) or {}).get("id") or \
                  (first.get("license", {}) or {}).get("name") or \
                  first.get("name") or ""
        comps.append(Component(name=name, version=version, ecosystem=eco,
                               purl=purl, license=str(lic),
                               coordinate=c.get("group", "")))
    return comps


def parse_spdx(data: dict) -> List[Component]:
    comps: List[Component] = []
    for p in data.get("packages", []) or []:
        name = p.get("name", "")
        version = p.get("versionInfo", "")
        lic = p.get("licenseConcluded", "") or p.get("licenseDeclared", "")
        purl = ""
        for ref in p.get("externalRefs", []) or []:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
        eco = _norm_ecosystem(purl) if purl else "unknown"
        comps.append(Component(name=name, version=version, ecosystem=eco,
                               purl=purl, license=str(lic)))
    return comps


def parse_sbom(path: str) -> List[Component]:
    """Dispatch by format. Returns list of components."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    fmt = data.get("bomFormat")
    if fmt == "CycloneDX":
        return parse_cyclonedx(data)
    if "spdxVersion" in data or data.get("bomFormat") == "SPDX":
        return parse_spdx(data)
    # heuristic: cyclonedx uses 'components', spdx uses 'packages'
    if "components" in data:
        return parse_cyclonedx(data)
    if "packages" in data:
        return parse_spdx(data)
    return []
