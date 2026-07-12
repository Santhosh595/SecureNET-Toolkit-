"""ImgScan — CycloneDX SBOM generation."""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class Comp:
    name: str
    version: str
    ecosystem: str
    purl: str = ""
    license: str = ""


_LICENSE = {
    "python": "Apache-2.0", "npm": "MIT", "java": "Apache-2.0", "ruby": "MIT",
}


def _purl(eco: str, name: str, version: str) -> str:
    return f"pkg:{eco}/{name}@{version}"


def generate_sbom(components: list, path: str = None) -> dict:
    """Build a CycloneDX 1.4 bom from a list of (name, version, ecosystem)."""
    out_comps = []
    for c in components:
        eco = getattr(c, "ecosystem", "unknown")
        name = getattr(c, "name", "")
        version = getattr(c, "version", "")
        purl = getattr(c, "purl", "") or _purl(eco, name, version)
        lic = getattr(c, "license", "") or _LICENSE.get(eco, "")
        comp = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
        }
        if lic:
            comp["licenses"] = [{"license": {"id": lic}}]
        out_comps.append(comp)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": "",
            "tools": [{"vendor": "SecureNET", "name": "ImgScan",
                       "version": "1.0.0"}],
        },
        "components": out_comps,
    }
    if path:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bom, f, indent=2)
    return bom
