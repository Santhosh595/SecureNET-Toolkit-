"""ImgScan — Ruby dependency scanner (Gemfile.lock)."""

from __future__ import annotations

import os
import re
from typing import Dict, List

from .common import (VulnFinding, load_offline_rules, enrich, upgrade_cmd)
from parsers.version_matcher import match_version

# Ruby rules reuse the curated python/node offline set where names overlap;
# here we bundle a small ruby-specific set inline (also merged into offline file
# at runtime is optional — kept independent for clarity).
RUBY_RULES = [
    ("rails", ["<6.1.7.1", ">=6.0,<6.1.7.1"], "CVE-2023-28362", "MEDIUM", 5.3, "6.1.7.1", "Possible XSS in Action View (CVE-2023-28362).", "https://nvd.nist.gov/vuln/detail/CVE-2023-28362"),
    ("actionpack", ["<7.0.4", ">=6.0,<7.0.4"], "CVE-2023-22797", "HIGH", 8.1, "7.0.4", "Possible open redirect (CVE-2023-22797).", "https://nvd.nist.gov/vuln/detail/CVE-2023-22797"),
    ("actionview", ["<6.1.7", ">=6.0,<6.1.7"], "CVE-2023-2719", "MEDIUM", 6.1, "6.1.7", "XSS via content_security_policy (CVE-2023-2719).", "https://nvd.nist.gov/vuln/detail/CVE-2023-2719"),
    ("nokogiri", ["<1.14.0", ">=1.0,<1.14.0"], "CVE-2023-28755", "HIGH", 7.5, "1.14.0", "ReDoS in Nokogiri (CVE-2023-28755).", "https://nvd.nist.gov/vuln/detail/CVE-2023-28755"),
    ("loofah", ["<2.19.1", ">=2.0,<2.19.1"], "CVE-2023-20631", "MEDIUM", 5.9, "2.19.1", "XSS sanitizer bypass (CVE-2023-20631).", "https://nvd.nist.gov/vuln/detail/CVE-2023-20631"),
    ("rack", ["<2.2.6.4", ">=2.0,<2.2.6.4"], "CVE-2023-27539", "HIGH", 7.5, "2.2.6.4", "ReDoS in Rack (CVE-2023-27539).", "https://nvd.nist.gov/vuln/detail/CVE-2023-27539"),
    ("sidekiq", ["<6.5.0", ">=6.0,<6.5.0"], "CVE-2022-23837", "MEDIUM", 5.9, "6.5.0", "DoS via unauthenticated dashboard.", "https://nvd.nist.gov/vuln/detail/CVE-2022-23837"),
    ("puma", ["<6.3.0", ">=5.0,<6.3.0"], "CVE-2023-45684", "HIGH", 7.5, "6.3.0", "Information leak in Puma (CVE-2023-45684).", "https://nvd.nist.gov/vuln/detail/CVE-2023-45684"),
]


def parse_gemfile_lock(path: str) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    text = open(path, encoding="utf-8", errors="ignore").read()
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            m = re.match(r"\s{4}([A-Za-z0-9_.\-]+)\s+\((\d[\d.A-Za-z\-]*)\)", line)
            if m:
                deps[m.group(1).lower()] = m.group(2)
            elif re.match(r"\s{2}\S", line) and "(" not in line:
                in_specs = False
    return deps


def scan_ruby_dir(path: str) -> List[VulnFinding]:
    fp = os.path.join(path, "Gemfile.lock")
    if not os.path.isfile(fp):
        return []
    deps = parse_gemfile_lock(fp)
    findings: List[VulnFinding] = []
    for (pkg, aff, cve, sev, cvss, fixed, desc, ref) in RUBY_RULES:
        if pkg.lower() not in deps:
            continue
        ver = deps[pkg.lower()]
        if match_version(ver, aff):
            f = VulnFinding(package=pkg, version=ver, ecosystem="ruby",
                            cve_id=cve, severity=sev.upper(),
                            cvss_score=cvss, description=desc,
                            fixed_version=fixed, reference=ref,
                            source="offline")
            findings.append(enrich(f))
    return findings
