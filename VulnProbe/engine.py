"""VulnProbe core — template-based HTTP probe engine (Nuclei-style).

Sends templated HTTP requests to a target and evaluates matchers
(status code / word / regex) to surface misconfigurations and
exposed assets. All checks are read-only and safe by design.
"""

from __future__ import annotations

import glob
import os
import re

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_HEADERS = {
    "User-Agent": "VulnProbe/1.0 (+https://github.com/Santhosh595/SecureNET-Toolkit-)"
}


def load_templates(directory: str) -> list[dict]:
    """Load all *.yaml probe templates from a directory."""
    templates: list[dict] = []
    if not directory or not os.path.isdir(directory):
        return templates
    for path in sorted(glob.glob(os.path.join(directory, "*.yaml"))):
        try:
            with open(path) as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                continue
            data["_file"] = os.path.basename(path)
            templates.append(data)
        except (OSError, yaml.YAMLError):
            continue
    return templates


def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=1, backoff_factor=0.2,
                  status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _matchers_haystack(resp) -> str:
    text = getattr(resp, "text", "") or ""
    headers = getattr(resp, "headers", {}) or {}
    hdr = "\n".join(f"{k}:{v}" for k, v in headers.items())
    return text + "\n" + hdr


def _match_status(resp, matcher) -> bool:
    return resp.status_code in set(matcher.get("status", []))


def _match_word(resp, matcher) -> bool:
    words = matcher.get("words", [])
    condition = matcher.get("condition", "or")
    hay = _matchers_haystack(resp)
    found = [w for w in words if w in hay]
    return len(found) == len(words) if condition == "and" else len(found) > 0


def _match_regex(resp, matcher) -> bool:
    patterns = matcher.get("regex", [])
    condition = matcher.get("condition", "or")
    hay = _matchers_haystack(resp)
    compiled = [re.compile(p, re.I) for p in patterns]
    found = [c for c in compiled if c.search(hay)]
    return len(found) == len(compiled) if condition == "and" else len(found) > 0


def evaluate_matcher(matcher: dict, resp) -> bool:
    """Public matcher evaluator — used by tests and the engine."""
    mtype = matcher.get("type", "word")
    if mtype == "status":
        return _match_status(resp, matcher)
    if mtype == "regex":
        return _match_regex(resp, matcher)
    return _match_word(resp, matcher)


def run_template(session: requests.Session, base_url: str, template: dict) -> dict | None:
    """Run a single template against base_url. Returns a finding dict or None."""
    info = template.get("info", {})
    severity = str(info.get("severity", "info")).lower()
    name = info.get("name", template.get("id", "unknown"))
    for req in template.get("requests", []):
        method = req.get("method", "GET").upper()
        path = req.get("path", "/")
        url = base_url.rstrip("/") + path
        try:
            resp = session.request(
                method, url, headers=DEFAULT_HEADERS,
                timeout=req.get("timeout", 8),
                allow_redirects=req.get("redirects", True),
            )
        except requests.RequestException:
            continue
        matchers = req.get("matchers", [])
        if not matchers:
            continue
        results = [evaluate_matcher(m, resp) for m in matchers]
        cond = req.get("matchers-condition", "and")
        passed = all(results) if cond == "and" else any(results)
        if passed:
            return {
                "id": template.get("id"),
                "name": name,
                "severity": severity,
                "method": method,
                "path": path,
                "status_code": resp.status_code,
                "matched_on": [m.get("type") for m in matchers],
                "template_file": template.get("_file"),
            }
    return None


def scan_target(base_url: str, templates: list[dict], session: requests.Session | None = None) -> list[dict]:
    """Run every template against a target. Returns a list of findings."""
    close_session = session is None
    session = session or build_session()
    findings: list[dict] = []
    for template in templates:
        finding = run_template(session, base_url, template)
        if finding:
            finding["target"] = base_url
            findings.append(finding)
    if close_session:
        session.close()
    return findings
