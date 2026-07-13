"""TechFinger — bulk URL scanner with CSV export."""

from __future__ import annotations

import csv
import os
import time
from typing import Iterable, List


def _risk_tally(techs) -> dict:
    tally = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for t in techs:
        sev = getattr(t, "risk", "INFO").upper()
        for k in tally:
            if sev.startswith(k[:4]):
                tally[k] += 1
                break
    return tally


def scan_urls(urls: Iterable[str], delay: float = 1.0,
              full: bool = False, user_agent: str = None,
              timeout: float = 8.0) -> List[dict]:
    """Scan a list of URLs. Returns a result dict per URL."""
    from fingerprinter import fetch, fingerprint
    from database import (init_db, save_scan, save_technologies,
                          save_header_checks, save_cves)
    init_db()
    out: List[dict] = []
    for i, url in enumerate(urls):
        url = url.strip()
        if not url:
            continue
        t0 = time.time()
        resp = fetch(url, timeout=timeout, full=full,
                     user_agent=user_agent or "")
        fp = fingerprint(resp)
        techs = fp["technologies"]
        cves = fp["cve_correlations"]
        try:
            sid = save_scan(url, len(techs), len(cves),
                           time.time() - t0, resp.status, resp.waf_detected)
            save_technologies(sid, techs)
            save_header_checks(sid, fp["header_checks"])
            save_cves(sid, cves)
        except Exception:
            sid = -1
        out.append({
            "url": url, "status": resp.status,
            "tech_count": len(techs), "cve_count": len(cves),
            "risk": _risk_tally(techs), "scan_id": sid,
            "waf": resp.waf_detected,
        })
        if delay and i < len(list(urls)) - 1:
            time.sleep(delay)
    return out


def export_csv(results: List[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "status", "tech_count", "cve_count",
                     "critical", "high", "medium", "info", "waf"])
        for r in results:
            rk = r["risk"]
            w.writerow([r["url"], r["status"], r["tech_count"],
                        r["cve_count"], rk["CRITICAL"], rk["HIGH"],
                        rk["MEDIUM"], rk["INFO"], r["waf"]])
