"""HTTP request engine.

Responsibilities:
    * resolve targets (URL / file / domain) with normalization + dedup
    * build a requests.Session with pooling + limited retries
    * send read-only requests (GET by default) with rate limiting + threads
    * open-redirect protection (never follow redirects to another host)
    * optional --dry-run (build requests, log them, never send)
    * emit findings (one per matched path) with extracted values
"""

from __future__ import annotations

import concurrent.futures as cf
import time
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .extractors import run_extractors
from .matchers import evaluate_matchers_block
from .ratelimiter import RateLimiter

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (compatible; SecureNET-VulnProbe/1.0; "
    "+https://github.com/Santhosh595/SecureNET-Toolkit-)",
]

DEFAULT_HEADERS = {
    "Accept": "*/*",
    "Connection": "keep-alive",
}

_UA_INDEX = 0


def _rotate_ua() -> str:
    global _UA_INDEX
    ua = USER_AGENTS[_UA_INDEX % len(USER_AGENTS)]
    _UA_INDEX += 1
    return ua


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    url = url.strip()
    url = url.lower() if "://" not in url.lower() else url
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    if not path:
        path = ""
    return urlunparse((scheme, netloc, path, "", "", ""))


def resolve_targets(target: str) -> list[str]:
    """Return a deduplicated, normalized list of base URLs to scan."""
    raw: list[str] = []
    # file of URLs?
    if target.startswith("@") or _looks_like_file(target):
        try:
            with open(target.lstrip("@"), "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw.append(line)
        except OSError:
            pass
    else:
        raw = [target]

    out: set[str] = set()
    for item in raw:
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        if not item.startswith(("http://", "https://")):
            host = item
            if "/" in host:
                host = host.split("/", 1)[0]
            # domain-wide: probe both schemes
            out.add(normalize_url("https://" + host))
            out.add(normalize_url("http://" + host))
        else:
            out.add(normalize_url(item))
    return sorted(out)


def _looks_like_file(target: str) -> bool:
    return (
        target.endswith((".txt", ".lst", ".csv", ".urls"))
        and "/" not in target
        and "." in target
    )


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[],  # we only retry connection errors via raise_on_status=False
        allowed_methods=None,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    """Runs templates against targets using a thread pool."""

    def __init__(
        self,
        templates: list[dict],
        *,
        workers: int = 25,
        rate_limit: int = 150,
        timeout: int = 10,
        dry_run: bool = False,
        global_headers: dict | None = None,
        on_finding=None,
        on_progress=None,
    ):
        self.templates = templates
        self.workers = max(1, int(workers))
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.dry_run = dry_run
        self.global_headers = global_headers or {}
        self.on_finding = on_finding  # callable(finding)
        self.on_progress = on_progress  # callable(done, total)
        self.limiter = RateLimiter(rate_limit)
        self._ua_counter = 0

    # -- request ----------------------------------------------------------

    def _send(self, session, method: str, url: str, headers: dict, allow_redirects: bool):
        if self.dry_run:
            return None  # signal dry-run; caller handles
        base_host = urlparse(url).netloc
        # open-redirect protection: cap redirects and verify host
        max_redirects = 5 if allow_redirects else 0
        resp = session.request(
            method, url, headers=headers, timeout=self.timeout,
            allow_redirects=False,
        )
        hops = 0
        while 0 < max_redirects and resp.is_redirect and hops < max_redirects:
            loc = resp.headers.get("Location")
            if not loc:
                break
            target = urlparse(resp.url)
            if loc.startswith("/"):
                next_url = urlunparse((target.scheme, target.netloc, loc, "", "", ""))
            else:
                next_url = loc
            # NEVER follow redirects to a different domain
            if urlparse(next_url).netloc and urlparse(next_url).netloc != base_host:
                break
            resp = session.request(
                method, next_url, headers=headers, timeout=self.timeout,
                allow_redirects=False,
            )
            hops += 1
        return resp

    # -- template ---------------------------------------------------------

    def _run_template(self, session, base_url: str, template: dict) -> list[dict]:
        findings: list[dict] = []
        tpl_headers = dict(DEFAULT_HEADERS)
        tpl_headers.update(self.global_headers)
        for req in template.get("requests", []):
            method = str(req.get("method", "GET")).upper()
            if method != "GET" and not template.get("safe"):
                # enforce read-only by default
                continue
            paths = req.get("path", ["/"])
            if isinstance(paths, str):
                paths = [paths]
            headers = dict(tpl_headers)
            headers["User-Agent"] = _rotate_ua()
            headers.update(req.get("headers") or {})
            allow_redirects = bool(req.get("follow_redirects", False))
            req_timeout = int(req.get("timeout", self.timeout))
            old_timeout = self.timeout
            self.timeout = req_timeout

            for path in paths:
                url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
                if self.dry_run:
                    if self.on_finding:
                        self.on_finding({
                            "dry_run": True, "method": method, "url": url,
                            "template_id": template["id"], "name": template["name"],
                        })
                    continue
                host = urlparse(url).netloc
                self.limiter.acquire(host)
                try:
                    t0 = time.monotonic()
                    resp = self._send(session, method, url, headers, allow_redirects)
                    elapsed_ms = int((time.monotonic() - t0) * 1000)
                except requests.RequestException as e:
                    self.limiter.note_success(host)
                    continue

                if resp is None:
                    continue  # defensive: dry-run handled above

                # 429 handling
                if resp.status_code == 429:
                    self.limiter.note_429(host)
                    ra = resp.headers.get("Retry-After")
                    if ra and ra.isdigit():
                        self.limiter.note_retry_after(host, float(ra))
                    continue
                self.limiter.note_success(host)

                matched, triggered = evaluate_matchers_block(
                    req.get("matchers") or [], resp
                )
                if matched:
                    extracted = run_extractors(resp, req.get("extractors") or [])
                    cond_desc = "; ".join(
                        f"{c.get('type')}"
                        + (f"({c.get('part')})" if c.get("part") else "")
                        for c in triggered
                    )
                    findings.append({
                        "template_id": template["id"],
                        "name": template["name"],
                        "severity": template["severity"],
                        "category": template.get("category", "uncategorized"),
                        "url": base_url,
                        "matched_path": path,
                        "matched_condition": cond_desc or "matcher",
                        "extracted": extracted,
                        "status_code": resp.status_code,
                        "response_size": len(resp.content or b""),
                        "response_ms": elapsed_ms,
                        "remediation": template.get("remediation", ""),
                        "method": method,
                        "timestamp": time.time(),
                    })
            self.timeout = old_timeout
        return findings

    # -- driver -----------------------------------------------------------

    def run(self, targets: list[str]) -> list[dict]:
        """Run all templates against all targets. Returns findings."""
        all_findings: list[dict] = []
        session = build_session() if not self.dry_run else None
        total = len(targets) * len(self.templates)
        done = 0

        def _work(base_url: str, template: dict):
            return self._run_template(session, base_url, template)

        try:
            with cf.ThreadPoolExecutor(max_workers=self.workers) as ex:
                futures = {}
                for base_url in targets:
                    for template in self.templates:
                        fut = ex.submit(_work, base_url, template)
                        futures[fut] = (base_url, template)
                for fut in cf.as_completed(futures):
                    base_url, template = futures[fut]
                    try:
                        res = fut.result()
                    except Exception:
                        res = []
                    for f in res:
                        all_findings.append(f)
                        if self.on_finding:
                            self.on_finding(f)
                    done += 1
                    if self.on_progress:
                        self.on_progress(done, total)
        finally:
            if session is not None:
                session.close()
        return all_findings
