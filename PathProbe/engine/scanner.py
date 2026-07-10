"""PathProbe — the orchestrating scanner (threads + filtering + recursion)."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from engine import requester, filter as filt, baseline, recursive
from engine.wordlist import build_wordlist


class Scanner:
    MAX_REQUESTS = 50000
    MAX_THREADS = 200

    def __init__(self, target: str, wordlist_spec: str, *,
                 extensions: list[str] | None = None,
                 prefix: str = "",
                 no_original: bool = False,
                 threads: int = 50,
                 timeout: float = 10.0,
                 rate_limit: int | None = None,
                 delay_ms: int = 0,
                 headers: dict | None = None,
                 cookies: dict | None = None,
                 user_agent: str | None = None,
                 proxy: str | None = None,
                 recursive: bool = False,
                 depth: int = 2,
                 recursive_status: set[int] | None = None,
                 show: set[int] | None = None,
                 hide: set[int] | None = None,
                 filter_size: int | None = None,
                 filter_size_range: tuple[int, int] | None = None,
                 filter_words: list[str] | None = None,
                 wildcard_check: bool = True,
                 respect_robots: bool = False,
                 on_result=None, on_progress=None, on_status=None):
        self.target = target.rstrip("/")
        if not self.target.startswith(("http://", "https://")):
            self.target = "https://" + self.target
        self.wordlist_spec = wordlist_spec
        self.extensions = extensions or []
        self.prefix = prefix
        self.no_original = no_original
        self.threads = max(1, min(threads, self.MAX_THREADS))
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.delay_ms = delay_ms
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.user_agent = user_agent
        self.proxy = proxy
        self.recursive = recursive
        self.depth = depth
        self.recursive_status = recursive_status or {200, 301, 302}
        self.show = show
        self.hide = hide
        self.filter_size = filter_size
        self.filter_size_range = filter_size_range
        self.filter_words = filter_words
        self.wildcard_check = wildcard_check
        self.respect_robots = respect_robots
        self.on_result = on_result
        self.on_progress = on_progress
        self.on_status = on_status

        self.words = build_wordlist(self.wordlist_spec, self.extensions,
                                    self.prefix, self.no_original)
        self.total = len(self.words)
        self.done = 0
        self.found = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._min_interval = (1.0 / self.rate_limit) if self.rate_limit else 0
        self._last_req = 0.0
        self.wildcard = None
        self.robots_disallowed = set()
        self.started_at = 0.0

    def _req_kwargs(self):
        return dict(timeout=self.timeout, headers=self.headers,
                    cookies=self.cookies, user_agent=self.user_agent, proxy=self.proxy)

    def _respect_rate(self):
        if self._min_interval > 0:
            now = time.time()
            wait = self._min_interval - (now - self._last_req)
            if wait > 0:
                time.sleep(wait)
            self._last_req = time.time()

    def _should_skip(self, word: str) -> bool:
        if not self.robots_disallowed:
            return False
        path = "/" + word.lstrip("/")
        for dis in self.robots_disallowed:
            if path == dis or path.startswith(dis.rstrip("*")):
                return True
        return False

    def _probe_one(self, word: str) -> dict | None:
        if self._stop.is_set():
            return None
        if self._should_skip(word):
            return None
        self._respect_rate()
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000.0)
        r = requester.probe(self.target, word, **self._req_kwargs())
        if r is None:
            return None
        return r

    def run(self) -> list[dict]:
        self.started_at = time.time()
        if self.on_status:
            self.on_status("running")
        # wildcard baseline
        if self.wildcard_check:
            self.wildcard = baseline.detect_baseline(self.target, **self._req_kwargs())
        # robots
        if self.respect_robots:
            self._parse_robots()

        findings: list[dict] = []
        self._scan_level(self.words, findings, depth=0)
        duration = time.time() - self.started_at
        if self.on_status:
            self.on_status("done")
        return findings, duration

    def _scan_level(self, words: list[str], findings: list[dict], depth: int):
        if self._stop.is_set():
            return
        level_findings: list[dict] = []
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe_one, w): w for w in words if not self._should_skip(w)}
            for fut in as_completed(futures):
                if self._stop.is_set():
                    break
                with self._lock:
                    self.done += 1
                r = fut.result()
                if r is None:
                    if self.on_progress:
                        self.on_progress(self.done, self.total)
                    continue
                if not filt.passes_filter(r, show=self.show, hide=self.hide,
                                          filter_size=self.filter_size,
                                          filter_size_range=self.filter_size_range,
                                          filter_words=self.filter_words,
                                          wildcard=self.wildcard):
                    if self.on_progress:
                        self.on_progress(self.done, self.total)
                    continue
                filt.annotate_interesting(r)
                level_findings.append(r)
                with self._lock:
                    self.found += 1
                if self.on_result:
                    self.on_result(r)
                if self.on_progress:
                    self.on_progress(self.done, self.total)

        findings.extend(level_findings)

        # recursion
        if self.recursive and depth < self.depth:
            next_words = []
            for f in level_findings:
                if recursive.is_directory_candidate(f, self.recursive_status):
                    # build sub-wordlist: re-run base wordlist under this dir
                    sub = f.get("word", "").rstrip("/") + "/"
                    for w in self.words:
                        next_words.append(f"{sub}{w}")
            if next_words and not self._stop.is_set():
                # recurse (guard total)
                if len(next_words) + self.done <= self.MAX_REQUESTS:
                    self._scan_level(next_words, findings, depth + 1)

    def stop(self):
        self._stop.set()

    def _parse_robots(self):
        r = requester.probe(self.target, "robots.txt", **self._req_kwargs())
        if r and r["status"] == 200:
            import requests
            try:
                text = requests.get(self.target + "/robots.txt", timeout=self.timeout,
                                    headers={"User-Agent": self.user_agent or "PathProbe"},
                                    proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None,
                                    verify=False).text
                for line in text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        p = line.split(":", 1)[1].strip()
                        if p:
                            self.robots_disallowed.add(p)
            except Exception:
                pass
