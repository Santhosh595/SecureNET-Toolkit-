"""APIGuard — shared test utilities."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests as req_lib

from auth import AuthConfig
from analyzer.baseline import BaselineTracker
from analyzer.response_analyzer import ResponseAnalyzer

ANALYZER = ResponseAnalyzer()
BASELINE = BaselineTracker()


class ApiRequester:
    """Wrapper around requests that respects auth, timeout, and safe mode."""

    def __init__(
        self,
        base_url: str,
        auth_config: AuthConfig,
        timeout: int = 10,
        unsafe: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = auth_config
        self.timeout = timeout
        self.unsafe = unsafe
        self.session = req_lib.Session()
        self.session.headers.update(auth_config.get_headers())
        self.session.headers["User-Agent"] = "APIGuard/1.0 (Security Scanner)"
        self.session.headers["Accept"] = "*/*"

    def request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> Optional[req_lib.Response]:
        """Send an HTTP request and record baseline. Returns None on error."""
        safe_methods = ("GET", "OPTIONS", "HEAD")
        if not self.unsafe and method.upper() not in safe_methods:
            # Skip destructive methods in safe mode unless --unsafe is set
            return None
        url = self.base_url + ("/" if path else "") + path.lstrip("/")
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        headers = kwargs.pop("headers", {})
        merged = dict(self.session.headers)
        merged.update(headers)
        try:
            start = time.time()
            resp = self.session.request(method, url, headers=merged, **kwargs)
            elapsed = time.time() - start
            # Record baseline for normal GET/OPTIONS requests
            if method.upper() in safe_methods:
                BASELINE.record(
                    method.upper(), path,
                    status=resp.status_code,
                    time_sec=elapsed,
                    size=len(resp.content),
                    content_type=resp.headers.get("Content-Type", ""),
                )
            return resp
        except req_lib.exceptions.Timeout:
            return None
        except req_lib.exceptions.ConnectionError:
            return None
        except Exception:
            return None

    def get(self, path: str, **kwargs: Any) -> Optional[req_lib.Response]:
        return self.request("GET", path, **kwargs)

    def options(self, path: str, **kwargs: Any) -> Optional[req_lib.Response]:
        return self.request("OPTIONS", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Optional[req_lib.Response]:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Optional[req_lib.Response]:
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Optional[req_lib.Response]:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Optional[req_lib.Response]:
        return self.request("DELETE", path, **kwargs)


def check_auth_bypass(requester: ApiRequester, path: str, method: str = "GET") -> Optional[Dict]:
    """Check if an endpoint is accessible without authentication."""
    # Send without auth headers
    anon_headers = dict(requester.session.headers)
    for auth_hdr in ("Authorization", "X-API-Key", "Cookie"):
        anon_headers.pop(auth_hdr, None)
    noauth = requester.session
    old_hdrs = dict(noauth.headers)
    noauth.headers.update(anon_headers)
    try:
        url = requester.base_url + "/" + path.lstrip("/")
        resp = noauth.request(method, url, timeout=requester.timeout, allow_redirects=False)
        if resp.status_code == 200:
            return {
                "status": resp.status_code,
                "evidence": f"Endpoint returned 200 without auth headers",
            }
        return None
    except Exception:
        return None
    finally:
        noauth.headers.update(old_hdrs)


def cvss_for(severity: str) -> float:
    """Estimate CVSS v3 score from severity label."""
    return {"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 2.5, "INFO": 0.0}.get(severity.upper(), 5.3)
