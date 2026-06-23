"""HeaderScan — HTTP Security Header Analyzer.

Analyzes HTTP response headers for security misconfigurations,
assigns risk levels, and computes an overall security score.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

import requests


class RiskLevel(Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Grade(Enum):
    A = "A"
    B = "B"
    C = "C"
    F = "F"


# ── Weight table — critical headers count more ──
HEADER_WEIGHTS: dict[str, int] = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy": 20,
    "X-Frame-Options": 15,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 8,
    "Permissions-Policy": 7,
    "X-XSS-Protection": 5,
    "Cache-Control": 5,
    "Set-Cookie": 5,
    "Server": 5,
}

TOTAL_WEIGHT = sum(HEADER_WEIGHTS.values())  # 100


@dataclass
class HeaderResult:
    """Result for a single header check."""
    header: str
    present: bool
    value: Optional[str]
    risk: str  # SAFE / WARNING / CRITICAL
    explanation: str
    recommendation: str


@dataclass
class ScanReport:
    """Full scan report for a URL."""
    url: str
    status_code: int
    headers_found: int
    headers_checked: int
    score: int
    grade: str
    results: list[HeaderResult] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers_found": self.headers_found,
            "headers_checked": self.headers_checked,
            "score": self.score,
            "grade": self.grade,
            "results": [asdict(r) for r in self.results],
            "error": self.error,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ── Individual header checkers ──

def _check_hsts(headers: dict[str, str]) -> HeaderResult:
    name = "Strict-Transport-Security"
    value = headers.get(name)
    if not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.CRITICAL.value,
            explanation="HSTS forces browsers to use HTTPS, preventing downgrade attacks.",
            recommendation="Set: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )
    # Check max-age
    max_age_match = re.search(r"max-age=(\d+)", value)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    if max_age < 31536000:
        return HeaderResult(
            header=name, present=True, value=value,
            risk=RiskLevel.WARNING.value,
            explanation=f"max-age is {max_age}s. Should be at least 31536000 (1 year).",
            recommendation="Set: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )
    return HeaderResult(
        header=name, present=True, value=value,
        risk=RiskLevel.SAFE.value,
        explanation="HSTS is properly configured with a long max-age.",
        recommendation="No change needed.",
    )


def _check_csp(headers: dict[str, str]) -> HeaderResult:
    name = "Content-Security-Policy"
    value = headers.get(name)
    if not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.CRITICAL.value,
            explanation="CSP prevents XSS by restricting which resources can be loaded.",
            recommendation="Set a strict CSP, e.g.: Content-Security-Policy: default-src 'self'",
        )
    # Check for unsafe directives
    unsafe = []
    if "'unsafe-inline'" in value:
        unsafe.append("'unsafe-inline'")
    if "'unsafe-eval'" in value:
        unsafe.append("'unsafe-eval'")
    if "*" in value and "default-src *" in value:
        unsafe.append("wildcard *")
    if unsafe:
        return HeaderResult(
            header=name, present=True, value=value[:120],
            risk=RiskLevel.WARNING.value,
            explanation=f"CSP contains unsafe directives: {', '.join(unsafe)}.",
            recommendation="Remove 'unsafe-inline', 'unsafe-eval', and wildcards from CSP.",
        )
    return HeaderResult(
        header=name, present=True, value=value[:120],
        risk=RiskLevel.SAFE.value,
        explanation="CSP is present and does not contain obviously unsafe directives.",
        recommendation="Review CSP regularly as your site evolves.",
    )


def _check_x_frame_options(headers: dict[str, str]) -> HeaderResult:
    name = "X-Frame-Options"
    value = headers.get(name)
    if not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.CRITICAL.value,
            explanation="Without X-Frame-Options, attackers can embed your page in iframes (clickjacking).",
            recommendation="Set: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed)",
        )
    value_upper = value.upper().strip()
    if value_upper in ("DENY", "SAMEORIGIN"):
        return HeaderResult(
            header=name, present=True, value=value,
            risk=RiskLevel.SAFE.value,
            explanation=f"X-Frame-Options is set to {value_upper}, preventing clickjacking.",
            recommendation="No change needed.",
        )
    return HeaderResult(
        header=name, present=True, value=value,
        risk=RiskLevel.WARNING.value,
        explanation=f"Value '{value}' is non-standard. Use DENY or SAMEORIGIN.",
        recommendation="Set: X-Frame-Options: DENY",
    )


def _check_x_content_type_options(headers: dict[str, str]) -> HeaderResult:
    name = "X-Content-Type-Options"
    value = headers.get(name)
    if not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.WARNING.value,
            explanation="Without this header, browsers may MIME-sniff responses, enabling XSS.",
            recommendation="Set: X-Content-Type-Options: nosniff",
        )
    if value.strip().lower() == "nosniff":
        return HeaderResult(
            header=name, present=True, value=value,
            risk=RiskLevel.SAFE.value,
            explanation="nosniff prevents MIME-type sniffing attacks.",
            recommendation="No change needed.",
        )
    return HeaderResult(
        header=name, present=True, value=value,
        risk=RiskLevel.WARNING.value,
        explanation=f"Value should be 'nosniff', got '{value}'.",
        recommendation="Set: X-Content-Type-Options: nosniff",
    )


def _check_referrer_policy(headers: dict[str, str]) -> HeaderResult:
    name = "Referrer-Policy"
    value = headers.get(name)
    if not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.WARNING.value,
            explanation="Without Referrer-Policy, full URLs may leak in the Referer header to third parties.",
            recommendation="Set: Referrer-Policy: strict-origin-when-cross-origin",
        )
    safe_values = {"no-referrer", "strict-origin-when-cross-origin", "same-origin", "origin"}
    if value.strip().lower() in safe_values:
        return HeaderResult(
            header=name, present=True, value=value,
            risk=RiskLevel.SAFE.value,
            explanation="Referrer-Policy is set to a safe value.",
            recommendation="No change needed.",
        )
    return HeaderResult(
        header=name, present=True, value=value,
        risk=RiskLevel.WARNING.value,
        explanation=f"Value '{value}' may leak more referrer information than necessary.",
        recommendation="Set: Referrer-Policy: strict-origin-when-cross-origin",
    )


def _check_permissions_policy(headers: dict[str, str]) -> HeaderResult:
    name = "Permissions-Policy"
    value = headers.get(name)
    if not value:
        # Also check legacy header
        legacy = headers.get("Feature-Policy")
        if legacy:
            return HeaderResult(
                header=name, present=True, value=legacy[:120],
                risk=RiskLevel.WARNING.value,
                explanation="Using deprecated Feature-Policy header instead of Permissions-Policy.",
                recommendation="Migrate to: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            )
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.WARNING.value,
            explanation="Permissions-Policy restricts which browser features pages can use.",
            recommendation="Set: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        )
    return HeaderResult(
        header=name, present=True, value=value[:120],
        risk=RiskLevel.SAFE.value,
        explanation="Permissions-Policy is set, restricting browser feature access.",
        recommendation="Review the policy to ensure it matches your site's needs.",
    )


def _check_xss_protection(headers: dict[str, str]) -> HeaderResult:
    name = "X-XSS-Protection"
    value = headers.get(name)
    if not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.WARNING.value,
            explanation="Legacy XSS filter header. Modern browsers rely on CSP instead.",
            recommendation="Set: X-XSS-Protection: 0 (disable legacy filter, rely on CSP)",
        )
    if value.strip() == "0":
        return HeaderResult(
            header=name, present=True, value=value,
            risk=RiskLevel.SAFE.value,
            explanation="Legacy XSS filter is disabled (rely on CSP, which is the modern approach).",
            recommendation="No change needed.",
        )
    return HeaderResult(
        header=name, present=True, value=value,
        risk=RiskLevel.WARNING.value,
        explanation="Enabling the legacy XSS filter can cause security issues in modern browsers.",
        recommendation="Set: X-XSS-Protection: 0",
    )


def _check_cache_control(headers: dict[str, str]) -> HeaderResult:
    name = "Cache-Control"
    value = headers.get(name)
    if not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.WARNING.value,
            explanation="Without Cache-Control, sensitive pages may be cached by browsers or proxies.",
            recommendation="Set: Cache-Control: no-store, no-cache, must-revalidate (for sensitive pages)",
        )
    value_lower = value.lower()
    if "no-store" in value_lower or "no-cache" in value_lower:
        return HeaderResult(
            header=name, present=True, value=value[:120],
            risk=RiskLevel.SAFE.value,
            explanation="Cache-Control prevents caching of sensitive content.",
            recommendation="No change needed.",
        )
    return HeaderResult(
        header=name, present=True, value=value[:120],
        risk=RiskLevel.WARNING.value,
        explanation="Cache-Control is set but may allow caching of sensitive data.",
        recommendation="For sensitive pages, add: no-store, no-cache",
    )


def _check_set_cookie(headers: dict[str, str]) -> HeaderResult:
    name = "Set-Cookie"
    # requests stores multiple Set-Cookie in a list via response.headers
    # but CaseInsensitiveDict only keeps last. We check what we have.
    value = headers.get(name)
    if not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.SAFE.value,
            explanation="No Set-Cookie header present. If your site uses cookies, check flags.",
            recommendation="When setting cookies, always use Secure, HttpOnly, and SameSite flags.",
        )
    issues = []
    if "secure" not in value.lower():
        issues.append("missing Secure flag")
    if "httponly" not in value.lower():
        issues.append("missing HttpOnly flag")
    if "samesite" not in value.lower():
        issues.append("missing SameSite flag")
    if issues:
        return HeaderResult(
            header=name, present=True, value=value[:120],
            risk=RiskLevel.CRITICAL.value,
            explanation=f"Cookie has security issues: {', '.join(issues)}.",
            recommendation="Set: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
        )
    return HeaderResult(
        header=name, present=True, value=value[:120],
        risk=RiskLevel.SAFE.value,
        explanation="Cookie has Secure, HttpOnly, and SameSite flags set.",
        recommendation="No change needed.",
    )


def _check_server_header(headers: dict[str, str]) -> HeaderResult:
    name = "Server"
    value = headers.get(name)
    powered = headers.get("X-Powered-By")
    issues = []
    if value:
        # Check if it reveals version info
        if re.search(r"/\d", value) or re.search(r"\d+\.\d", value):
            issues.append(f"Server: {value}")
    if powered:
        issues.append(f"X-Powered-By: {powered}")
    if not issues and not value:
        return HeaderResult(
            header=name, present=False, value=None,
            risk=RiskLevel.SAFE.value,
            explanation="Server header is not revealing version information.",
            recommendation="No change needed.",
        )
    if not issues:
        return HeaderResult(
            header=name, present=True, value=value[:120],
            risk=RiskLevel.SAFE.value,
            explanation="Server header is present but does not reveal version details.",
            recommendation="Consider removing the Server header entirely.",
        )
    return HeaderResult(
        header=name, present=True, value="; ".join(issues)[:120],
        risk=RiskLevel.WARNING.value,
        explanation="Server/X-Powered-By headers reveal technology stack information to attackers.",
        recommendation="Remove or obfuscate Server and X-Powered-By headers.",
    )


# ── Registry of all checkers ──
HEADER_CHECKERS = [
    _check_hsts,
    _check_csp,
    _check_x_frame_options,
    _check_x_content_type_options,
    _check_referrer_policy,
    _check_permissions_policy,
    _check_xss_protection,
    _check_cache_control,
    _check_set_cookie,
    _check_server_header,
]


def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    parsed = urlparse(url.strip())
    if not parsed.scheme:
        return "https://" + url.strip()
    return url.strip()


def _compute_grade(score: int) -> Grade:
    if score >= 90:
        return Grade.A
    if score >= 75:
        return Grade.B
    if score >= 50:
        return Grade.C
    return Grade.F


def scan_url(url: str, timeout: float = 5.0, follow_redirects: bool = True) -> ScanReport:
    """Fetch a URL and analyze its HTTP security headers.

    Args:
        url: The URL to scan.
        timeout: Request timeout in seconds.
        follow_redirects: Whether to follow HTTP redirects (up to 5).

    Returns:
        A ScanReport with results for all 10 security headers.
    """
    url = _normalize_url(url)

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=follow_redirects,
            headers={
                "User-Agent": "HeaderScan/1.0 (+https://github.com/Santhosh595/SecureNET-Toolkit-)"
            },
        )
    except requests.exceptions.Timeout:
        return ScanReport(
            url=url, status_code=0, headers_found=0,
            headers_checked=len(HEADER_CHECKERS),
            score=0, grade=Grade.F.value,
            error=f"Request timed out after {timeout}s",
        )
    except requests.exceptions.ConnectionError:
        return ScanReport(
            url=url, status_code=0, headers_found=0,
            headers_checked=len(HEADER_CHECKERS),
            score=0, grade=Grade.F.value,
            error="Could not connect to the target URL",
        )
    except requests.exceptions.TooManyRedirects:
        return ScanReport(
            url=url, status_code=0, headers_found=0,
            headers_checked=len(HEADER_CHECKERS),
            score=0, grade=Grade.F.value,
            error="Too many redirects (limit: 5)",
        )
    except requests.exceptions.RequestException as exc:
        return ScanReport(
            url=url, status_code=0, headers_found=0,
            headers_checked=len(HEADER_CHECKERS),
            score=0, grade=Grade.F.value,
            error=f"Request failed: {exc}",
        )

    # Normalize header names to title-case for consistent lookup
    headers: dict[str, str] = {}
    for key, val in resp.headers.items():
        # Title-case the header name
        title_key = "-".join(part.capitalize() for part in key.split("-"))
        headers[title_key] = val

    results: list[HeaderResult] = []
    score = 0

    for checker in HEADER_CHECKERS:
        result = checker(headers)
        results.append(result)
        weight = HEADER_WEIGHTS.get(result.header, 5)
        if result.risk == RiskLevel.SAFE.value:
            score += weight
        elif result.risk == RiskLevel.WARNING.value:
            score += weight // 2
        # CRITICAL = 0 points for that header

    grade = _compute_grade(score)

    return ScanReport(
        url=resp.url,
        status_code=resp.status_code,
        headers_found=len([r for r in results if r.present]),
        headers_checked=len(results),
        score=score,
        grade=grade.value,
        results=results,
    )
