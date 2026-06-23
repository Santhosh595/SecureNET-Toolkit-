"""SubProbe — DNS resolution and HTTP status checking.

Handles DNS queries, wildcard detection, and HTTP live status checks.
"""

from __future__ import annotations

import random
import socket
import string
import time
from typing import Optional

import dns.resolver
import requests


def generate_random_subdomain(length: int = 12) -> str:
    """Generate a random subdomain for wildcard detection."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


def check_wildcard_dns(domain: str, timeout: float = 3.0) -> tuple[bool, Optional[str]]:
    """Check if a domain has wildcard DNS enabled.

    Args:
        domain: The target domain (e.g., example.com).
        timeout: DNS timeout in seconds.

    Returns:
        (is_wildcard, wildcard_ip_or_None)
    """
    random_sub = f"{generate_random_subdomain()}.{domain}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(random_sub, "A")
        if answers:
            ip = str(answers[0])
            return True, ip
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, socket.timeout, Exception):
        pass
    return False, None


def resolve_dns(subdomain: str, timeout: float = 3.0) -> Optional[str]:
    """Resolve a subdomain to its IP address.

    Args:
        subdomain: Full subdomain (e.g., api.example.com).
        timeout: DNS timeout in seconds.

    Returns:
        IP address string or None if resolution fails.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(subdomain, "A")
        if answers:
            return str(answers[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, socket.timeout, Exception):
        pass
    return None


def check_http_status(subdomain: str, timeout: float = 5.0) -> tuple[int, str]:
    """Check HTTP/HTTPS status of a subdomain.

    Args:
        subdomain: Full subdomain to check.
        timeout: HTTP timeout in seconds.

    Returns:
        (status_code, status_string) where status_string is LIVE/DEAD/REDIRECT/TIMEOUT
    """
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{subdomain}"
            resp = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
            code = resp.status_code
            if code == 200:
                return code, "LIVE"
            elif 300 <= code < 400:
                return code, "REDIRECT"
            elif code == 403:
                return code, "LIVE"
            elif code == 404:
                return code, "DEAD"
            else:
                return code, "LIVE"
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            return 0, "TIMEOUT"
        except Exception:
            continue
    return 0, "DEAD"


def resolve_and_check(subdomain: str, timeout: float = 5.0) -> dict:
    """Resolve a subdomain and check its HTTP status.

    Args:
        subdomain: Full subdomain to check.
        timeout: HTTP timeout in seconds.

    Returns:
        Dict with keys: ip, http_status, status
    """
    ip = resolve_dns(subdomain, timeout=timeout)
    if ip:
        http_code, http_status = check_http_status(subdomain, timeout=timeout)
        return {"ip": ip, "http_status": http_code, "status": http_status}
    return {"ip": None, "http_status": 0, "status": "DEAD"}
