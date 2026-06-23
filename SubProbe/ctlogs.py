"""SubProbe — Certificate Transparency log integration via crt.sh.

Queries crt.sh to find subdomains from SSL/TLS certificate logs.
"""

from __future__ import annotations

import time
from typing import Optional

import requests


def query_crtsh(domain: str, timeout: float = 15.0, delay: float = 0.5) -> list[str]:
    """Query crt.sh for subdomains via Certificate Transparency logs.

    Args:
        domain: Target domain (e.g., example.com).
        timeout: Request timeout in seconds.
        delay: Delay between requests to respect rate limits.

    Returns:
        List of unique subdomain strings found.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains: set[str] = set()

    try:
        time.sleep(delay)
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []

        data = resp.json()
        if not isinstance(data, list):
            return []

        for entry in data:
            # Extract common name
            common_name = entry.get("common_name", "")
            if common_name:
                # Handle wildcard certs
                if common_name.startswith("*."):
                    base = common_name[2:]
                    subdomains.add(base)
                    # Also add the base domain
                    for suffix in ["www", "mail", "api", "admin", "dev"]:
                        subdomains.add(f"{suffix}.{base}")
                else:
                    subdomains.add(common_name.lower())

            # Extract subject alternative names
            san = entry.get("name_value", "")
            if san:
                for name in san.split("\n"):
                    name = name.strip().lower()
                    if name and name.endswith(f".{domain}"):
                        if name.startswith("*."):
                            base = name[2:]
                            subdomains.add(base)
                        else:
                            subdomains.add(name)

    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
            requests.exceptions.RequestException, ValueError, Exception):
        pass

    # Filter to only include valid subdomains of the target domain
    filtered = set()
    for sub in subdomains:
        sub = sub.strip().lower()
        if sub and (sub == domain or sub.endswith(f".{domain}")):
            # Basic validation
            if all(c.isalnum() or c in "-." for c in sub) and len(sub) <= 253:
                filtered.add(sub)

    return sorted(filtered)
