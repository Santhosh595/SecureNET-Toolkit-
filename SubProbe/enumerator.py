"""SubProbe — Core subdomain enumeration engine.

Orchestrates wordlist brute-force, CT log queries, and DNS record analysis.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import dns.resolver

from resolver import resolve_and_check, check_wildcard_dns
from ctlogs import query_crtsh


DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlists", "subdomains.txt")


def load_wordlist(path: str) -> list[str]:
    """Load a wordlist file (one word per line)."""
    words = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.append(word)
    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist not found: {path}")
    return words


def enumerate_wordlist(
    domain: str,
    words: list[str],
    wildcard_ip: Optional[str],
    max_workers: int = 100,
    progress_callback=None,
) -> list[dict]:
    """Enumerate subdomains via wordlist brute-force.

    Args:
        domain: Target domain.
        words: List of subdomain prefixes.
        wildcard_ip: Wildcard IP to filter out (or None).
        max_workers: Thread pool size.
        progress_callback: Called with (found, total) periodically.

    Returns:
        List of result dicts.
    """
    results = []
    found_count = 0
    total = len(words)

    def check_word(word: str) -> Optional[dict]:
        subdomain = f"{word}.{domain}"
        info = resolve_and_check(subdomain)
        if info["ip"]:
            # Filter wildcard
            if wildcard_ip and info["ip"] == wildcard_ip:
                return None
            interesting = info["http_status"] in (200, 403)
            return {
                "subdomain": subdomain,
                "ip": info["ip"],
                "http_status": info["http_status"],
                "status": info["status"],
                "source": "WORDLIST",
                "interesting": interesting,
            }
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_word, w): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
            found_count += 1
            if progress_callback and found_count % 50 == 0:
                progress_callback(found_count, total)

    if progress_callback:
        progress_callback(total, total)

    return results


def enumerate_ct_logs(domain: str) -> list[dict]:
    """Enumerate subdomains via Certificate Transparency logs."""
    results = []
    subdomains = query_crtsh(domain)
    for sub in subdomains:
        info = resolve_and_check(sub)
        if info["ip"]:
            interesting = info["http_status"] in (200, 403)
            results.append({
                "subdomain": sub,
                "ip": info["ip"],
                "http_status": info["http_status"],
                "status": info["status"],
                "source": "CT_LOG",
                "interesting": interesting,
            })
    return results


def enumerate_dns_records(domain: str) -> list[dict]:
    """Enumerate subdomains via DNS record analysis."""
    results = []
    subdomains_seen = set()

    record_types = ["MX", "NS", "TXT", "CNAME", "A"]
    for rtype in record_types:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(domain, rtype)
            for answer in answers:
                target = str(answer).rstrip(".")
                # Extract hostname from MX (priority target)
                if rtype == "MX":
                    parts = target.split()
                    if len(parts) >= 2:
                        target = parts[1].rstrip(".")
                # Extract hostname from NS
                elif rtype == "NS":
                    target = target.rstrip(".")

                if target != domain and target.endswith(f".{domain}"):
                    subdomains_seen.add(target.lower())
        except Exception:
            pass

    for sub in sorted(subdomains_seen):
        info = resolve_and_check(sub)
        if info["ip"]:
            interesting = info["http_status"] in (200, 403)
            results.append({
                "subdomain": sub,
                "ip": info["ip"],
                "http_status": info["http_status"],
                "status": info["status"],
                "source": "DNS_RECORD",
                "interesting": interesting,
            })

    return results


def enumerate_domain(
    domain: str,
    use_wordlist: bool = True,
    use_ct: bool = True,
    use_dns: bool = True,
    wordlist_path: Optional[str] = None,
    max_workers: int = 100,
    progress_callback=None,
) -> list[dict]:
    """Run full subdomain enumeration.

    Args:
        domain: Target domain.
        use_wordlist: Enable wordlist brute-force.
        use_ct: Enable CT log queries.
        use_dns: Enable DNS record analysis.
        wordlist_path: Custom wordlist file path.
        max_workers: Thread pool size for wordlist.
        progress_callback: Called with (current, total) during wordlist scan.

    Returns:
        List of unique result dicts.
    """
    domain = domain.lower().strip()

    # Validate domain
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.resolve(domain, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
        raise ValueError(f"Domain does not exist or has no DNS records: {domain}")

    # Check wildcard
    is_wildcard, wildcard_ip = check_wildcard_dns(domain)
    if is_wildcard:
        pass  # Will filter later

    all_results = []

    # Method 1: Wordlist
    if use_wordlist:
        wl_path = wordlist_path or DEFAULT_WORDLIST
        words = load_wordlist(wl_path)
        wl_results = enumerate_wordlist(domain, words, wildcard_ip, max_workers, progress_callback)
        all_results.extend(wl_results)

    # Method 2: CT Logs
    if use_ct:
        ct_results = enumerate_ct_logs(domain)
        all_results.extend(ct_results)

    # Method 3: DNS Records
    if use_dns:
        dns_results = enumerate_dns_records(domain)
        all_results.extend(dns_results)

    # Deduplicate by subdomain (keep first seen)
    seen = set()
    deduped = []
    for r in all_results:
        sub = r["subdomain"].lower()
        if sub not in seen:
            seen.add(sub)
            deduped.append(r)

    return deduped
