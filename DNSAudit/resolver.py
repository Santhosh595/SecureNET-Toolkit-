#!/usr/bin/env python3
"""
DNSAudit DNS Resolution Engine
================================
Core DNS query engine for the DNSAudit tool. Provides DNS resolution with
multi-resolver comparison for hijacking detection, caching, IDN support,
and comprehensive audit logging.

Requirements:
    pip install dnspython
"""

import time
import logging
import json
import os
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone

import dns.resolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.message
import dns.query
import dns.flags

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 5.0  # seconds per query
MAX_RETRIES = 3
RETRY_BACKOFF = 0.5  # seconds between retries
RATE_LIMIT_DELAY = 0.2  # 200ms between queries

WELL_KNOWN_RESOLVERS = {
    "8.8.8.8": "Google (8.8.8.8)",
    "8.8.4.4": "Google (8.8.4.4)",
    "1.1.1.1": "Cloudflare (1.1.1.1)",
    "1.0.0.1": "Cloudflare (1.0.0.1)",
    "9.9.9.9": "Quad9 (9.9.9.9)",
    "149.112.112.112": "Quad9 (149.112.112.112)",
    "208.67.222.222": "OpenDNS (208.67.222.222)",
    "208.67.220.220": "OpenDNS (208.67.220.220)",
}

DEFAULT_COMPARISON_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

AUDIT_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_logs")

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("dnsaudit.resolver")
logger.setLevel(logging.DEBUG)

# Console handler
_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.INFO)
_console_fmt = logging.Formatter("[%(levelname)s] %(message)s")
_console_handler.setFormatter(_console_fmt)
logger.addHandler(_console_handler)


def setup_file_logger(log_dir: str = AUDIT_LOG_DIR) -> logging.FileHandler:
    """Create a file handler for the audit trail."""
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(log_dir, f"dns_audit_{timestamp}.log")
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return fh


# ---------------------------------------------------------------------------
# Data Classes & Enums
# ---------------------------------------------------------------------------

class ResponseStatus(Enum):
    """Status codes for DNS query responses."""
    SUCCESS = "SUCCESS"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"
    TIMEOUT = "TIMEOUT"
    NOANSWER = "NOANSWER"
    NOAUTH = "NOAUTH"
    REFUSED = "REFUSED"
    ERROR = "ERROR"


@dataclass
class DNSAnswer:
    """Represents a single DNS answer record."""
    rrtype: str
    rdata: str
    ttl: int
    rrclass: str = "IN"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DNSResponse:
    """Complete DNS response for a query."""
    domain: str
    query_name: str  # actual queried name (may differ for IDN)
    rrtype: str
    resolver: str
    status: ResponseStatus
    answers: List[DNSAnswer] = field(default_factory=list)
    query_time_ms: float = 0.0
    timestamp: str = ""
    error_message: str = ""
    raw_wire: str = ""  # base64-encoded raw wire format
    attempt: int = 1

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @property
    def rdata_values(self) -> List[str]:
        """Extract just the rdata strings from answers."""
        return [a.rdata for a in self.answers]


@dataclass
class ComparisonResult:
    """Result of comparing DNS responses across multiple resolvers."""
    domain: str
    rrtype: str
    responses: List[DNSResponse] = field(default_factory=list)
    hijacking_detected: bool = False
    hijacking_details: List[str] = field(default_factory=list)
    consensus: Optional[str] = None  # most common answer set
    divergence_count: int = 0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "rrtype": self.rrtype,
            "responses": [r.to_dict() for r in self.responses],
            "hijacking_detected": self.hijacking_detected,
            "hijacking_details": self.hijacking_details,
            "consensus": self.consensus,
            "divergence_count": self.divergence_count,
        }


# ---------------------------------------------------------------------------
# Domain Normalization
# ---------------------------------------------------------------------------

def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name:
    - Strip whitespace
    - Convert to lowercase
    - Strip trailing dot
    - Handle IDN/punycode (encode if needed)
    """
    if not domain:
        raise ValueError("Domain cannot be empty")

    domain = domain.strip().lower().rstrip(".")

    # Validate and handle IDN
    try:
        # Try to encode as IDNA (handles internationalized domains)
        domain_encoded = domain.encode("idna").decode("ascii")
        return domain_encoded
    except (UnicodeError, UnicodeDecodeError, idna_error):
        # If IDNA encoding fails, try manual puncode handling
        if domain.startswith("xn--"):
            return domain
        # Re-raise with helpful message
        raise ValueError(f"Invalid domain name (IDN encoding failed): {domain}")


def decode_punycode(domain: str) -> str:
    """Decode a punycode domain to its Unicode representation."""
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:
        return domain


# IDNA import handling
try:
    import idna
    idna_error = idna.IDNAError
except ImportError:
    idna_error = UnicodeError


# ---------------------------------------------------------------------------
# DNS Response Cache
# ---------------------------------------------------------------------------

class DNSCache:
    """
    In-memory DNS response cache for the session.
    Keyed by (domain, rrtype, resolver) with TTL-based expiration.
    """

    def __init__(self):
        self._cache: Dict[str, Tuple[DNSResponse, float]] = {}
        self._hits = 0
        self._misses = 0

    def _make_key(self, domain: str, rrtype: str, resolver: str) -> str:
        raw = f"{domain}|{rrtype}|{resolver}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, domain: str, rrtype: str, resolver: str) -> Optional[DNSResponse]:
        key = self._make_key(domain, rrtype, resolver)
        if key in self._cache:
            response, cached_at = self._cache[key]
            # Check if cache entry is still valid (use min TTL of 60s or actual)
            min_ttl = min((a.ttl for a in response.answers), default=60)
            if time.time() - cached_at < min_ttl:
                self._hits += 1
                logger.debug("Cache HIT for %s %s @ %s", domain, rrtype, resolver)
                return response
            else:
                # Expired
                del self._cache[key]
        self._misses += 1
        return None

    def put(self, domain: str, rrtype: str, resolver: str, response: DNSResponse):
        key = self._make_key(domain, rrtype, resolver)
        self._cache[key] = (response, time.time())
        logger.debug("Cache PUT for %s %s @ %s", domain, rrtype, resolver)

    def clear(self):
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    @property
    def stats(self) -> dict:
        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / max(1, self._hits + self._misses),
        }


# ---------------------------------------------------------------------------
# DNS Resolver Engine
# ---------------------------------------------------------------------------

class DNSResolverEngine:
    """
    Core DNS resolution engine with multi-resolver comparison,
    caching, and audit logging.
    """

    def __init__(
        self,
        resolver_ip: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
        rate_limit_delay: float = RATE_LIMIT_DELAY,
        enable_audit_log: bool = True,
        audit_log_dir: str = AUDIT_LOG_DIR,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit_delay = rate_limit_delay
        self.cache = DNSCache()
        self._last_query_time = 0.0

        # Setup audit logging
        if enable_audit_log:
            setup_file_logger(audit_log_dir)

        # Configure resolver
        self.resolver_ip = resolver_ip or self._get_system_resolver()
        self._resolver_name = WELL_KNOWN_RESOLVERS.get(self.resolver_ip, self.resolver_ip)

        # Initialize dnspython resolver
        self._resolver = dns.resolver.Resolver()
        self._resolver.nameservers = [self.resolver_ip]
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout * 2  # total lifetime for retries

        logger.info(
            "DNSResolverEngine initialized | resolver: %s (%s) | timeout: %.1fs | retries: %d",
            self.resolver_ip,
            self._resolver_name,
            self.timeout,
            self.max_retries,
        )

    @staticmethod
    def _get_system_resolver() -> str:
        """Get the system's default DNS resolver."""
        try:
            resolver = dns.resolver.Resolver()
            if resolver.nameservers:
                return resolver.nameservers[0]
        except Exception:
            pass
        logger.warning("Could not detect system resolver, falling back to 8.8.8.8")
        return "8.8.8.8"

    def _rate_limit(self):
        """Enforce rate limiting between queries."""
        now = time.time()
        elapsed = now - self._last_query_time
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            time.sleep(sleep_time)
        self._last_query_time = time.time()

    def _classify_exception(self, exc: Exception) -> Tuple[ResponseStatus, str]:
        """Classify a DNS exception into a ResponseStatus."""
        if isinstance(exc, dns.resolver.NXDOMAIN):
            return ResponseStatus.NXDOMAIN, str(exc)
        elif isinstance(exc, dns.resolver.NoNameservers):
            return ResponseStatus.SERVFAIL, str(exc)
        elif isinstance(exc, dns.exception.Timeout):
            return ResponseStatus.TIMEOUT, str(exc)
        elif isinstance(exc, dns.resolver.NoAnswer):
            return ResponseStatus.NOANSWER, str(exc)
        elif isinstance(exc, dns.resolver.NXDOMAIN):
            return ResponseStatus.NXDOMAIN, str(exc)
        else:
            return ResponseStatus.ERROR, f"{type(exc).__name__}: {exc}"

    def _build_raw_wire(self, response: dns.message.Message) -> str:
        """Encode raw DNS wire format for audit trail."""
        import base64
        try:
            wire = response.to_wire()
            return base64.b64encode(wire).decode("ascii")
        except Exception:
            return ""

    def query(
        self,
        domain: str,
        rrtype: str = "A",
        resolver_ip: Optional[str] = None,
        use_cache: bool = True,
    ) -> DNSResponse:
        """
        Perform a DNS query with retries and caching.

        Args:
            domain: Domain name to query
            rrtype: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, etc.)
            resolver_ip: Override resolver IP (uses default if None)
            use_cache: Whether to use the response cache

        Returns:
            DNSResponse object with results
        """
        # Normalize domain
        norm_domain = normalize_domain(domain)
        rrtype = rrtype.upper().strip()

        # Determine resolver
        target_resolver = resolver_ip or self.resolver_ip

        # Check cache
        if use_cache:
            cached = self.cache.get(norm_domain, rrtype, target_resolver)
            if cached is not None:
                logger.info("Cache hit: %s %s @ %s", norm_domain, rrtype, target_resolver)
                return cached

        # Create a temporary resolver if overriding
        if resolver_ip and resolver_ip != self.resolver_ip:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout * 2
        else:
            resolver = self._resolver

        # Perform query with retries
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            self._rate_limit()
            start_time = time.time()

            try:
                logger.debug(
                    "Querying %s %s @ %s (attempt %d/%d)",
                    norm_domain, rrtype, target_resolver, attempt, self.max_retries
                )

                answer = resolver.resolve(norm_domain, rrtype)
                elapsed_ms = (time.time() - start_time) * 1000

                # Build response
                dns_answers = []
                for rdata in answer:
                    rr = DNSAnswer(
                        rrtype=rrtype,
                        rdata=str(rdata),
                        ttl=answer.rrset.ttl if answer.rrset else 0,
                        rrclass=dns.rdataclass.to_text(
                            answer.rrset.rdclass if answer.rrset else dns.rdataclass.IN
                        ),
                    )
                    dns_answers.append(dns)

                response = DNSResponse(
                    domain=domain,
                    query_name=norm_domain,
                    rrtype=rrtype,
                    resolver=target_resolver,
                    status=ResponseStatus.SUCCESS,
                    answers=dns_answers,
                    query_time_ms=round(elapsed_ms, 2),
                    attempt=attempt,
                )

                # Cache successful response
                if use_cache:
                    self.cache.put(norm_domain, rrtype, target_resolver, response)

                # Log the raw response
                logger.info(
                    "DNS %s %s @ %s -> %s (%.1fms, attempt %d)",
                    norm_domain,
                    rrtype,
                    target_resolver,
                    ", ".join(response.rdata_values) if response.rdata_values else "NO DATA",
                    elapsed_ms,
                    attempt,
                )
                logger.debug("Raw response: %s", response.to_dict())

                return response

            except Exception as e:
                elapsed_ms = (time.time() - start_time) * 1000
                last_error = e
                status, msg = self._classify_exception(e)

                logger.warning(
                    "DNS query failed: %s %s @ %s | status=%s | attempt=%d/%d | %.1fms | %s",
                    norm_domain, rrtype, target_resolver, status.value,
                    attempt, self.max_retries, elapsed_ms, msg,
                )

                # Don't retry on NXDOMAIN (definitive answer)
                if status == ResponseStatus.NXDOMAIN:
                    break

                # Backoff before retry
                if attempt < self.max_retries:
                    time.sleep(RETRY_BACKOFF * attempt)

        # All retries exhausted
        status, error_msg = self._classify_exception(last_error) if last_error else (ResponseStatus.ERROR, "Unknown error")
        response = DNSResponse(
            domain=domain,
            query_name=norm_domain,
            rrtype=rrtype,
            resolver=target_resolver,
            status=status,
            query_time_ms=round(elapsed_ms, 2),
            error_message=error_msg,
            attempt=self.max_retries,
        )

        logger.error(
            "DNS query exhausted retries: %s %s @ %s | status=%s",
            norm_domain, rrtype, target_resolver, status.value,
        )
        return response

    def query_multiple(
        self,
        domain: str,
        rrtype: str = "A",
        resolvers: Optional[List[str]] = None,
    ) -> List[DNSResponse]:
        """
        Query a domain against multiple resolvers.

        Args:
            domain: Domain name to query
            rrtype: DNS record type
            resolvers: List of resolver IPs (default: comparison resolvers)

        Returns:
            List of DNSResponse objects
        """
        target_resolvers = resolvers or DEFAULT_COMPARISON_RESOLVERS
        results = []

        for resolver_ip in target_resolvers:
            resp = self.query(domain, rrtype, resolver_ip=resolver_ip)
            results.append(resp)

        return results

    def compare_resolvers(
        self,
        domain: str,
        rrtype: str = "A",
        resolvers: Optional[List[str]] = None,
    ) -> ComparisonResult:
        """
        Compare DNS responses across multiple resolvers to detect hijacking.

        Args:
            domain: Domain name to query
            rrtype: DNS record type
            resolvers: List of resolver IPs to compare

        Returns:
            ComparisonResult with hijacking analysis
        """
        responses = self.query_multiple(domain, rrtype, resolvers)

        comparison = ComparisonResult(
            domain=domain,
            rrtype=rrtype,
            responses=responses,
        )

        # Analyze for hijacking
        successful_responses = [r for r in responses if r.status == ResponseStatus.SUCCESS]

        if len(successful_responses) < 2:
            # Not enough data to compare
            if not successful_responses:
                comparison.hijacking_details.append("No successful responses from any resolver")
            else:
                comparison.hijacking_details.append("Only one resolver returned successful response - insufficient for comparison")
            return comparison

        # Group responses by their answer sets
        answer_groups: Dict[str, List[DNSResponse]] = {}
        for resp in successful_responses:
            key = "|".join(sorted(resp.rdata_values))
            if key not in answer_groups:
                answer_groups[key] = []
            answer_groups[key].append(resp)

        # Determine consensus (largest group)
        consensus_key = max(answer_groups.keys(), key=lambda k: len(answer_groups[k]))
        consensus_responses = answer_groups[consensus_key]
        comparison.consensus = consensus_key

        # Check for divergence
        divergent_responses = [r for r in successful_responses if r not in consensus_responses]
        comparison.divergence_count = len(divergent_responses)

        if divergent_responses:
            comparison.hijacking_detected = True
            for div_resp in divergent_responses:
                detail = (
                    f"Hijacking suspected: resolver {div_resp.resolver} returned "
                    f"{div_resp.rdata_values} (consensus: {consensus_key})"
                )
                comparison.hijacking_details.append(detail)
                logger.warning(
                    "HIJACKING DETECTED: %s %s @ %s -> %s (diverges from consensus: %s)",
                    domain, rrtype, div_resp.resolver,
                    div_resp.rdata_values, consensus_key,
                )
        else:
            # Check for NXDOMAIN inconsistency
            nxdomain_responses = [r for r in responses if r.status == ResponseStatus.NXDOMAIN]
            if nxdomain_responses and successful_responses:
                comparison.hijacking_detected = True
                for nx_resp in nxdomain_responses:
                    detail = (
                        f"NXDOMAIN inconsistency: {nx_resp.resolver} returned NXDOMAIN "
                        f"while others returned successful answers"
                    )
                    comparison.hijacking_details.append(detail)

        # Check for SERVFAIL inconsistency
        servfail_responses = [r for r in responses if r.status == ResponseStatus.SERVFAIL]
        if servfail_responses and successful_responses:
            for sf_resp in servfail_responses:
                detail = (
                    f"SERVFAIL from {sf_resp.resolver} while others succeeded - possible filtering"
                )
                comparison.hijacking_details.append(detail)

        logger.info(
            "Comparison for %s %s: hijacking=%s, divergences=%d, consensus=%s",
            domain, rrtype, comparison.hijacking_detected,
            comparison.divergence_count, comparison.consensus,
        )

        return comparison

    def detect_hijacking(
        self,
        domain: str,
        rrtype: str = "A",
        resolvers: Optional[List[str]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Simplified hijacking detection.

        Returns:
            Tuple of (is_hijacked, details_list)
        """
        result = self.compare_resolvers(domain, rrtype, resolvers)
        return result.hijacking_detected, result.hijacking_details

    def bulk_query(
        self,
        domains: List[str],
        rrtype: str = "A",
        resolvers: Optional[List[str]] = None,
    ) -> List[DNSResponse]:
        """
        Query multiple domains against resolvers.

        Args:
            domains: List of domain names
            rrtype: DNS record type
            resolvers: List of resolver IPs

        Returns:
            List of DNSResponse objects
        """
        results = []
        target_resolvers = resolvers or [self.resolver_ip]

        for domain in domains:
            for resolver_ip in target_resolvers:
                resp = self.query(domain, rrtype, resolver_ip=resolver_ip)
                results.append(resp)

        return results

    def export_audit_log(self, filepath: str):
        """Export the current session's audit data to a JSON file."""
        audit_data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "resolver": self.resolver_ip,
            "resolver_name": self._resolver_name,
            "cache_stats": self.cache.stats,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(audit_data, f, indent=2)
        logger.info("Audit log exported to %s", filepath)

    @property
    def cache_stats(self) -> dict:
        return self.cache.stats


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

def resolve_domain(
    domain: str,
    rrtype: str = "A",
    resolver: Optional[str] = None,
) -> DNSResponse:
    """
    Quick convenience function for a single DNS query.

    Args:
        domain: Domain to resolve
        rrtype: Record type (default: A)
        resolver: Resolver IP (default: system)

    Returns:
        DNSResponse
    """
    engine = DNSResolverEngine(resolver_ip=resolver, enable_audit_log=False)
    return engine.query(domain, rrtype)


def check_hijacking(
    domain: str,
    rrtype: str = "A",
    resolvers: Optional[List[str]] = None,
) -> ComparisonResult:
    """
    Quick convenience function for hijacking detection.

    Args:
        domain: Domain to check
        rrtype: Record type (default: A)
        resolvers: List of resolver IPs to compare

    Returns:
        ComparisonResult
    """
    engine = DNSResolverEngine(enable_audit_log=False)
    return engine.compare_resolvers(domain, rrtype, resolvers)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    """Command-line interface for the DNS resolver engine."""
    import argparse

    parser = argparse.ArgumentParser(
        description="DNSAudit DNS Resolution Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --type MX --resolver 8.8.8.8
  %(prog)s example.com --compare
  %(prog)s example.com --compare --resolvers 8.8.8.8 1.1.1.1 9.9.9.9
  %(prog)s --bulk domains.txt --compare
        """,
    )
    parser.add_argument("domain", nargs="?", help="Domain to query")
    parser.add_argument("--type", "-t", default="A", help="DNS record type (default: A)")
    parser.add_argument(
        "--resolver", "-r", default=None,
        help="DNS resolver IP (default: system, or 8.8.8.8/1.1.1.1/9.9.9.9)",
    )
    parser.add_argument(
        "--compare", "-c", action="store_true",
        help="Compare results across multiple resolvers for hijacking detection",
    )
    parser.add_argument(
        "--resolvers", nargs="+", default=None,
        help="Resolver IPs to compare (default: 8.8.8.8 1.1.1.1 9.9.9.9)",
    )
    parser.add_argument(
        "--bulk", "-b", default=None,
        help="File containing domains to query (one per line)",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"Query timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Disable response caching",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--audit-log-dir", default=AUDIT_LOG_DIR,
        help="Directory for audit log files",
    )

    args = parser.parse_args()

    if not args.domain and not args.bulk:
        parser.error("Either a domain or --bulk <file> is required")

    # Setup logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)

    # Initialize engine
    engine = DNSResolverEngine(
        resolver_ip=args.resolver,
        timeout=args.timeout,
        enable_audit_log=True,
        audit_log_dir=args.audit_log_dir,
    )

    # Bulk mode
    if args.bulk:
        with open(args.bulk, "r") as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        logger.info("Bulk query mode: %d domains", len(domains))
        results = engine.bulk_query(domains, args.type, args.resolvers)

        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            for resp in results:
                status_icon = "✓" if resp.status == ResponseStatus.SUCCESS else "✗"
                print(
                    f"{status_icon} {resp.query_name} {resp.rrtype} @ {resp.resolver} "
                    f"-> {resp.rdata_values or resp.status.value} ({resp.query_time_ms:.0f}ms)"
                )
        return

    # Single domain mode
    if args.compare:
        result = engine.compare_resolvers(args.domain, args.type, args.resolvers)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"DNS Hijacking Check: {args.domain} ({args.type})")
            print(f"{'='*60}")

            for resp in result.responses:
                status_icon = "✓" if resp.status == ResponseStatus.SUCCESS else "✗"
                print(
                    f"  {status_icon} {resp.resolver:18s} -> "
                    f"{resp.rdata_values or resp.status.value:30s} "
                    f"({resp.query_time_ms:.0f}ms)"
                )

            print(f"\n{'─'*60}")
            if result.hijacking_detected:
                print(f"  ⚠ HIJACKING DETECTED ({len(result.hijacking_details)} issues)")
                for detail in result.hijacking_details:
                    print(f"    • {detail}")
            else:
                print(f"  ✓ No hijacking detected (consensus: {result.consensus})")
            print(f"{'='*60}\n")
    else:
        resp = engine.query(args.domain, args.type, use_cache=not args.no_cache)

        if args.json:
            print(json.dumps(resp.to_dict(), indent=2))
        else:
            status_icon = "✓" if resp.status == ResponseStatus.SUCCESS else "✗"
            print(f"\n{status_icon} {resp.query_name} ({resp.rrtype})")
            print(f"  Resolver: {resp.resolver}")
            print(f"  Status:   {resp.status.value}")
            print(f"  Time:     {resp.query_time_ms:.1f}ms")
            if resp.answers:
                print(f"  Answers:")
                for ans in resp.answers:
                    print(f"    {ans.rrtype} {ans.rdata} (TTL: {ans.ttl})")
            if resp.error_message:
                print(f"  Error:    {resp.error_message}")
            print()

    # Print cache stats
    if args.verbose:
        stats = engine.cache_stats
        logger.debug("Cache stats: size=%d, hits=%d, misses=%d, hit_rate=%.2f%%",
                      stats["size"], stats["hits"], stats["misses"], stats["hit_rate"] * 100)


if __name__ == "__main__":
    main()
