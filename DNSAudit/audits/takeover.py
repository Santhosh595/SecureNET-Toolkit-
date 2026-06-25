#!/usr/bin/env python3
"""
DNSAudit - Subdomain Takeover Detection Module (Category 6)

Detects vulnerable subdomain takeovers by:
1. Enumerating common subdomains via a 200-word wordlist
2. Resolving CNAME records for each subdomain
3. Checking if CNAME targets point to known external services
4. Verifying if those external services are unclaimed/vulnerable

Vulnerable services covered:
- AWS S3 (*.s3.amazonaws.com)
- AWS CloudFront (*.cloudfront.net)
- GitHub Pages (*.github.io)
- Heroku (*.herokuapp.com)
- Netlify (*.netlify.app)
- Vercel (*.vercel.app)
- Azure (*.azurewebsites.net)
- Shopify (*.myshopify.com)
- Fastly (*.fastly.net)
- Pantheon (*.pantheonsite.io)
- Ghost (*.ghost.io)
- Surge.sh (*.surge.sh)
- Sendgrid
- Desk.com
- Zendesk (*.zendesk.com)
"""

import dns.resolver
import dns.exception
import requests
import socket
import time
import json
import sys
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum


# ─── Data Models ───────────────────────────────────────────────────────────────

class TakeoverVerdict(Enum):
    YES = "YES"
    NO = "NO"
    MAYBE = "MAYBE"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class TakeoverFinding:
    subdomain: str
    cname_target: Optional[str]
    service_identified: Optional[str]
    takeover_possible: TakeoverVerdict
    evidence: str
    severity: Severity
    resolution_status: str = ""  # NXDOMAIN, NOERROR, SERVFAIL, etc.


@dataclass
class TakeoverReport:
    domain: str
    total_scanned: int
    cname_found: int
    potential_takeovers: int
    findings: List[TakeoverFinding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)


# ─── Subdomain Wordlist (200 entries) ─────────────────────────────────────────

SUBDOMAIN_WORDLIST = [
    # Common infrastructure
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "email", "owa",
    "autodiscover", "cpanel", "whm", "webdisk", "admin", "administrator",
    "portal", "dashboard", "panel", "control", "manage", "management",
    # Development & staging
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "sandbox", "demo", "preview", "beta", "alpha", "gamma", "canary",
    "build", "ci", "cd", "jenkins", "gitlab", "git", "svn", "cvs",
    # Cloud & hosting
    "cloud", "aws", "azure", "gcp", "s3", "cdn", "static", "assets", "media",
    "img", "image", "images", "video", "download", "downloads", "upload",
    "storage", "bucket", "repo", "repository", "registry", "docker",
    # Services & apps
    "api", "api1", "api2", "app", "apps", "application", "service", "services",
    "backend", "frontend", "server", "server1", "server2", "host", "host1",
    "node", "node1", "node2", "worker", "job", "task", "queue", "cache",
    "redis", "db", "database", "mysql", "postgres", "mongo", "elasticsearch",
    "search", "solr", "analytics", "metrics", "monitor", "monitoring",
    "grafana", "prometheus", "kibana", "logs", "log", "status", "health",
    "ping", "uptime", "stats", "statistics", "report", "reports",
    # Business & departments
    "corp", "corporate", "internal", "intranet", "extranet", "vpn", "remote",
    "office", "branch", "store", "shop", "cart", "checkout", "payment",
    "billing", "invoice", "account", "accounts", "user", "users", "member",
    "members", "client", "clients", "customer", "customers", "partner",
    "partners", "vendor", "vendors", "supplier", "hr", "finance", "legal",
    "support", "help", "helpdesk", "ticket", "tickets", "wiki", "docs",
    "documentation", "kb", "knowledge", "knowledgebase", "forum", "forums",
    "community", "blog", "news", "press", "media", "events", "event",
    "conference", "webinar", "training", "learn", "education", "academy",
    "careers", "jobs", "hr", "people", "team", "about", "contact", "info",
    # Security & auth
    "auth", "sso", "login", "signin", "signup", "register", "oauth",
    "secure", "ssl", "tls", "cert", "certificate", "firewall", "waf",
    "security", "scan", "audit", "compliance", "pentest", "bugbounty",
    # Misc common
    "old", "new", "v1", "v2", "v3", "2019", "2020", "2021", "2022", "2023",
    "2024", "2025", "2026", "backup", "bak", "archive", "archives", "temp",
    "tmp", "staging1", "staging2", "dev1", "dev2", "test1", "test2",
    "prod", "production", "live", "www2", "www3", "en", "fr", "de", "es",
    "jp", "cn", "ru", "br", "au", "uk", "us", "eu", "asia", "na", "sa",
]


# ─── Vulnerable Service Signatures ────────────────────────────────────────────

@dataclass
class VulnerableService:
    name: str
    cname_patterns: List[str]  # suffixes to match against CNAME
    nxdomain_indicator: bool = True  # NXDOMAIN on CNAME = vulnerable
    http_check_url: Optional[str] = None  # URL pattern to check for unclaimed
    http_unclaimed_text: Optional[List[str]] = None  # text indicating unclaimed
    severity: Severity = Severity.CRITICAL


VULNERABLE_SERVICES = [
    VulnerableService(
        name="AWS S3",
        cname_patterns=[".s3.amazonaws.com", ".s3-website"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["NoSuchBucket", "The specified bucket does not exist"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="AWS CloudFront",
        cname_patterns=[".cloudfront.net"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["Bad request", "ERROR: Invalid request"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="GitHub Pages",
        cname_patterns=[".github.io", ".github.io."],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["404", "There isn't a GitHub Pages site here", "Page not found"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Heroku",
        cname_patterns=[".herokuapp.com", ".herokudns.com"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["No such app", "There is no app configured at this address"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Netlify",
        cname_patterns=[".netlify.app", ".netlify.com"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["Not Found", "The requested site does not exist"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Vercel",
        cname_patterns=[".vercel.app", ".now.sh"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["The deployment could not be found", "404", "NOT_FOUND"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Azure",
        cname_patterns=[".azurewebsites.net", ".cloudapp.net", ".blob.core.windows.net"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["404 Web Site not found", "Error 404 - Web app not found"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Shopify",
        cname_patterns=[".myshopify.com"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["Sorry, this shop is currently unavailable", "Only one step left"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Fastly",
        cname_patterns=[".fastly.net", ".fastlylb.net"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["Fastly error: unknown domain"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Pantheon",
        cname_patterns=[".pantheonsite.io", ".pantheon.io", ".gotpantheon.com"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["404 error unknown site"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Ghost",
        cname_patterns=[".ghost.io"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["Site not found", "404"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Surge.sh",
        cname_patterns=[".surge.sh"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["project not found"],
        severity=Severity.CRITICAL,
    ),
    VulnerableService(
        name="Sendgrid",
        cname_patterns=["sendgrid.net"],
        nxdomain_indicator=True,
        severity=Severity.HIGH,
    ),
    VulnerableService(
        name="Desk.com",
        cname_patterns=[".desk.com", ".zendesk.com"],
        nxdomain_indicator=True,
        severity=Severity.HIGH,
    ),
    VulnerableService(
        name="Zendesk",
        cname_patterns=[".zendesk.com"],
        nxdomain_indicator=True,
        http_check_url="http://{target}",
        http_unclaimed_text=["Account not found", "Help Center Closed"],
        severity=Severity.HIGH,
    ),
]


# ─── DNS Resolution ───────────────────────────────────────────────────────────

def resolve_cname(domain: str, nameservers: Optional[List[str]] = None) -> Tuple[Optional[str], str]:
    """
    Resolve the CNAME record for a given domain.
    Returns (cname_target, status) where status is DNS resolution status.
    """
    try:
        resolver = dns.resolver.Resolver()
        if nameservers:
            resolver.nameservers = nameservers
        resolver.timeout = 5
        resolver.lifetime = 10

        answer = resolver.resolve(domain, 'CNAME')
        cname = str(answer[0].target).rstrip('.')
        return cname, "NOERROR"
    except dns.resolver.NXDOMAIN:
        return None, "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return None, "NO_ANSWER"
    except dns.resolver.NoNameservers:
        return None, "NO_NAMESERVERS"
    except dns.exception.Timeout:
        return None, "TIMEOUT"
    except Exception as e:
        return None, f"ERROR: {str(e)}"


def resolve_a(domain: str, nameservers: Optional[List[str]] = None) -> Tuple[Optional[List[str]], str]:
    """
    Resolve A records for a domain.
    Returns (list_of_ips, status).
    """
    try:
        resolver = dns.resolver.Resolver()
        if nameservers:
            resolver.nameservers = nameservers
        resolver.timeout = 5
        resolver.lifetime = 10

        answer = resolver.resolve(domain, 'A')
        ips = [str(rdata) for rdata in answer]
        return ips, "NOERROR"
    except dns.resolver.NXDOMAIN:
        return None, "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return None, "NO_ANSWER"
    except dns.exception.Timeout:
        return None, "TIMEOUT"
    except Exception as e:
        return None, f"ERROR: {str(e)}"


# ─── Service Identification ───────────────────────────────────────────────────

def identify_service(cname: str) -> Optional[VulnerableService]:
    """
    Check if a CNAME target matches any known vulnerable service pattern.
    """
    cname_lower = cname.lower()
    for service in VULNERABLE_SERVICES:
        for pattern in service.cname_patterns:
            if cname_lower.endswith(pattern.lower()):
                return service
    return None


# ─── Takeover Verification ────────────────────────────────────────────────────

def check_nxdomain(domain: str, nameservers: Optional[List[str]] = None) -> bool:
    """
    Check if a domain returns NXDOMAIN.
    """
    try:
        resolver = dns.resolver.Resolver()
        if nameservers:
            resolver.nameservers = nameservers
        resolver.timeout = 5
        resolver.lifetime = 10
        resolver.resolve(domain, 'A')
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


def check_http_unclaimed(service: VulnerableService, target: str) -> Tuple[bool, str]:
    """
    Check if an HTTP endpoint shows signs of being unclaimed.
    Returns (is_unclaimed, evidence).
    """
    if not service.http_check_url:
        return False, "No HTTP check configured for this service"

    url = service.http_check_url.format(target=target)
    try:
        response = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "DNSAudit/1.0"})
        body = response.status_code
        text = response.text.lower()

        if service.http_unclaimed_text:
            for indicator in service.http_unclaimed_text:
                if indicator.lower() in text:
                    return True, f"HTTP {response.status_code}: Found unclaimed indicator '{indicator}' in response"

        # Check for specific status codes that suggest unclaimed
        if response.status_code == 404:
            return True, f"HTTP 404: Service endpoint returned not found"

        return False, f"HTTP {response.status_code}: Service appears claimed/active"
    except requests.exceptions.ConnectionError:
        return True, "Connection refused/reset - service may be unclaimed"
    except requests.exceptions.Timeout:
        return False, "HTTP check timed out"
    except Exception as e:
        return False, f"HTTP check error: {str(e)}"


def verify_takeover(subdomain: str, cname: str, service: VulnerableService,
                    nameservers: Optional[List[str]] = None) -> TakeoverFinding:
    """
    Verify if a subdomain takeover is possible.
    """
    evidence_parts = []
    verdict = TakeoverVerdict.NO
    severity = Severity.INFO

    # Step 1: Check if the CNAME target itself resolves
    cname_ips, cname_status = resolve_a(cname, nameservers)

    if cname_status == "NXDOMAIN":
        evidence_parts.append(f"CNAME target '{cname}' returns NXDOMAIN")
        verdict = TakeoverVerdict.YES
        severity = service.severity
    elif cname_status == "TIMEOUT":
        evidence_parts.append(f"CNAME target '{cname}' resolution timed out")
        verdict = TakeoverVerdict.MAYBE
        severity = Severity.MEDIUM
    elif cname_ips:
        evidence_parts.append(f"CNAME target '{cname}' resolves to {', '.join(cname_ips)}")

        # Step 2: If CNAME resolves, check HTTP for unclaimed indicators
        if service.http_check_url:
            is_unclaimed, http_evidence = check_http_unclaimed(service, cname)
            evidence_parts.append(http_evidence)

            if is_unclaimed:
                verdict = TakeoverVerdict.YES
                severity = service.severity
            else:
                verdict = TakeoverVerdict.NO
                severity = Severity.LOW
        else:
            # No HTTP check available; rely on DNS resolution only
            verdict = TakeoverVerdict.NO
            severity = Severity.LOW
    else:
        evidence_parts.append(f"CNAME target '{cname}' status: {cname_status}")
        verdict = TakeoverVerdict.MAYBE
        severity = Severity.MEDIUM

    return TakeoverFinding(
        subdomain=subdomain,
        cname_target=cname,
        service_identified=service.name,
        takeover_possible=verdict,
        evidence="; ".join(evidence_parts),
        severity=severity,
        resolution_status=cname_status,
    )


# ─── Main Scanner ─────────────────────────────────────────────────────────────

def scan_subdomain(domain: str, subdomain: str,
                   nameservers: Optional[List[str]] = None) -> Optional[TakeoverFinding]:
    """
    Scan a single subdomain for takeover vulnerability.
    Returns a TakeoverFinding if the subdomain has a CNAME to a vulnerable service, else None.
    """
    fqdn = f"{subdomain}.{domain}"

    # Resolve CNAME
    cname, status = resolve_cname(fqdn, nameservers)

    if not cname:
        return None

    # Check if CNAME points to a vulnerable service
    service = identify_service(cname)
    if not service:
        return None

    # Verify takeover possibility
    finding = verify_takeover(fqdn, cname, service, nameservers)
    return finding


def run_takeover_scan(domain: str,
                      wordlist: Optional[List[str]] = None,
                      nameservers: Optional[List[str]] = None,
                      max_workers: int = 10,
                      rate_limit: float = 0.05) -> TakeoverReport:
    """
    Run a full subdomain takeover scan against a domain.

    Args:
        domain: Target domain to scan
        wordlist: Custom subdomain wordlist (defaults to built-in 200-word list)
        nameservers: Custom DNS nameservers
        max_workers: Number of concurrent threads
        rate_limit: Delay between DNS queries per thread (seconds)

    Returns:
        TakeoverReport with all findings
    """
    if wordlist is None:
        wordlist = SUBDOMAIN_WORDLIST

    report = TakeoverReport(
        domain=domain,
        total_scanned=len(wordlist),
        cname_found=0,
        potential_takeovers=0,
    )

    start_time = time.time()
    findings_lock = None  # Not needed with ThreadPoolExecutor result collection

    def scan_with_delay(sub):
        if rate_limit > 0:
            time.sleep(rate_limit)
        try:
            return scan_subdomain(domain, sub, nameservers)
        except Exception as e:
            report.errors.append(f"Error scanning {sub}.{domain}: {str(e)}")
            return None

    print(f"[*] Starting subdomain takeover scan for: {domain}")
    print(f"[*] Wordlist size: {len(wordlist)} subdomains")
    print(f"[*] Checking {len(VULNERABLE_SERVICES)} vulnerable service signatures")
    print(f"[*] Using {max_workers} concurrent workers\n")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_with_delay, sub): sub
            for sub in wordlist
        }

        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 25 == 0 or completed == len(wordlist):
                print(f"  [+] Progress: {completed}/{len(wordlist)} subdomains scanned", end="\r")

            try:
                finding = future.result()
                if finding:
                    report.findings.append(finding)
                    report.cname_found += 1
                    if finding.takeover_possible in (TakeoverVerdict.YES, TakeoverVerdict.MAYBE):
                        report.potential_takeovers += 1
            except Exception as e:
                sub = futures[futures]
                report.errors.append(f"Future error for {sub}: {str(e)}")

    report.scan_duration_seconds = round(time.time() - start_time, 2)

    print(f"\n[*] Scan complete in {report.scan_duration_seconds}s")
    print(f"[*] CNAME records found: {report.cname_found}")
    print(f"[*] Potential takeovers: {report.potential_takeovers}")

    return report


# ─── Report Formatting ────────────────────────────────────────────────────────

def format_report_text(report: TakeoverReport) -> str:
    """Format the report as human-readable text."""
    lines = []
    lines.append("=" * 80)
    lines.append("DNSAUDIT - SUBDOMAIN TAKEOVER SCAN REPORT")
    lines.append("=" * 80)
    lines.append(f"Target Domain    : {report.domain}")
    lines.append(f"Total Scanned    : {report.total_scanned}")
    lines.append(f"CNAMEs Found     : {report.cname_found}")
    lines.append(f"Potential Issues : {report.potential_takeovers}")
    lines.append(f"Scan Duration    : {report.scan_duration_seconds}s")
    lines.append("=" * 80)

    if not report.findings:
        lines.append("\n[+] No vulnerable CNAME records found.")
    else:
        # Sort by severity (CRITICAL first)
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                          Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(report.findings, key=lambda f: severity_order.get(f.severity, 5))

        for i, finding in enumerate(sorted_findings, 1):
            lines.append(f"\n{'─' * 70}")
            lines.append(f"FINDING #{i}")
            lines.append(f"{'─' * 70}")
            lines.append(f"  Subdomain        : {finding.subdomain}")
            lines.append(f"  CNAME Target     : {finding.cname_target}")
            lines.append(f"  Service          : {finding.service_identified}")
            lines.append(f"  Takeover Possible: {finding.takeover_possible.value}")
            lines.append(f"  Severity         : {finding.severity.value}")
            lines.append(f"  DNS Status       : {finding.resolution_status}")
            lines.append(f"  Evidence         : {finding.evidence}")

    if report.errors:
        lines.append(f"\n{'─' * 70}")
        lines.append(f"ERRORS ({len(report.errors)}):")
        for err in report.errors[:20]:  # Limit displayed errors
            lines.append(f"  - {err}")
        if len(report.errors) > 20:
            lines.append(f"  ... and {len(report.errors) - 20} more errors")

    lines.append(f"\n{'=' * 80}")
    return "\n".join(lines)


def format_report_json(report: TakeoverReport) -> str:
    """Format the report as JSON."""
    data = {
        "domain": report.domain,
        "total_scanned": report.total_scanned,
        "cname_found": report.cname_found,
        "potential_takeovers": report.potential_takeovers,
        "scan_duration_seconds": report.scan_duration_seconds,
        "findings": [
            {
                "subdomain": f.subdomain,
                "cname_target": f.cname_target,
                "service_identified": f.service_identified,
                "takeover_possible": f.takeover_possible.value,
                "severity": f.severity.value,
                "evidence": f.evidence,
                "resolution_status": f.resolution_status,
            }
            for f in report.findings
        ],
        "errors": report.errors,
    }
    return json.dumps(data, indent=2)


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    """CLI entry point for the subdomain takeover scanner."""
    import argparse

    parser = argparse.ArgumentParser(
        description="DNSAudit - Subdomain Takeover Detection (Category 6)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python takeover.py -d example.com
  python takeover.py -d example.com -o report.json --format json
  python takeover.py -d example.com -w custom_wordlist.txt --workers 20
  python takeover.py -d example.com --nameservers 8.8.8.8 1.1.1.1
        """
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    parser.add_argument("-w", "--wordlist", help="Custom subdomain wordlist file (one per line)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--workers", type=int, default=10, help="Concurrent workers (default: 10)")
    parser.add_argument("--rate-limit", type=float, default=0.05,
                        help="Delay between queries in seconds (default: 0.05)")
    parser.add_argument("--nameservers", nargs="+", help="Custom DNS nameservers")

    args = parser.parse_args()

    # Load custom wordlist if provided
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"[*] Loaded custom wordlist: {len(wordlist)} entries")
        except FileNotFoundError:
            print(f"[-] Wordlist file not found: {args.wordlist}")
            sys.exit(1)

    # Run the scan
    report = run_takeover_scan(
        domain=args.domain,
        wordlist=wordlist,
        nameservers=args.nameservers,
        max_workers=args.workers,
        rate_limit=args.rate_limit,
    )

    # Format output
    if args.format == "json":
        output = format_report_json(report)
    else:
        output = format_report_text(report)

    # Write or print output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"\n[+] Report saved to: {args.output}")
    else:
        print("\n" + output)

    # Exit with appropriate code
    if report.potential_takeovers > 0:
        sys.exit(2)  # Vulnerabilities found
    sys.exit(0)


if __name__ == "__main__":
    main()
