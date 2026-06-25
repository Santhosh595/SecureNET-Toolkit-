#!/usr/bin/env python3
"""
DNSAudit Bulk Scanning Module
==============================
Processes a list of domains from a file, generates per-domain reports,
produces a summary comparison table, and exports results as CSV or JSON.

Features:
  - Concurrent scanning via ThreadPoolExecutor
  - Progress bar with real-time status
  - Per-domain audit reports (JSON)
  - Summary comparison table (console + export)
  - CSV and JSON export formats
  - Configurable record types and resolvers
  - Graceful error handling per domain

Requirements:
    pip install dnspython tqdm
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path

# ---------------------------------------------------------------------------
# Imports from sibling modules
# ---------------------------------------------------------------------------
try:
    from resolver import (
        DNSResolverEngine,
        DNSResponse,
        ComparisonResult,
        ResponseStatus,
        DEFAULT_COMPARISON_RESOLVERS,
        normalize_domain,
    )
    from scorer import DNSScorer, CATEGORY_NAMES, MAX_RAW_SCORE
except ImportError:
    # Allow running as standalone script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from resolver import (
        DNSResolverEngine,
        DNSResponse,
        ComparisonResult,
        ResponseStatus,
        DEFAULT_COMPARISON_RESOLVERS,
        normalize_domain,
    )
    from scorer import DNSScorer, CATEGORY_NAMES, MAX_RAW_SCORE

# ---------------------------------------------------------------------------
# Optional progress bar
# ---------------------------------------------------------------------------
try:
    from tqdm import tqdm as _tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("dnsaudit.bulk")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _ch = logging.StreamHandler()
    _ch.setLevel(logging.INFO)
    _fmt = logging.Formatter("[%(levelname)s] %(message)s")
    _ch.setFormatter(_fmt)
    logger.addHandler(_ch)


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class DomainAuditResult:
    """Complete audit result for a single domain."""
    domain: str
    timestamp: str = ""
    record_types: List[str] = field(default_factory=list)
    resolver_results: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    hijacking_detected: bool = False
    hijacking_details: List[str] = field(default_factory=list)
    score: Optional[Dict[str, Any]] = None
    error: str = ""
    scan_duration_ms: float = 0.0
    status: str = "pending"  # pending, scanning, completed, error

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BulkScanSummary:
    """Summary of the entire bulk scan operation."""
    total_domains: int = 0
    completed: int = 0
    errors: int = 0
    hijacking_detected_count: int = 0
    start_time: str = ""
    end_time: str = ""
    total_duration_ms: float = 0.0
    results: List[DomainAuditResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_domains": self.total_domains,
            "completed": self.completed,
            "errors": self.errors,
            "hijacking_detected_count": self.hijacking_detected_count,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_duration_ms": self.total_duration_ms,
            "results": [r.to_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# Domain Loading
# ---------------------------------------------------------------------------

def load_domains(filepath: str) -> List[str]:
    """
    Load domains from a text file (one per line).
    Skips empty lines and lines starting with '#'.
    Normalizes each domain.
    """
    domains = []
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Domain file not found: {filepath}")

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                normalized = normalize_domain(line)
                domains.append(normalized)
            except ValueError as e:
                logger.warning("Skipping invalid domain on line %d: %s (%s)", line_num, line, e)

    # Deduplicate while preserving order
    seen = set()
    unique_domains = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)

    logger.info("Loaded %d unique domains from %s", len(unique_domains), filepath)
    return unique_domains


# ---------------------------------------------------------------------------
# Single Domain Audit
# ---------------------------------------------------------------------------

def audit_single_domain(
    domain: str,
    engine: DNSResolverEngine,
    record_types: Optional[List[str]] = None,
    resolvers: Optional[List[str]] = None,
    check_hijacking: bool = True,
) -> DomainAuditResult:
    """
    Perform a full DNS audit on a single domain.

    Args:
        domain: Domain name to audit
        engine: DNSResolverEngine instance
        record_types: List of DNS record types to check
        resolvers: List of resolver IPs for comparison
        check_hijacking: Whether to check for DNS hijacking

    Returns:
        DomainAuditResult with all findings
    """
    start_time = time.time()
    result = DomainAuditResult(domain=domain, status="scanning")

    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

    if resolvers is None:
        resolvers = DEFAULT_COMPARISON_RESOLVERS

    result.record_types = record_types
    all_hijacking_details = []

    try:
        for rrtype in record_types:
            # Query across all resolvers
            responses = engine.query_multiple(domain, rrtype, resolvers)

            # Store results
            result.resolver_results[rrtype] = [r.to_dict() for r in responses]

            # Check for hijacking if requested
            if check_hijacking:
                comparison = engine.compare_resolvers(domain, rrtype, resolvers)
                if comparison.hijacking_detected:
                    result.hijacking_detected = True
                    all_hijacking_details.extend(comparison.hijacking_details)

        result.hijacking_details = all_hijacking_details

        # Score the audit
        scorer = DNSScorer(domain)
        _populate_scorer_from_results(scorer, result)
        result.score = scorer.calculate().to_dict()

        result.status = "completed"

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        logger.error("Error auditing %s: %s", domain, e)

    result.scan_duration_ms = round((time.time() - start_time) * 1000, 2)
    return result


def _populate_scorer_from_results(scorer: DNSScorer, result: DomainAuditResult) -> None:
    """Populate a DNSScorer with findings from audit results."""
    # SPF check (from TXT records)
    txt_results = result.resolver_results.get("TXT", [])
    has_spf = any(
        "v=spf1" in str(ans.get("rdata", ""))
        for resp in txt_results
        for ans in resp.get("answers", [])
    )
    if not has_spf:
        scorer.add_finding("SPF", "CRITICAL", "No SPF record found")

    # DMARC check (from TXT records for _dmarc.domain)
    has_dmarc = any(
        "v=DMARC1" in str(ans.get("rdata", ""))
        for resp in txt_results
        for ans in resp.get("answers", [])
    )
    if not has_dmarc:
        scorer.add_finding("DMARC", "HIGH", "No DMARC record found")

    # DKIM check (basic - would need selector enumeration for full check)
    # We note it as a low finding since we can't check all selectors
    scorer.add_finding("DKIM", "LOW", "DKIM check requires selector enumeration (not performed in bulk)")

    # DNSSEC check (from SOA/NS consistency)
    ns_results = result.resolver_results.get("NS", [])
    if not ns_results or all(
        r.get("status") != "SUCCESS" for r in ns_results
    ):
        scorer.add_finding("Nameserver Security", "HIGH", "Could not retrieve NS records")

    # Zone Transfer check
    scorer.add_finding("Zone Transfer", "LOW", "Zone transfer check requires AXFR query (not performed in bulk)")

    # Hijacking findings
    if result.hijacking_detected:
        for detail in result.hijacking_details:
            scorer.add_finding("DNS Cache Poisoning", "CRITICAL", detail)

    # Mail Server Security (from MX records)
    mx_results = result.resolver_results.get("MX", [])
    if not mx_results or all(
        r.get("status") != "SUCCESS" for r in mx_results
    ):
        scorer.add_finding("Mail Server Security", "MEDIUM", "No MX records found")

    # CAA check
    caa_results = result.resolver_results.get("CAA", [])
    if not caa_results or all(
        r.get("status") != "SUCCESS" for r in caa_results
    ):
        scorer.add_finding("CAA Records", "LOW", "No CAA records found")

    # DNS Hygiene - check for consistent responses
    for rrtype, responses in result.resolver_results.items():
        statuses = [r.get("status") for r in responses]
        if statuses and not all(s == statuses[0] for s in statuses):
            scorer.add_finding(
                "DNS Hygiene",
                "MEDIUM",
                f"Inconsistent {rrtype} responses across resolvers"
            )


# ---------------------------------------------------------------------------
# Progress Bar Helper
# ---------------------------------------------------------------------------

class ProgressTracker:
    """Wrapper for progress tracking with or without tqdm."""

    def __init__(self, total: int, desc: str = "Scanning"):
        self.total = total
        self.current = 0
        self.desc = desc
        self._pbar = None

        if HAS_TQDM:
            self._pbar = _tqdm(total=total, desc=desc, unit="domain",
                               bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]")

    def update(self, n: int = 1, domain: str = "", status: str = ""):
        self.current += n
        if self._pbar:
            postfix = f"{domain[:30]}" if domain else ""
            if status:
                postfix += f" ({status})"
            self._pbar.set_postfix_str(postfix, refresh=True)
            self._pbar.update(n)
        else:
            # Simple console progress
            pct = (self.current / self.total) * 100
            msg = f"\r{self.desc}: {self.current}/{self.total} ({pct:.0f}%)"
            if domain:
                msg += f" - {domain}"
            if status:
                msg += f" [{status}]"
            sys.stdout.write(msg.ljust(80))
            sys.stdout.flush()

    def close(self):
        if self._pbar:
            self._pbar.close()
        else:
            sys.stdout.write("\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Bulk Scanner
# ---------------------------------------------------------------------------

class BulkScanner:
    """
    Main bulk scanning orchestrator.

    Usage::

        scanner = BulkScanner(
            domains=["example.com", "test.org"],
            max_workers=5,
            record_types=["A", "MX", "TXT"],
        )
        summary = scanner.run()
        scanner.export_csv("results.csv")
        scanner.export_json("results.json")
    """

    def __init__(
        self,
        domains: List[str],
        max_workers: int = 5,
        record_types: Optional[List[str]] = None,
        resolvers: Optional[List[str]] = None,
        check_hijacking: bool = True,
        timeout: float = 5.0,
        output_dir: str = "bulk_reports",
    ):
        self.domains = domains
        self.max_workers = max_workers
        self.record_types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]
        self.resolvers = resolvers or DEFAULT_COMPARISON_RESOLVERS
        self.check_hijacking = check_hijacking
        self.timeout = timeout
        self.output_dir = output_dir
        self.summary = BulkScanSummary(total_domains=len(domains))

    def run(self) -> BulkScanSummary:
        """Execute the bulk scan with concurrent workers and progress bar."""
        self.summary.start_time = datetime.now(timezone.utc).isoformat()
        start = time.time()

        logger.info(
            "Starting bulk scan: %d domains, %d workers, record types: %s",
            len(self.domains), self.max_workers, self.record_types
        )

        progress = ProgressTracker(total=len(self.domains), desc="DNS Audit")

        # Create a shared engine (thread-safe for queries)
        engine = DNSResolverEngine(
            timeout=self.timeout,
            enable_audit_log=False,
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_domain = {}
            for domain in self.domains:
                future = executor.submit(
                    audit_single_domain,
                    domain=domain,
                    engine=engine,
                    record_types=self.record_types,
                    resolvers=self.resolvers,
                    check_hijacking=self.check_hijacking,
                )
                future_to_domain[future] = domain

            # Collect results as they complete
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    self.summary.results.append(result)

                    if result.status == "completed":
                        self.summary.completed += 1
                    else:
                        self.summary.errors += 1

                    if result.hijacking_detected:
                        self.summary.hijacking_detected_count += 1

                    progress.update(
                        n=1,
                        domain=domain,
                        status=result.status + (" ⚠ HIJACK" if result.hijacking_detected else ""),
                    )

                except Exception as e:
                    error_result = DomainAuditResult(
                        domain=domain,
                        status="error",
                        error=str(e),
                    )
                    self.summary.results.append(error_result)
                    self.summary.errors += 1
                    progress.update(n=1, domain=domain, status="ERROR")
                    logger.error("Unexpected error for %s: %s", domain, e)

        progress.close()

        self.summary.end_time = datetime.now(timezone.utc).isoformat()
        self.summary.total_duration_ms = round((time.time() - start) * 1000, 2)

        logger.info(
            "Bulk scan complete: %d/%d completed, %d errors, %d hijacking detected, %.1fs",
            self.summary.completed,
            self.summary.total_domains,
            self.summary.errors,
            self.summary.hijacking_detected_count,
            self.summary.total_duration_ms / 1000,
        )

        return self.summary

    # -----------------------------------------------------------------------
    # Per-Domain Reports
    # -----------------------------------------------------------------------

    def generate_per_domain_reports(self) -> str:
        """
        Generate individual JSON reports for each domain.
        Returns the output directory path.
        """
        report_dir = os.path.join(self.output_dir, "per_domain")
        os.makedirs(report_dir, exist_ok=True)

        for result in self.summary.results:
            safe_name = result.domain.replace(".", "_").replace("/", "_")
            filepath = os.path.join(report_dir, f"{safe_name}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)

        logger.info("Per-domain reports saved to %s", report_dir)
        return report_dir

    # -----------------------------------------------------------------------
    # Summary Table (Console)
    # -----------------------------------------------------------------------

    def print_summary_table(self) -> None:
        """Print a formatted comparison table to the console."""
        # Header
        print(f"\n{'='*120}")
        print(f"  DNSAudit Bulk Scan Summary")
        print(f"  Total: {self.summary.total_domains} | Completed: {self.summary.completed} | "
              f"Errors: {self.summary.errors} | Hijacking: {self.summary.hijacking_detected_count} | "
              f"Duration: {self.summary.total_duration_ms/1000:.1f}s")
        print(f"{'='*120}")

        # Column headers
        header = (
            f"{'#':>4} {'Domain':<40} {'Status':<12} {'Grade':<6} {'Score':<8} "
            f"{'Hijack':<8} {'Issues':<6} {'Time(ms)':<10}"
        )
        print(header)
        print(f"{'─'*120}")

        # Sort results: hijacking first, then by score (worst first)
        sorted_results = sorted(
            self.summary.results,
            key=lambda r: (
                not r.hijacking_detected,
                -(r.score.get("overall_percentage", 0) if r.score else 0),
            ),
        )

        for i, result in enumerate(sorted_results, 1):
            grade = result.score.get("grade", "N/A") if result.score else "N/A"
            score = result.score.get("overall_percentage", 0) if result.score else 0
            hijack = "⚠ YES" if result.hijacking_detected else "  no"
            issues = len(result.hijacking_details) + (
                sum(len(c.get("findings", [])) for c in result.score.get("categories", {}).values())
                if result.score else 0
            )

            # Color coding (ANSI escape codes)
            status_color = {
                "completed": "\033[92m",  # green
                "error": "\033[91m",       # red
                "scanning": "\033[93m",    # yellow
            }.get(result.status, "")
            reset = "\033[0m"

            row = (
                f"{i:>4} {result.domain:<40} {status_color}{result.status:<12}{reset} "
                f"{grade:<6} {score:>6.1f}% {hijack:<8} {issues:<6} {result.scan_duration_ms:>8.0f}"
            )
            print(row)

        print(f"{'─'*120}")

        # Grade distribution
        grade_counts: Dict[str, int] = {}
        for r in self.summary.results:
            if r.score:
                g = r.score.get("grade", "N/A")
                grade_counts[g] = grade_counts.get(g, 0) + 1

        if grade_counts:
            print(f"\n  Grade Distribution: ", end="")
            for grade_label in ["A+", "A", "B", "C", "D", "F"]:
                count = grade_counts.get(grade_label, 0)
                if count > 0:
                    print(f"{grade_label}={count} ", end="")
            print()

        print(f"{'='*120}\n")

    # -----------------------------------------------------------------------
    # Export: CSV
    # -----------------------------------------------------------------------

    def export_csv(self, filepath: Optional[str] = None) -> str:
        """
        Export bulk results as CSV.

        Columns: domain, status, grade, score_pct, hijacking_detected,
                 hijacking_details, scan_duration_ms, error, and per-record-type status.
        """
        if filepath is None:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"bulk_results_{timestamp}.csv")

        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        # Build fieldnames
        base_fields = [
            "domain", "status", "grade", "score_percentage",
            "hijacking_detected", "hijacking_details",
            "scan_duration_ms", "error", "timestamp",
        ]
        # Add per-record-type fields
        record_type_fields = []
        for rrtype in self.record_types:
            record_type_fields.append(f"{rrtype}_status")
            record_type_fields.append(f"{rrtype}_answers")

        fieldnames = base_fields + record_type_fields

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for result in self.summary.results:
                row = {
                    "domain": result.domain,
                    "status": result.status,
                    "grade": result.score.get("grade", "") if result.score else "",
                    "score_percentage": result.score.get("overall_percentage", "") if result.score else "",
                    "hijacking_detected": result.hijacking_detected,
                    "hijacking_details": "; ".join(result.hijacking_details),
                    "scan_duration_ms": result.scan_duration_ms,
                    "error": result.error,
                    "timestamp": result.timestamp,
                }

                # Add per-record-type data
                for rrtype in self.record_types:
                    responses = result.resolver_results.get(rrtype, [])
                    if responses:
                        statuses = list(set(r.get("status", "") for r in responses))
                        row[f"{rrtype}_status"] = "|".join(statuses)

                        # Collect all answer values
                        answers = []
                        for resp in responses:
                            for ans in resp.get("answers", []):
                                answers.append(ans.get("rdata", ""))
                        row[f"{rrtype}_answers"] = "|".join(answers)
                    else:
                        row[f"{rrtype}_status"] = ""
                        row[f"{rrtype}_answers"] = ""

                writer.writerow(row)

        logger.info("CSV exported to %s", filepath)
        return filepath

    # -----------------------------------------------------------------------
    # Export: JSON
    # -----------------------------------------------------------------------

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export complete bulk results as JSON."""
        if filepath is None:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"bulk_results_{timestamp}.json")

        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.summary.to_dict(), f, indent=2, default=str)

        logger.info("JSON exported to %s", filepath)
        return filepath

    # -----------------------------------------------------------------------
    # Full Pipeline
    # -----------------------------------------------------------------------

    def run_full_pipeline(
        self,
        export_format: str = "both",
        show_table: bool = True,
    ) -> BulkScanSummary:
        """
        Run the complete bulk scan pipeline:
        1. Scan all domains concurrently
        2. Print summary table
        3. Generate per-domain reports
        4. Export results

        Args:
            export_format: "csv", "json", "both", or "none"
            show_table: Whether to print the summary table to console

        Returns:
            BulkScanSummary with all results
        """
        # Step 1: Run scan
        summary = self.run()

        # Step 2: Print table
        if show_table:
            self.print_summary_table()

        # Step 3: Per-domain reports
        self.generate_per_domain_reports()

        # Step 4: Export
        if export_format in ("csv", "both"):
            self.export_csv()
        if export_format in ("json", "both"):
            self.export_json()

        return summary


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    """Command-line interface for bulk DNS scanning."""
    parser = argparse.ArgumentParser(
        description="DNSAudit Bulk Scanner - Audit multiple domains concurrently",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s domains.txt
  %(prog)s domains.txt --workers 10 --format both
  %(prog)s domains.txt --types A MX TXT --resolvers 8.8.8.8 1.1.1.1
  %(prog)s domains.txt --output ./my_reports --format json --no-table
  %(prog)s domains.txt --timeout 10 --workers 3
        """,
    )

    parser.add_argument(
        "domain_file",
        help="Path to file containing domains (one per line)",
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=5,
        help="Number of concurrent workers (default: 5)",
    )
    parser.add_argument(
        "--types", "-t", nargs="+",
        default=["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"],
        help="DNS record types to check (default: A AAAA MX NS TXT SOA CNAME CAA)",
    )
    parser.add_argument(
        "--resolvers", "-r", nargs="+",
        default=None,
        help="Resolver IPs for comparison (default: 8.8.8.8 1.1.1.1 9.9.9.9)",
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="Query timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--output", "-o", default="bulk_reports",
        help="Output directory for reports (default: bulk_reports)",
    )
    parser.add_argument(
        "--format", "-f", choices=["csv", "json", "both", "none"], default="both",
        help="Export format (default: both)",
    )
    parser.add_argument(
        "--no-table", action="store_true",
        help="Suppress the summary table output",
    )
    parser.add_argument(
        "--no-hijack-check", action="store_true",
        help="Skip hijacking detection (faster scan)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose/debug logging",
    )

    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)

    # Load domains
    try:
        domains = load_domains(args.domain_file)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)

    if not domains:
        logger.error("No valid domains found in %s", args.domain_file)
        sys.exit(1)

    # Create scanner
    scanner = BulkScanner(
        domains=domains,
        max_workers=args.workers,
        record_types=args.types,
        resolvers=args.resolvers,
        check_hijacking=not args.no_hijack_check,
        timeout=args.timeout,
        output_dir=args.output,
    )

    # Run pipeline
    scanner.run_full_pipeline(
        export_format=args.format,
        show_table=not args.no_table,
    )


if __name__ == "__main__":
    main()
