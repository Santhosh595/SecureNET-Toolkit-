"""JWTInspect — Report generation.

Generates JSON and HTML reports from test results.
"""

from __future__ import annotations

import json
import time
from typing import Any

from parser import ParsedJWT, format_timestamp, format_duration
from tests import TestResult, get_verdict


def generate_report(parsed: ParsedJWT, results: list[TestResult],
                     wordlist_size: int = 0, duration: float = 0) -> dict:
    """Generate a full JSON report."""
    verdict, _ = get_verdict(results)

    report = {
        "tool": "JWTInspect v1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "scan_duration": round(duration, 2),
        "token_info": {
            "algorithm": parsed.algorithm,
            "token_type": parsed.token_type,
            "header": parsed.header,
            "payload": parsed.payload,
            "signature_present": bool(parsed.signature),
            "is_expired": parsed.is_expired,
            "expires_in": format_duration(parsed.expires_in),
            "issued_ago": format_duration(parsed.issued_ago),
            "is_valid_time": parsed.is_valid_time,
        },
        "claims": {
            "iss": parsed.claims.iss,
            "sub": parsed.claims.sub,
            "aud": parsed.claims.aud,
            "exp": parsed.claims.exp,
            "exp_readable": format_timestamp(parsed.claims.exp) if parsed.claims.exp else None,
            "iat": parsed.claims.iat,
            "iat_readable": format_timestamp(parsed.claims.iat) if parsed.claims.iat else None,
            "nbf": parsed.claims.nbf,
            "nbf_readable": format_timestamp(parsed.claims.nbf) if parsed.claims.nbf else None,
            "jti": parsed.claims.jti,
        },
        "security_tests": [
            {
                "test": r.test_name,
                "result": r.result,
                "severity": r.severity,
                "finding": r.finding,
                "proof": r.proof,
                "remediation": r.remediation,
            }
            for r in results
        ],
        "summary": {
            "total_tests": len(results),
            "critical": sum(1 for r in results if r.severity == "CRITICAL"),
            "high": sum(1 for r in results if r.severity == "HIGH"),
            "medium": sum(1 for r in results if r.severity == "MEDIUM"),
            "low": sum(1 for r in results if r.severity == "LOW"),
            "pass": sum(1 for r in results if r.result == "PASS"),
            "fail": sum(1 for r in results if r.result == "FAIL"),
            "warnings": sum(1 for r in results if r.result == "WARNING"),
            "wordlist_size": wordlist_size,
        },
        "verdict": verdict,
        "errors": parsed.errors,
    }
    return report
