"""JWTInspect — Security test suite.

8 automated JWT security tests covering known attack vectors.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

from parser import ParsedJWT, forge_token, _base64url_encode


@dataclass
class TestResult:
    """Result of a single security test."""
    test_name: str
    result: str  # PASS / FAIL / WARNING / INFO
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    finding: str
    proof: str = ""
    remediation: str = ""


def _severity_color(severity: str) -> str:
    return {"CRITICAL": "bold red", "HIGH": "bold orange", "MEDIUM": "bold yellow",
            "LOW": "bold blue", "INFO": "dim"}.get(severity, "white")


# ── Test 1: Algorithm Confusion (alg:none) ──

def test_alg_none(parsed: ParsedJWT) -> TestResult:
    """Test for alg:none vulnerability."""
    alg = parsed.algorithm.lower()

    if alg == "none":
        return TestResult(
            test_name="Algorithm Confusion (alg:none)",
            result="FAIL", severity="CRITICAL",
            finding="Token uses 'alg':'none' — signature verification is disabled.",
            proof=f"Header algorithm is '{parsed.algorithm}'. Forged token: {forge_token(parsed.header, parsed.payload)}",
            remediation="Server must reject tokens with alg:none. Only accept expected algorithms.",
        )

    # Try forging with alg:none
    forged_header = dict(parsed.header)
    forged_header["alg"] = "none"
    forged = forge_token(forged_header, parsed.payload)

    return TestResult(
        test_name="Algorithm Confusion (alg:none)",
        result="INFO", severity="INFO",
        finding=f"Token uses '{parsed.algorithm}'. alg:none not detected in original header.",
        proof=f"Sample forged token (alg:none): {forged[:80]}...",
        remediation="Ensure server explicitly rejects alg:none tokens.",
    )


# ── Test 2: Weak Secret Brute Force ──

def test_weak_secret(parsed: ParsedJWT, wordlist: list[str]) -> TestResult:
    """Test HS256/HS384/HS512 secret strength via brute force."""
    alg = parsed.algorithm.upper()
    if not alg.startswith("HS"):
        return TestResult(
            test_name="Weak Secret Brute Force",
            result="INFO", severity="INFO",
            finding=f"Token uses {alg} — secret brute force only applies to HMAC algorithms.",
            proof="", remediation="",
        )

    hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not hash_func:
        return TestResult(
            test_name="Weak Secret Brute Force",
            result="INFO", severity="INFO",
            finding=f"Unknown HMAC algorithm: {alg}",
            proof="", remediation="",
        )

    header_b64 = _base64url_encode(json.dumps(parsed.header, separators=(",", ":")).encode())
    payload_b64 = _base64url_encode(json.dumps(parsed.payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    target_sig = parsed.signature

    for word in wordlist:
        sig = hmac.new(word.encode(), signing_input, hash_func).digest()
        import base64
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        if sig_b64 == target_sig:
            forged = forge_token(parsed.header, parsed.payload, word, alg)
            return TestResult(
                test_name="Weak Secret Brute Force",
                result="FAIL", severity="CRITICAL",
                finding=f"Secret cracked: '{word}'",
                proof=f"Cracked token (valid signature): {forged[:100]}...",
                remediation="Use a strong random secret (256+ bits) or switch to RS256.",
            )

    return TestResult(
        test_name="Weak Secret Brute Force",
        result="PASS", severity="INFO",
        finding=f"Secret not found in wordlist ({len(wordlist)} candidates).",
        proof="", remediation="Consider using stronger secrets or asymmetric algorithms.",
    )


# ── Test 3: Algorithm Substitution (RS256 → HS256) ──

def test_alg_substitution(parsed: ParsedJWT) -> TestResult:
    """Test for RS256→HS256 algorithm substitution vulnerability."""
    alg = parsed.algorithm.upper()

    if alg != "RS256":
        return TestResult(
            test_name="Algorithm Substitution (RS256→HS256)",
            result="INFO", severity="INFO",
            finding=f"Token uses {alg} — substitution test only applies to RS256 tokens.",
            proof="", remediation="",
        )

    return TestResult(
        test_name="Algorithm Substitution (RS256→HS256)",
        result="WARNING", severity="HIGH",
        finding="Token uses RS256. If the server accepts HS256, an attacker can forge tokens using the public key as HMAC secret.",
        proof="Attack: Take the public key, create header with alg:HS256, sign HMAC(public_key, signing_input).",
        remediation="Server must enforce expected algorithm per key type. Reject HS256 when RS256 is expected.",
    )


# ── Test 4: Expiration Check ──

def test_expiration(parsed: ParsedJWT) -> TestResult:
    """Test token expiration configuration."""
    if parsed.claims.exp is None:
        return TestResult(
            test_name="Expiration Check",
            result="FAIL", severity="CRITICAL",
            finding="Token has no 'exp' claim — it never expires.",
            proof="Payload contains no expiration timestamp.",
            remediation="Always include 'exp' claim. Use short-lived tokens (15-60 min).",
        )

    if parsed.is_expired:
        return TestResult(
            test_name="Expiration Check",
            result="WARNING", severity="MEDIUM",
            finding=f"Token expired {abs(parsed.expires_in):.0f}s ago.",
            proof=f"Expiration: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(parsed.claims.exp))} UTC",
            remediation="Server must reject expired tokens.",
        )

    if parsed.claims.iat and parsed.claims.exp:
        lifetime = parsed.claims.exp - parsed.claims.iat
        if lifetime > 2592000:  # 30 days
            return TestResult(
                test_name="Expiration Check",
                result="FAIL", severity="CRITICAL",
                finding=f"Token lifetime is {lifetime/86400:.0f} days — dangerously long.",
                proof=f"iat={parsed.claims.iat}, exp={parsed.claims.exp}, lifetime={lifetime}s",
                remediation="Use short-lived tokens (max 7 days). Implement refresh tokens.",
            )
        elif lifetime > 604800:  # 7 days
            return TestResult(
                test_name="Expiration Check",
                result="WARNING", severity="MEDIUM",
                finding=f"Token lifetime is {lifetime/86400:.1f} days — longer than recommended.",
                proof=f"iat={parsed.claims.iat}, exp={parsed.claims.exp}",
                remediation="Consider reducing token lifetime to 7 days or less.",
            )

    return TestResult(
        test_name="Expiration Check",
        result="PASS", severity="INFO",
        finding=f"Token expires in {parsed.expires_in/3600:.1f}h.",
        proof=f"Valid expiration window configured.",
        remediation="",
    )


# ── Test 5: Sensitive Data in Payload ──

def test_sensitive_data(parsed: ParsedJWT) -> TestResult:
    """Test for sensitive data exposure in JWT payload."""
    findings = []
    payload_str = json.dumps(parsed.payload)

    # Check for passwords/secrets
    sensitive_keys = ["password", "secret", "key", "token", "api_key", "apikey",
                      "access_token", "refresh_token", "private_key", "credential"]
    for key in sensitive_keys:
        if key.lower() in payload_str.lower():
            findings.append(f"Sensitive key '{key}' found in payload")

    # Check for PII
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    if re.search(email_pattern, payload_str):
        findings.append("Email address found in payload")

    phone_pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
    if re.search(phone_pattern, payload_str):
        findings.append("Phone number pattern found in payload")

    # Check for internal IPs
    internal_ip = r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    if re.search(internal_ip, payload_str):
        findings.append("Internal/private IP address found in payload")

    # Check for elevated roles
    role_keys = ["role", "roles", "admin", "is_admin", "isAdmin", "superuser", "permission"]
    for key in role_keys:
        if key.lower() in payload_str.lower():
            val = parsed.payload.get(key, "")
            if isinstance(val, str) and val.lower() in ("admin", "superuser", "root", "true"):
                findings.append(f"Elevated role detected: {key}={val}")
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, str) and v.lower() in ("admin", "superuser", "root"):
                        findings.append(f"Elevated role detected: {key}=[{v}]")

    if findings:
        return TestResult(
            test_name="Sensitive Data in Payload",
            result="FAIL", severity="HIGH",
            finding="; ".join(findings),
            proof="JWT payload is base64-encoded, not encrypted. Anyone with the token can read this data.",
            remediation="Never put sensitive data (passwords, PII, internal IPs) in JWT payload. Use opaque tokens for sensitive data.",
        )

    return TestResult(
        test_name="Sensitive Data in Payload",
        result="PASS", severity="INFO",
        finding="No obvious sensitive data patterns detected in payload.",
        proof="",
        remediation="",
    )


# ── Test 6: Kid Header Injection ──

def test_kid_injection(parsed: ParsedJWT) -> TestResult:
    """Test for kid (key ID) header injection."""
    kid = parsed.header.get("kid")

    if kid is None:
        return TestResult(
            test_name="Kid Header Injection",
            result="PASS", severity="INFO",
            finding="No 'kid' header present.",
            proof="",
            remediation="",
        )

    # Check for suspicious patterns in kid
    suspicious = False
    proof_parts = [f"kid value: '{kid}'"]

    if "://" in kid or kid.startswith("/") or ".." in kid:
        suspicious = True
        proof_parts.append("Contains path traversal or URL patterns")

    if "'" in kid or '"' in kid or ";" in kid or "$" in kid:
        suspicious = True
        proof_parts.append("Contains SQL injection or command injection characters")

    if kid.startswith("{") or kid.startswith("["):
        suspicious = True
        proof_parts.append("Contains structured data (possible injection)")

    if suspicious:
        return TestResult(
            test_name="Kid Header Injection",
            result="FAIL", severity="HIGH",
            finding=f"Suspicious 'kid' header value detected.",
            proof="; ".join(proof_parts),
            remediation="Validate and sanitize 'kid' header. Use allowlist of expected key IDs.",
        )

    return TestResult(
        test_name="Kid Header Injection",
        result="WARNING", severity="MEDIUM",
        finding=f"'kid' header present: '{kid}'. Ensure server validates against allowlist.",
        proof="kid is used to select signing key — injection can bypass verification.",
        remediation="Use strict allowlist for kid values. Never use kid directly in file paths or DB queries.",
    )


# ── Test 7: JKU / X5U Header Abuse ──

def test_jku_abuse(parsed: ParsedJWT) -> TestResult:
    """Test for jku/x5u header abuse."""
    jku = parsed.header.get("jku")
    x5u = parsed.header.get("x5u")

    if not jku and not x5u:
        return TestResult(
            test_name="JKU/X5U Header Abuse",
            result="PASS", severity="INFO",
            finding="No 'jku' or 'x5u' headers present.",
            proof="",
            remediation="",
        )

    findings = []
    if jku:
        findings.append(f"jku: {jku}")
    if x5u:
        findings.append(f"x5u: {x5u}")

    return TestResult(
        test_name="JKU/X5U Header Abuse",
        result="FAIL", severity="HIGH",
        finding=f"External key URL headers present: {'; '.join(findings)}",
        proof="Server may fetch signing keys from attacker-controlled URLs, enabling token forgery.",
        remediation="Never trust jku/x5u headers from tokens. Use a pre-configured key store.",
    )


# ── Test 8: Claim Manipulation Detection ──

def test_claim_diff(parsed: ParsedJWT, compare_token: Optional[str] = None) -> TestResult:
    """Test for claim manipulation between two tokens."""
    if not compare_token:
        return TestResult(
            test_name="Claim Manipulation Detection",
            result="INFO", severity="INFO",
            finding="No comparison token provided. Use --compare <token> to diff claims.",
            proof="",
            remediation="",
        )

    from parser import parse_jwt
    parsed2 = parse_jwt(compare_token)

    if parsed2.errors:
        return TestResult(
            test_name="Claim Manipulation Detection",
            result="INFO", severity="INFO",
            finding="Comparison token is malformed.",
            proof="",
            remediation="",
        )

    # Diff payloads
    diffs = []
    all_keys = set(list(parsed.payload.keys()) + list(parsed2.payload.keys()))
    for key in sorted(all_keys):
        v1 = parsed.payload.get(key)
        v2 = parsed2.payload.get(key)
        if v1 != v2:
            diffs.append(f"{key}: {v1} → {v2}")

    if not diffs:
        return TestResult(
            test_name="Claim Manipulation Detection",
            result="PASS", severity="INFO",
            finding="No claim differences detected between tokens.",
            proof="",
            remediation="",
        )

    # Check for privilege escalation patterns
    escalation = False
    for d in diffs:
        if any(k in d.lower() for k in ["role", "admin", "permission", "superuser", "access"]):
            escalation = True

    return TestResult(
        test_name="Claim Manipulation Detection",
        result="WARNING" if not escalation else "FAIL",
        severity="MEDIUM" if not escalation else "HIGH",
        finding=f"Claim differences found: {'; '.join(diffs)}",
        proof="Differences may indicate token tampering or privilege escalation.",
        remediation="Server must validate all claims server-side. Don't trust client-provided tokens for authorization.",
    )


# ── Run all tests ──

def run_all_tests(parsed: ParsedJWT, wordlist: list[str],
                   compare_token: Optional[str] = None) -> list[TestResult]:
    """Run all 8 security tests."""
    results = [
        test_alg_none(parsed),
        test_weak_secret(parsed, wordlist),
        test_alg_substitution(parsed),
        test_expiration(parsed),
        test_sensitive_data(parsed),
        test_kid_injection(parsed),
        test_jku_abuse(parsed),
        test_claim_diff(parsed, compare_token),
    ]
    return results


def get_verdict(results: list[TestResult]) -> tuple[str, str]:
    """Calculate overall verdict from test results."""
    severities = [r.severity for r in results]
    if "CRITICAL" in severities:
        return "CRITICALLY VULNERABLE", "bold red"
    elif "HIGH" in severities:
        return "VULNERABLE", "bold orange"
    elif "MEDIUM" in severities:
        return "WEAK", "bold yellow"
    elif "LOW" in severities:
        return "MODERATE", "bold blue"
    else:
        return "SECURE", "bold green"
