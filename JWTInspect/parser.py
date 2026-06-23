"""JWTInspect — JWT token parser and claims extractor.

Handles decoding, normalization, and claim analysis.
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class JWTClaims:
    """Extracted JWT claims with metadata."""
    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    jti: Optional[str] = None
    raw_payload: dict = field(default_factory=dict)
    raw_header: dict = field(default_factory=dict)


@dataclass
class ParsedJWT:
    """Fully parsed JWT token."""
    original_token: str
    header: dict
    payload: dict
    signature: str
    algorithm: str
    token_type: str  # JWS / JWE / nested
    claims: JWTClaims
    is_expired: bool = False
    expires_in: Optional[float] = None  # seconds until expiry (negative if expired)
    issued_ago: Optional[float] = None  # seconds since issued
    is_valid_time: bool = True
    errors: list[str] = field(default_factory=list)


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    # Replace URL-safe chars
    data = data.replace("-", "+").replace("_", "/")
    return base64.b64decode(data)


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string."""
    encoded = base64.urlsafe_b64encode(data).decode("utf-8")
    return encoded.rstrip("=")


def _normalize_token(token: str) -> str:
    """Normalize JWT token — strip Bearer prefix, whitespace."""
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def parse_jwt(token: str) -> ParsedJWT:
    """Parse a JWT token into its components.

    Args:
        token: The JWT token string (may include "Bearer " prefix).

    Returns:
        ParsedJWT with all components decoded.
    """
    token = _normalize_token(token)
    parts = token.split(".")

    if len(parts) < 3:
        return ParsedJWT(
            original_token=token, header={}, payload={}, signature="",
            algorithm="UNKNOWN", token_type="UNKNOWN",
            claims=JWTClaims(),
            errors=[f"Invalid JWT format: expected 3+ parts, got {len(parts)}"],
        )

    header_b64, payload_b64, sig_b64 = parts[0], parts[1], parts[2]

    # Detect JWE (encrypted)
    token_type = "JWS"
    if len(parts) == 5:
        token_type = "JWE"

    # Decode header
    try:
        header_json = _base64url_decode(header_b64)
        header = json.loads(header_json)
    except Exception as e:
        return ParsedJWT(
            original_token=token, header={}, payload={}, signature=sig_b64,
            algorithm="UNKNOWN", token_type=token_type,
            claims=JWTClaims(),
            errors=[f"Failed to decode header: {e}"],
        )

    # Decode payload
    try:
        payload_json = _base64url_decode(payload_b64)
        payload = json.loads(payload_json)
    except Exception as e:
        return ParsedJWT(
            original_token=token, header=header, payload={}, signature=sig_b64,
            algorithm=header.get("alg", "UNKNOWN"), token_type=token_type,
            claims=JWTClaims(raw_header=header),
            errors=[f"Failed to decode payload: {e}"],
        )

    algorithm = header.get("alg", "UNKNOWN")

    # Extract claims
    claims = JWTClaims(
        iss=payload.get("iss"),
        sub=payload.get("sub"),
        aud=payload.get("aud"),
        exp=payload.get("exp"),
        iat=payload.get("iat"),
        nbf=payload.get("nbf"),
        jti=payload.get("jti"),
        raw_payload=payload,
        raw_header=header,
    )

    # Time-based analysis
    now = time.time()
    is_valid_time = True

    if claims.exp is not None:
        expires_in = claims.exp - now
        is_expired = expires_in < 0
    else:
        expires_in = None
        is_expired = False

    if claims.iat is not None:
        issued_ago = now - claims.iat
    else:
        issued_ago = None

    if claims.nbf is not None and now < claims.nbf:
        is_valid_time = False

    if claims.exp is not None and is_expired:
        is_valid_time = False

    return ParsedJWT(
        original_token=token,
        header=header,
        payload=payload,
        signature=sig_b64,
        algorithm=algorithm,
        token_type=token_type,
        claims=claims,
        is_expired=is_expired,
        expires_in=expires_in,
        issued_ago=issued_ago,
        is_valid_time=is_valid_time,
    )


def format_timestamp(ts: int) -> str:
    """Format a Unix timestamp to human-readable string."""
    try:
        from datetime import datetime, timezone
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def format_duration(seconds: Optional[float]) -> str:
    """Format a duration in seconds to human-readable string."""
    if seconds is None:
        return "N/A"
    if seconds < 0:
        return f"Expired {format_duration(-seconds)} ago"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}m"
    if seconds < 86400:
        return f"{seconds/3600:.1f}h"
    return f"{seconds/86400:.1f}d"


def forge_token(header: dict, payload: dict, secret: str = "",
                 algorithm: str = "HS256") -> str:
    """Create a JWT token from header, payload, and optional secret.

    Args:
        header: JWT header dict.
        payload: JWT payload dict.
        secret: Signing secret (for HS256/HS384/HS512).
        algorithm: Signing algorithm.

    Returns:
        Encoded JWT token string.
    """
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}"

    if algorithm == "none":
        return f"{signing_input}."
    elif algorithm.startswith("HS"):
        import hmac
        import hashlib
        hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(algorithm)
        if hash_func:
            sig = hmac.new(secret.encode(), signing_input.encode(), hash_func).digest()
            sig_b64 = _base64url_encode(sig)
            return f"{signing_input}.{sig_b64}"

    return f"{signing_input}."
