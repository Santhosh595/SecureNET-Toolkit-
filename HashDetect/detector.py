"""HashDetect — Hash type identification and validation.

Identifies hash types based on length, charset, and pattern matching.
Assigns confidence levels and algorithm categories.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Confidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Category(Enum):
    CRYPTOGRAPHIC = "CRYPTOGRAPHIC"
    WEAK = "WEAK"
    PASSWORD = "PASSWORD"
    CHECKSUM = "CHECKSUM"
    ENCODING = "ENCODING"


@dataclass
class HashMatch:
    """A single possible hash type match."""
    name: str
    confidence: str  # HIGH / MEDIUM / LOW
    length: int
    category: str    # CRYPTOGRAPHIC / WEAK / PASSWORD / CHECKSUM / ENCODING
    crackable: bool
    note: str


@dataclass
class DetectionResult:
    """Full result for a hash input."""
    input_hash: str
    normalized_hash: str
    is_valid_hex: bool
    is_base64: bool
    matches: list[HashMatch] = field(default_factory=list)
    error: Optional[str] = None


# ── Hash type definitions ──
# Each entry: (name, length, charset_pattern, category, crackable, note)
HASH_TYPES = [
    # Checksums
    ("CRC32", 8, r"^[0-9a-f]{8}$", Category.CHECKSUM, False, "CRC32 checksum — not a cryptographic hash"),

    # MySQL
    ("MySQL4", 16, r"^[0-9a-f]{16}$", Category.WEAK, True, "MySQL 3.x hash — weak algorithm"),

    # LM Hash
    ("LM Hash", 32, r"^[0-9A-F]{32}$", Category.WEAK, True, "LM Hash — extremely weak, crackable in seconds"),

    # NTLM
    ("NTLM", 32, r"^[0-9a-f]{32}$", Category.PASSWORD, True, "NTLM hash — crackable with wordlists"),

    # MD5
    ("MD5", 32, r"^[0-9a-f]{32}$", Category.WEAK, True, "MD5 is broken — avoid for security use"),

    # RIPEMD-160
    ("RIPEMD-160", 40, r"^[0-9a-f]{40}$", Category.CRYPTOGRAPHIC, True, "RIPEMD-160 — rare but crackable with wordlists"),

    # MySQL5 / SHA-1
    ("SHA-1", 40, r"^[0-9a-f]{40}$", Category.WEAK, True, "SHA-1 is deprecated — collision attacks exist"),
    ("MySQL5", 40, r"^[0-9a-f]{40}$", Category.WEAK, True, "MySQL 5.x hash — SHA-1 based"),

    # SHA-2 family
    ("SHA-224", 56, r"^[0-9a-f]{56}$", Category.CRYPTOGRAPHIC, True, "SHA-224 — secure but rare"),
    ("SHA-256", 64, r"^[0-9a-f]{64}$", Category.CRYPTOGRAPHIC, True, "SHA-256 — secure, crackable with weak passwords"),
    ("SHA3-256", 64, r"^[0-9a-f]{64}$", Category.CRYPTOGRAPHIC, True, "SHA3-256 — secure, crackable with weak passwords"),
    ("SHA-384", 96, r"^[0-9a-f]{96}$", Category.CRYPTOGRAPHIC, True, "SHA-384 — secure, crackable with weak passwords"),
    ("SHA-512", 128, r"^[0-9a-f]{128}$", Category.CRYPTOGRAPHIC, True, "SHA-512 — secure, crackable with weak passwords"),
    ("SHA3-512", 128, r"^[0-9a-f]{128}$", Category.CRYPTOGRAPHIC, True, "SHA3-512 — secure, crackable with weak passwords"),
    ("Whirlpool", 128, r"^[0-9a-f]{128}$", Category.CRYPTOGRAPHIC, True, "Whirlpool — secure, less common"),

    # bcrypt
    ("bcrypt", 60, r"^\$2[ab]\$\d{2}\$.{53}$", Category.PASSWORD, False, "bcrypt — intentionally slow, not crackable with wordlists"),

    # Argon2
    ("Argon2", 0, r"^\$argon2", Category.PASSWORD, False, "Argon2 — modern password hash, not crackable with wordlists"),
]


def _is_hex(s: str) -> bool:
    """Check if string is valid hexadecimal."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _is_base64(s: str) -> bool:
    """Check if string looks like base64."""
    if len(s) < 4:
        return False
    pattern = r"^[A-Za-z0-9+/]+=*$"
    return bool(re.match(pattern, s)) and len(s) % 4 == 0


def detect_hash(hash_input: str) -> DetectionResult:
    """Identify possible hash types for a given string.

    Args:
        hash_input: The hash string to analyze.

    Returns:
        DetectionResult with all possible matches.
    """
    if not hash_input or not hash_input.strip():
        return DetectionResult(input_hash="", normalized_hash="",
                               is_valid_hex=False, is_base64=False,
                               error="Empty input")

    normalized = hash_input.strip().lower()

    # Check if it's base64-encoded (not a hash)
    is_b64 = _is_base64(hash_input.strip()) and not _is_hex(normalized)

    # Check if valid hex
    is_hex = _is_hex(normalized)

    if not is_hex and not is_b64:
        return DetectionResult(input_hash=hash_input, normalized_hash=normalized,
                               is_valid_hex=False, is_base64=False,
                               error="Input is not valid hex or base64")

    matches: list[HashMatch] = []

    for name, length, pattern, category, crackable, note in HASH_TYPES:
        # Length check (0 means variable length like bcrypt/Argon2)
        if length > 0 and len(normalized) != length:
            continue

        # Pattern check
        if not re.match(pattern, normalized):
            continue

        # Determine confidence
        if name in ("Argon2",):
            confidence = Confidence.HIGH.value
        elif name == "bcrypt":
            confidence = Confidence.HIGH.value
        elif name == "CRC32":
            confidence = Confidence.HIGH.value
        elif name == "LM Hash":
            # LM is uppercase hex — HIGH if all uppercase
            if hash_input.strip().isupper():
                confidence = Confidence.HIGH.value
            else:
                confidence = Confidence.LOW.value
        elif name in ("SHA-224", "SHA-384"):
            confidence = Confidence.HIGH.value
        elif name in ("SHA-256", "SHA3-256"):
            # Same length — differentiate by noting both
            confidence = Confidence.MEDIUM.value
        elif name in ("SHA-512", "SHA3-512", "Whirlpool"):
            # All 128 hex chars
            confidence = Confidence.MEDIUM.value
        elif name in ("MD5", "NTLM"):
            # Both 32 hex — flag both
            confidence = Confidence.MEDIUM.value
        elif name in ("SHA-1", "MySQL5"):
            # Both 40 hex
            confidence = Confidence.MEDIUM.value
        elif name == "RIPEMD-160":
            confidence = Confidence.HIGH.value
        elif name == "MySQL4":
            confidence = Confidence.HIGH.value
        else:
            confidence = Confidence.LOW.value

        matches.append(HashMatch(
            name=name, confidence=confidence, length=len(normalized),
            category=category.value, crackable=crackable, note=note,
        ))

    # If base64, add a flag
    if is_b64 and not is_hex:
        matches.insert(0, HashMatch(
            name="Base64 (encoded, not hashed)",
            confidence=Confidence.HIGH.value, length=len(normalized),
            category=Category.ENCODING.value, crackable=False,
            note="This appears to be base64-encoded data, not a hash. Decode first.",
        ))

    if not matches:
        return DetectionResult(input_hash=hash_input, normalized_hash=normalized,
                               is_valid_hex=is_hex, is_base64=is_b64,
                               error="No matching hash types found")

    return DetectionResult(input_hash=hash_input, normalized_hash=normalized,
                           is_valid_hex=is_hex, is_base64=is_b64, matches=matches)
