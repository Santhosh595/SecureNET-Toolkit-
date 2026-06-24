"""SecretSniff — Shannon entropy calculator.

Detects high-entropy strings that are likely random secrets, keys, or tokens.
"""

from __future__ import annotations

import math
import re
from typing import Optional


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Args:
        data: Input string to analyze.

    Returns:
        Entropy value in bits (0-8 for byte-level).
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)

    # Count frequency of each character
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(data: str, threshold: float = 4.5) -> bool:
    """Check if a string has high entropy.

    Args:
        data: String to check.
        threshold: Entropy threshold (default 4.5 bits).

    Returns:
        True if entropy exceeds threshold.
    """
    if len(data) < 20:
        return False
    return calculate_entropy(data) >= threshold


def find_high_entropy_strings(text: str, threshold: float = 4.5,
                                min_length: int = 20,
                                max_length: int = 500) -> list[dict]:
    """Find high-entropy strings in text.

    Args:
        text: Input text to scan.
        threshold: Entropy threshold.
        min_length: Minimum string length to consider.
        max_length: Maximum string length to consider.

    Returns:
        List of dicts with 'value', 'entropy', 'position'.
    """
    results = []

    # Extract quoted strings and base64-like strings
    patterns = [
        r'["\']([A-Za-z0-9+/=_\-]{' + str(min_length) + r',' + str(max_length) + r'})["\']',
        r'\b([A-Za-z0-9+/=_\-]{' + str(min_length) + r',' + str(max_length) + r'})\b',
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, text):
            value = match.group(1)
            entropy = calculate_entropy(value)
            if entropy >= threshold:
                results.append({
                    "value": value,
                    "entropy": round(entropy, 2),
                    "position": match.start(),
                })

    return results


def has_secret_context(line: str) -> bool:
    """Check if a line contains secret-related keywords.

    Args:
        line: Text line to check.

    Returns:
        True if line contains secret-related keywords.
    """
    keywords = [
        "key", "secret", "token", "password", "api", "apikey",
        "auth", "credential", "private", "access", "bearer",
        "jwt", "session", "encrypt", "decrypt", "sign",
        "aws", "gcp", "azure", "github", "stripe", "twilio",
        "sendgrid", "mailgun", "slack", "webhook",
    ]
    line_lower = line.lower()
    return any(kw in line_lower for kw in keywords)
