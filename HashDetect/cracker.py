"""HashDetect — Wordlist-based hash cracking.

Attempts to crack hashes using a built-in wordlist or custom wordlist.
Fully local processing — no external APIs.
"""

from __future__ import annotations

import hashlib
import time
from typing import Optional, Callable


def load_wordlist(path: str) -> list[str]:
    """Load a wordlist file (one word per line)."""
    words = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word:
                    words.append(word)
    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist not found: {path}")
    except Exception as e:
        raise RuntimeError(f"Error reading wordlist: {e}")
    return words


def get_hash_function(hash_name: str):
    """Return the hashlib function for a given hash type name."""
    mapping = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-224": hashlib.sha224,
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "SHA3-256": hashlib.sha3_256,
        "SHA3-512": hashlib.sha3_512,
        "RIPEMD-160": lambda d: hashlib.new("ripemd160", d),
    }
    return mapping.get(hash_name)


def crack_hash(
    target_hash: str,
    hash_name: str,
    words: list[str],
    timeout: float = 30.0,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> tuple[Optional[str], int, float]:
    """Attempt to crack a hash using a wordlist.

    Args:
        target_hash: The hash to crack (lowercase hex).
        hash_name: The hash algorithm name.
        words: List of candidate passwords.
        timeout: Maximum time in seconds.
        progress_callback: Called with (attempted, total) periodically.

    Returns:
        (plaintext_or_None, words_attempted, time_elapsed)
    """
    hash_func = get_hash_function(hash_name)
    if hash_func is None:
        return (None, 0, 0.0)

    normalized = target_hash.lower().strip()
    total = len(words)
    start = time.time()

    for i, word in enumerate(words):
        # Check timeout
        if time.time() - start > timeout:
            return (None, i, round(time.time() - start, 2))

        # Hash the candidate
        candidate = hash_func(word.encode("utf-8")).hexdigest()
        if candidate == normalized:
            return (word, i + 1, round(time.time() - start, 2))

        # Progress callback every 100 words
        if progress_callback and i % 100 == 0:
            progress_callback(i, total)

    if progress_callback:
        progress_callback(total, total)
    return (None, total, round(time.time() - start, 2))
