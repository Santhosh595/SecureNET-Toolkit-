"""SecretSniff — File and directory scanner.

Recursively scans files, respects .gitignore, skips binaries.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Generator

from patterns.rules import get_patterns, SecretPattern
from scanner.entropy import find_high_entropy_strings, has_secret_context

# Binary file extensions to skip
BINARY_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".o", ".a", ".dylib", ".dll", ".exe",
    ".bin", ".wasm", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z",
    ".rar", ".jar", ".war", ".ear",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".ttf", ".otf", ".woff", ".woff2",
    ".sqlite", ".db", ".mdb",
    ".min.js", ".min.css", ".map",
}

# Test/fixture patterns to skip by default
TEST_PATTERNS = [
    r".*_test\.", r".*test_.*", r".*\.test\.", r".*spec_.*",
    r".*\.example$", r".*\.sample$", r".*\.fixture$",
    r".*/test/.*", r".*/tests/.*", r".*/fixtures/.*",
    r".*/docs/.*", r".*\.md$", r".*\.rst$",
]

# Inline ignore pattern
IGNORE_INLINE_PATTERN = re.compile(r"#\s*secretsniff:ignore", re.IGNORECASE)


def is_binary_file(path: Path) -> bool:
    """Check if a file is binary by extension and content."""
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    # Check for null bytes in first 1024 bytes
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except (OSError, PermissionError):
        return True
    return False


def is_test_file(path: Path) -> bool:
    """Check if a file is a test/fixture file."""
    name = path.name
    for pattern in TEST_PATTERNS:
        if re.match(pattern, name):
            return True
    return False


def should_skip_path(path: Path, respect_gitignore: bool = True) -> bool:
    """Check if a path should be skipped."""
    name = path.name
    # Always skip hidden dirs and common non-code dirs
    skip_dirs = {".git", ".svn", "node_modules", "__pycache__", ".tox",
                 ".eggs", "*.egg-info", "vendor", "dist", "build", ".mypy_cache"}
    if name in skip_dirs:
        return True
    if name.startswith(".") and name not in {".env", ".envrc"}:
        return True
    return False


def iter_files(base_path: Path, respect_gitignore: bool = True,
                include_tests: bool = False) -> Generator[Path, None, None]:
    """Iterate over files to scan.

    Args:
        base_path: Root directory to scan.
        respect_gitignore: Whether to respect .gitignore.
        include_tests: Whether to include test files.

    Yields:
        Path objects for files to scan.
    """
    if base_path.is_file():
        if not is_binary_file(base_path):
            yield base_path
        return

    for root, dirs, files in os.walk(base_path):
        root_path = Path(root)

        # Filter directories
        dirs[:] = [d for d in dirs if not should_skip_path(root_path / d, respect_gitignore)]

        for filename in files:
            file_path = root_path / filename

            if should_skip_path(file_path, respect_gitignore):
                continue

            if not include_tests and is_test_file(file_path):
                continue

            if is_binary_file(file_path):
                continue

            yield file_path


def scan_file(file_path: Path, patterns: list[SecretPattern],
              use_entropy: bool = True, entropy_threshold: float = 4.5,
              max_file_size: int = 10 * 1024 * 1024) -> list[dict]:
    """Scan a single file for secrets.

    Args:
        file_path: Path to file.
        patterns: List of detection patterns.
        use_entropy: Whether to use entropy analysis.
        entropy_threshold: Entropy threshold for detection.
        max_file_size: Maximum file size to scan (bytes).

    Returns:
        List of finding dicts.
    """
    findings = []

    try:
        # Check file size
        stat = file_path.stat()
        if stat.st_size > max_file_size:
            return findings

        # Read file
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, PermissionError):
        return findings

    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        # Check for inline ignore
        if IGNORE_INLINE_PATTERN.search(line):
            continue

        # Check each pattern
        for pattern in patterns:
            for match in pattern.search(line):
                matched_value = match.group(1) if match.lastindex else match.group(0)
                findings.append({
                    "file": str(file_path),
                    "line": line_num,
                    "rule": pattern.name,
                    "severity": pattern.severity,
                    "confidence": pattern.confidence,
                    "value": matched_value,
                    "value_redacted": _redact_value(matched_value),
                    "entropy": None,
                    "context": line.strip()[:200],
                    "commit_hash": None,
                    "author": None,
                    "date": None,
                    "allowlisted": False,
                })

        # Entropy analysis
        if use_entropy and has_secret_context(line):
            entropy_matches = find_high_entropy_strings(line, entropy_threshold)
            for em in entropy_matches:
                # Skip if already caught by a pattern
                already_found = any(
                    f["line"] == line_num and f["value"] == em["value"]
                    for f in findings
                )
                if not already_found:
                    findings.append({
                        "file": str(file_path),
                        "line": line_num,
                        "rule": "High Entropy String",
                        "severity": "MEDIUM",
                        "confidence": "LOW",
                        "value": em["value"],
                        "value_redacted": _redact_value(em["value"]),
                        "entropy": em["entropy"],
                        "context": line.strip()[:200],
                        "commit_hash": None,
                        "author": None,
                        "date": None,
                        "allowlisted": False,
                    })

    return findings


def _redact_value(value: str) -> str:
    """Redact a secret value, showing first 4 and last 4 chars."""
    if len(value) <= 8:
        return value[:2] + "****" + value[-2:]
    return value[:4] + "****" + value[-4:]
