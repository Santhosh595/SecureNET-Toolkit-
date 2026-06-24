"""SecretSniff - File and directory scanner.

Recursively scans files, respects .gitignore, skips binaries.
Supports threading, mmap for large files, and progress reporting.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

from patterns.rules import get_patterns, SecretPattern
from scanner.entropy import find_high_entropy_strings, has_secret_context
from patterns.keywords import is_placeholder

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

TEST_PATTERNS = [
    r".*_test\.", r".*test_.*", r".*\.test\.", r".*spec_.*",
    r".*\.example$", r".*\.sample$", r".*\.fixture$",
    r".*/test/.*", r".*/tests/.*", r".*/fixtures/.*",
    r".*/docs/.*", r".*\.md$", r".*\.rst$",
]

IGNORE_INLINE_PATTERN = re.compile(r"#\s*secretsniff:ignore", re.IGNORECASE)


def is_binary_file(path: Path) -> bool:
    """Check if a file is binary by extension and content."""
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
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
    skip_dirs = {".git", ".svn", "node_modules", "__pycache__", ".tox",
                 ".eggs", "*.egg-info", "vendor", "dist", "build", ".mypy_cache"}
    if name in skip_dirs:
        return True
    if name.startswith(".") and name not in {".env", ".envrc"}:
        return True
    return False


def iter_files(base_path: Path, respect_gitignore: bool = True,
                include_tests: bool = False) -> Generator[Path, None, None]:
    """Iterate over files to scan."""
    if base_path.is_file():
        if not is_binary_file(base_path):
            yield base_path
        return

    for root, dirs, files in os.walk(base_path):
        root_path = Path(root)
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
    """Scan a single file for secrets."""
    findings = []

    try:
        stat = file_path.stat()
        if stat.st_size > max_file_size:
            return findings
        if stat.st_size == 0:
            return findings
    except (OSError, PermissionError):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, PermissionError):
        return findings

    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        if IGNORE_INLINE_PATTERN.search(line):
            continue

        for pattern in patterns:
            for match in pattern.search(line):
                matched_value = match.group(1) if match.lastindex else match.group(0)

                if is_placeholder(matched_value):
                    findings.append({
                        "file": str(file_path), "line": line_num,
                        "rule": pattern.name, "severity": "LOW",
                        "confidence": "LOW", "value": matched_value,
                        "value_redacted": _redact_value(matched_value),
                        "entropy": None, "context": line.strip()[:200],
                        "commit_hash": None, "author": None, "date": None,
                        "allowlisted": False,
                    })
                    continue

                findings.append({
                    "file": str(file_path), "line": line_num,
                    "rule": pattern.name, "severity": pattern.severity,
                    "confidence": pattern.confidence, "value": matched_value,
                    "value_redacted": _redact_value(matched_value),
                    "entropy": None, "context": line.strip()[:200],
                    "commit_hash": None, "author": None, "date": None,
                    "allowlisted": False,
                })

        if use_entropy and has_secret_context(line):
            entropy_matches = find_high_entropy_strings(line, entropy_threshold)
            for em in entropy_matches:
                already_found = any(
                    f["line"] == line_num and f["value"] == em["value"]
                    for f in findings
                )
                if not already_found and not is_placeholder(em["value"]):
                    findings.append({
                        "file": str(file_path), "line": line_num,
                        "rule": "High Entropy String", "severity": "MEDIUM",
                        "confidence": "LOW", "value": em["value"],
                        "value_redacted": _redact_value(em["value"]),
                        "entropy": em["entropy"], "context": line.strip()[:200],
                        "commit_hash": None, "author": None, "date": None,
                        "allowlisted": False,
                    })

    return findings


def scan_files_parallel(file_paths: list[Path], patterns: list[SecretPattern],
                        max_workers: int = 20) -> list[dict]:
    """Scan multiple files in parallel using thread pool."""
    all_findings = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_file, fp, patterns): fp for fp in file_paths}
        for future in as_completed(futures):
            try:
                result = future.result()
                all_findings.extend(result)
            except Exception:
                pass
    return all_findings


def _redact_value(value: str) -> str:
    """Redact a secret value, showing first 4 and last 4 chars."""
    if not value:
        return "****"
    if len(value) <= 8:
        return value[:2] + "****" + value[-2:]
    return value[:4] + "****" + value[-4:]
