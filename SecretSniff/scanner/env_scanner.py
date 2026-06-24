"""SecretSniff — Environment file scanner.

Targets .env files, docker-compose, k8s configs, terraform, etc.
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

from patterns.rules import get_patterns
from scanner.file_scanner import scan_file, _redact_value

# Environment file patterns (higher priority targets)
ENV_FILES = [
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test", ".envrc",
    "docker-compose.yml", "docker-compose.override.yml",
]

# Regex to match env file patterns
ENV_PATTERN = re.compile(
    r"(^|\.)env(\.[a-z]+)?$|\.envrc$|docker-compose.*\.ya?ml$",
    re.IGNORECASE
)

# Directories that commonly contain env/secrets
ENV_DIRS = ["kubernetes", "helm", "terraform", "ansible/vars", "ansible/group_vars"]

import re


def find_env_files(base_path: Path) -> Generator[Path, None, None]:
    """Find environment and configuration files.

    Args:
        base_path: Root directory to search.

    Yields:
        Path objects for environment files.
    """
    if base_path.is_file():
        if _is_env_file(base_path):
            yield base_path
        return

    for root, dirs, files in os.walk(base_path):
        root_path = Path(root)

        for filename in files:
            file_path = root_path / filename
            if _is_env_file(file_path):
                yield file_path


def _is_env_file(path: Path) -> bool:
    """Check if a file is an environment/config file."""
    name = path.name

    # Direct matches
    if name in ENV_FILES:
        return True

    # Pattern matches
    if ENV_PATTERN.search(name):
        return True

    # Directory-based matches
    try:
        relative = path.relative_to(path.anchor) if path.is_absolute() else path
        for env_dir in ENV_DIRS:
            if env_dir in relative.parts:
                return True
    except (ValueError, TypeError):
        pass

    # Specific patterns
    if name.endswith(".tfvars") or name.endswith(".tf"):
        return True
    if name.endswith(".yaml") or name.endswith(".yml"):
        if any(d in path.parts for d in ["kubernetes", "k8s", "helm"]):
            return True

    return False


def scan_env_files(base_path: Path, include_tests: bool = False) -> list[dict]:
    """Scan environment files for secrets.

    Args:
        base_path: Root directory.
        include_tests: Whether to include test files.

    Returns:
        List of finding dicts.
    """
    patterns = get_patterns()
    findings = []

    for file_path in find_env_files(base_path):
        file_findings = scan_file(file_path, patterns, use_entropy=True)
        for f in file_findings:
            # Env file findings are higher severity
            if f["severity"] == "MEDIUM":
                f["severity"] = "HIGH"
        findings.extend(file_findings)

    return findings


import os
