"""SecretSniff - Allowlist management.

Supports ignoring findings by rule, path, pattern, or commit.
Loads from .secretsniff-ignore file and global config.
"""

from __future__ import annotations

import json
import time
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AllowlistEntry:
    """A single allowlist entry."""
    type: str  # rule, path, pattern, commit
    value: str
    reason: str = ""
    added_by: str = ""
    added_at: float = field(default_factory=time.time)


class Allowlist:
    """Manages allowlisted findings to suppress false positives."""

    def __init__(self, ignore_file: Optional[Path] = None):
        self.entries: list[AllowlistEntry] = []
        if ignore_file and ignore_file.exists():
            self.load_ignore_file(ignore_file)

    def load_ignore_file(self, path: Path) -> None:
        """Load allowlist from .secretsniff-ignore file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Format: type:value or just value (defaults to pattern)
                    if ":" in line and line.split(":")[0] in ("rule", "path", "pattern", "commit"):
                        entry_type, value = line.split(":", 1)
                        self.entries.append(AllowlistEntry(type=entry_type.strip(), value=value.strip()))
                    else:
                        self.entries.append(AllowlistEntry(type="pattern", value=line))
        except (OSError, PermissionError):
            pass

    def load_global_config(self, config_path: Path) -> None:
        """Load allowlist entries from global config YAML."""
        try:
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            if config and "allowlist" in config:
                allowlist_config = config["allowlist"]
                for rule in allowlist_config.get("rules", []):
                    self.add_rule(str(rule))
                for path_pattern in allowlist_config.get("paths", []):
                    self.add_path(str(path_pattern))
                for pattern in allowlist_config.get("patterns", []):
                    self.add_pattern(str(pattern))
                for commit in allowlist_config.get("commits", []):
                    self.add_commit(str(commit))
        except ImportError:
            pass
        except (OSError, KeyError, Exception):
            pass

    def add_rule(self, rule_name: str, reason: str = "") -> None:
        """Add a rule name to allowlist."""
        self.entries.append(AllowlistEntry(type="rule", value=rule_name, reason=reason))

    def add_path(self, path_pattern: str, reason: str = "") -> None:
        """Add a path pattern to allowlist."""
        self.entries.append(AllowlistEntry(type="path", value=path_pattern, reason=reason))

    def add_pattern(self, pattern: str, reason: str = "") -> None:
        """Add a value pattern to allowlist."""
        self.entries.append(AllowlistEntry(type="pattern", value=pattern, reason=reason))

    def add_commit(self, commit_hash: str, reason: str = "") -> None:
        """Add a commit hash to allowlist."""
        self.entries.append(AllowlistEntry(type="commit", value=commit_hash, reason=reason))

    def is_allowlisted(self, finding: dict) -> bool:
        """Check if a finding should be suppressed.

        Args:
            finding: Finding dict with rule, file, commit_hash, value.

        Returns:
            True if finding is allowlisted.
        """
        for entry in self.entries:
            if entry.type == "rule" and finding.get("rule") == entry.value:
                return True
            elif entry.type == "path" and entry.value in finding.get("file", ""):
                return True
            elif entry.type == "pattern" and entry.value in finding.get("value", ""):
                return True
            elif entry.type == "commit" and finding.get("commit_hash") == entry.value:
                return True
        return False

    def filter_findings(self, findings: list[dict]) -> list[dict]:
        """Filter out allowlisted findings.

        Args:
            findings: List of finding dicts.

        Returns:
            Filtered list with allowlisted flag set.
        """
        for finding in findings:
            finding["allowlisted"] = self.is_allowlisted(finding)
        return findings

    def save(self, path: Path) -> None:
        """Save allowlist to file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write("# SecretSniff Allowlist\n")
            f.write("# Format: type:value or just pattern\n")
            f.write("# Types: rule, path, pattern, commit\n\n")
            for entry in self.entries:
                if entry.reason:
                    f.write(f"# {entry.reason}\n")
                f.write(f"{entry.type}:{entry.value}\n")

    def remove(self, entry_type: str, value: str) -> bool:
        """Remove an allowlist entry."""
        for i, entry in enumerate(self.entries):
            if entry.type == entry_type and entry.value == value:
                self.entries.pop(i)
                return True
        return False
