"""SecretSniff - Git repository scanner.

Scans git working tree and commit history for secrets.
Uses gitpython for reliable git access.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from patterns.rules import get_patterns
from scanner.file_scanner import scan_file, _redact_value


def is_git_repo(path: Path) -> bool:
    """Check if path is inside a git repository."""
    try:
        import git
        git.Repo(str(path), search_parent_directories=True)
        return True
    except Exception:
        pass    # Fallback to subprocess
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=str(path), capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def get_repo_root(path: Path) -> Optional[Path]:
    """Get git repository root."""
    try:
        import git
        repo = git.Repo(str(path), search_parent_directories=True)
        return Path(repo.working_tree_dir)
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path), capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except Exception:
        pass
    return None


def scan_git_history(repo_path: Path, depth: int = 0,
                     include_tests: bool = False) -> list[dict]:
    """Scan git commit history for secrets.

    Args:
        repo_path: Path to git repository.
        depth: Max commits to scan (0 = all).
        include_tests: Whether to include test files.

    Returns:
        List of finding dicts with commit info.
    """
    findings = []
    patterns = get_patterns()

    try:
        import git
        repo = git.Repo(str(repo_path))

        # Build commit list
        commits = list(repo.iter_commits(max_count=depth if depth > 0 else None))

        for commit in commits:
            for blob in commit.tree.traverse():
                if blob.type != "blob":
                    continue

                file_name = str(blob.path)

                # Skip binary and large files
                try:
                    if blob.size > 10 * 1024 * 1024:
                        continue
                except Exception:
                    continue

                # Read blob content
                try:
                    content = blob.data_stream.read().decode("utf-8", errors="ignore")
                except Exception:
                    continue

                # Write to temp and scan
                with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp",
                                                  delete=False, encoding="utf-8") as tmp:
                    tmp.write(content)
                    tmp_path = Path(tmp.name)

                try:
                    file_findings = scan_file(tmp_path, patterns)
                    for f in file_findings:
                        f["file"] = file_name
                        f["commit_hash"] = commit.hexsha[:8]
                        f["author"] = commit.author.name or "unknown"
                        f["date"] = commit.committed_datetime.isoformat()
                    findings.extend(file_findings)
                finally:
                    tmp_path.unlink(missing_ok=True)

    except ImportError:
        # Fallback to subprocess method
        findings = _scan_git_history_subprocess(repo_path, depth, include_tests, patterns)
    except Exception:
        pass

    return findings


def _scan_git_history_subprocess(repo_path: Path, depth: int, include_tests: bool,
                                  patterns: list) -> list[dict]:
    """Fallback git history scan using subprocess."""
    findings = []

    try:
        cmd = ["git", "log", "--format=%H|%an|%ae|%ai", "--name-only"]
        if depth > 0:
            cmd.extend(["-n", str(depth)])
        result = subprocess.run(
            cmd, cwd=str(repo_path), capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return findings

        blocks = result.stdout.split("\n\n")
        for block in blocks:
            lines = block.strip().split("\n")
            if not lines:
                continue

            parts = lines[0].split("|", 3)
            if len(parts) < 4:
                continue
            commit_hash, author, email, date = parts

            file_names = [l.strip() for l in lines[1:] if l.strip()]
            for file_name in file_names:
                try:
                    content_result = subprocess.run(
                        ["git", "show", f"{commit_hash}:{file_name}"],
                        cwd=str(repo_path), capture_output=True, text=True, timeout=10
                    )
                    if content_result.returncode != 0:
                        continue
                except Exception:
                    continue

                with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp",
                                                  delete=False, encoding="utf-8") as tmp:
                    tmp.write(content_result.stdout)
                    tmp_path = Path(tmp.name)

                try:
                    file_findings = scan_file(tmp_path, patterns)
                    for f in file_findings:
                        f["file"] = file_name
                        f["commit_hash"] = commit_hash[:8]
                        f["author"] = author
                        f["date"] = date
                    findings.extend(file_findings)
                finally:
                    tmp_path.unlink(missing_ok=True)

    except Exception:
        pass

    return findings


def scan_git_worktree(repo_path: Path, include_tests: bool = False) -> list[dict]:
    """Scan current working tree of a git repository.

    Args:
        repo_path: Path to git repository.
        include_tests: Whether to include test files.

    Returns:
        List of finding dicts.
    """
    from scanner.file_scanner import iter_files
    patterns = get_patterns()
    findings = []

    for file_path in iter_files(repo_path, respect_gitignore=True, include_tests=include_tests):
        file_findings = scan_file(file_path, patterns)
        for f in file_findings:
            try:
                f["file"] = str(file_path.relative_to(repo_path))
            except ValueError:
                f["file"] = str(file_path)
        findings.extend(file_findings)

    return findings
