"""PathProbe — wordlist loading, merging, dedup, extension fuzzing and prefixing."""

from __future__ import annotations

import os
from pathlib import Path

BUILTIN = {
    "common": "wordlists/common.txt",
    "api": "wordlists/api.txt",
    "files": "wordlists/files.txt",
    "large": "wordlists/large.txt",
}

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent


def resolve_builtin(name: str) -> str | None:
    if name in BUILTIN:
        return str(_ROOT / BUILTIN[name])
    return None


def load_wordlist_file(path: str) -> list[str]:
    """Load words from a file. Returns [] if missing. UTF-8 with fallback."""
    p = Path(path)
    if not p.is_file():
        # try relative to PathProbe root
        p = _ROOT / path
    if not p.is_file():
        return []
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = p.read_text(encoding="utf-8", errors="replace")
    out = []
    for line in text.splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        out.append(w)
    return out


def build_wordlist(spec: str, extensions: list[str] | None = None,
                   prefix: str = "", no_original: bool = False) -> list[str]:
    """Build the final request-word list from a spec.

    spec examples:
        "common"                 -> built-in wordlist
        "wordlists/api.txt"      -> file path
        "a.txt,b.txt"            -> multiple files merged + deduped
        "common,api"             -> built-in + built-in merged

    extensions: e.g. ["php","bak"] -> append .ext to each word (and keep bare
                unless no_original).
    prefix: e.g. "/api/v1" -> prepend to each word.
    """
    merged: list[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        builtin_path = resolve_builtin(part)
        if builtin_path:
            words = load_wordlist_file(builtin_path)
        else:
            words = load_wordlist_file(part)
        merged.extend(words)

    # dedupe (case-sensitive, preserve first occurrence)
    seen: set[str] = set()
    deduped: list[str] = []
    for w in merged:
        if w not in seen:
            seen.add(w)
            deduped.append(w)

    # prefixing
    if prefix:
        pref = prefix.strip().strip("/")
        deduped = [f"{pref}/{w}" if not w.startswith("/") else f"{pref}{w}" for w in deduped]

    # extension fuzzing
    if extensions:
        fuzzed: list[str] = []
        for w in deduped:
            base = w
            # strip leading slash for extension join cleanliness but keep path
            if not no_original:
                fuzzed.append(w)
            for ext in extensions:
                ext = ext.strip().lstrip(".")
                if base.endswith("/"):
                    fuzzed.append(f"{base.strip('/')}.{ext}")
                else:
                    fuzzed.append(f"{base}.{ext}")
        # re-dedupe
        seen2: set[str] = set()
        out: list[str] = []
        for w in fuzzed:
            if w not in seen2:
                seen2.add(w)
                out.append(w)
        deduped = out
    return deduped


def wordlist_entry_count(name: str) -> int:
    builtin_path = resolve_builtin(name)
    if builtin_path:
        return len(load_wordlist_file(builtin_path))
    return len(load_wordlist_file(name))


def available_wordlists() -> list[dict]:
    out = []
    for name, rel in BUILTIN.items():
        p = _ROOT / rel
        out.append({"name": name, "path": rel, "entry_count": len(load_wordlist_file(str(p))), "built_in": True})
    # scan wordlists/ dir for custom files
    wl_dir = _ROOT / "wordlists"
    if wl_dir.is_dir():
        for f in sorted(wl_dir.glob("*.txt")):
            base = f.stem
            if base in BUILTIN:
                continue
            out.append({"name": base, "path": f"wordlists/{f.name}", "entry_count": len(load_wordlist_file(str(f))), "built_in": False})
    return out
