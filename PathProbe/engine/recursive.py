"""PathProbe — recursive directory scan manager + tree builder."""

from __future__ import annotations

from engine import requester, filter as filt


def is_directory_candidate(result: dict, recursive_status: set[int]) -> bool:
    """A found path is a recursion candidate if its status is in the
    recursive set AND it looks like a directory (ends with / or the
    redirect target suggests a trailing-slash dir)."""
    if result["status"] not in recursive_status:
        return False
    word = result.get("word", "")
    if word.endswith("/"):
        return True
    # 301 to same path + "/" => directory
    rt = result.get("redirect_to") or ""
    if result["status"] in (301, 302) and rt.endswith("/") and rt.rstrip("/").endswith(word.rstrip("/")):
        return True
    return False


def build_tree(findings: list[dict]) -> dict:
    """Build a nested dict tree from finding URLs for the dashboard view.

    Each node: { "name": str, "children": {name: node}, "finding": dict|None }
    """
    root: dict = {"name": "", "children": {}, "finding": None}
    for f in findings:
        parts = [p for p in f["url"].split("/") if p]
        # strip scheme/host: keep path parts only
        # find first path segment after host
        from urllib.parse import urlparse
        path = urlparse(f["url"]).path
        segs = [s for s in path.split("/") if s]
        node = root
        for seg in segs:
            node = node["children"].setdefault(seg, {"name": seg, "children": {}, "finding": None})
        node["finding"] = f
    return root


def render_tree(node: dict, prefix: str = "", lines: list[str] | None = None) -> list[str]:
    """Render the tree as indented text lines."""
    if lines is None:
        lines = []
    children = sorted(node["children"].values(), key=lambda c: c["name"])
    for i, child in enumerate(children):
        last = i == len(children) - 1
        conn = "└── " if last else "├── "
        f = child["finding"]
        tag = ""
        if f:
            status = f.get("status")
            cat = filt.category(status) if status else "other"
            icon = {"found": "", "redirect": "→", "protected": "⚠",
                    "error": "✖", "other": ""}.get(cat, "")
            interesting = " ★ INTERESTING" if f.get("interesting") else ""
            tag = f" [{status}] {icon}{interesting}".rstrip()
        lines.append(f"{prefix}{conn}{child['name']}{tag}")
        render_tree(child, prefix + ("    " if last else "│   "), lines)
    return lines
