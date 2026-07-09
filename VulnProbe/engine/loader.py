"""Template YAML loader + schema validator.

Loads VulnProbe templates from a single file, a directory, or the
built-in ``templates/`` folder. Validates the schema before running and
detects duplicate template IDs (hard error). Invalid templates are
reported as WARNINGs and skipped by the caller.
"""

from __future__ import annotations

import glob
import os
import re

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PATHS_PER_TEMPLATE = 20
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_MATCHER_TYPES = {"status", "word", "regex", "size", "binary", "header"}
VALID_MATCH_PARTS = {"body", "header", "all"}
VALID_CONDITIONS = {"and", "or"}
VALID_COMPARISONS = {"gt", "lt", "eq", "gte", "lte"}

CATEGORY_BY_DIR = {
    "exposed-panels": "exposed-panels",
    "sensitive-files": "sensitive-files",
    "version-leak": "version-leak",
    "default-creds": "default-creds",
    "misconfiguration": "misconfiguration",
    "cve": "cve",
    "api-security": "api-security",
    "ssl-headers": "ssl-headers",
}

# Built-in template base directory (VulnProbe/templates)
_BUILTIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


class TemplateError(ValueError):
    """Raised when a template fails schema validation."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_template(data: dict, filename: str = "<string>") -> None:
    """Validate a template dict against the VulnProbe schema.

    Raises TemplateError describing the first problem found.
    """
    if not isinstance(data, dict):
        raise TemplateError(f"{filename}: top-level YAML must be a mapping")

    tid = data.get("id")
    if not tid or not isinstance(tid, str):
        raise TemplateError(f"{filename}: missing required string field 'id'")
    if not re.match(r"^[a-z0-9][a-z0-9._-]*$", tid):
        raise TemplateError(f"{filename}: template id '{tid}' is not slug-safe")

    name = data.get("name")
    if not name or not isinstance(name, str):
        raise TemplateError(f"{filename}: missing required string field 'name'")

    severity = str(data.get("severity", "info")).lower()
    if severity not in VALID_SEVERITIES:
        raise TemplateError(
            f"{filename}: severity '{data.get('severity')}' invalid "
            f"(must be one of {sorted(VALID_SEVERITIES)})"
        )
    data["severity"] = severity

    # category: infer from folder if absent, else must be a known slug
    category = data.get("category")
    if category is None:
        data["category"] = "uncategorized"
    elif not isinstance(category, str):
        raise TemplateError(f"{filename}: 'category' must be a string")

    tags = data.get("tags")
    if tags is not None and not isinstance(tags, list):
        raise TemplateError(f"{filename}: 'tags' must be a list")

    requests = data.get("requests")
    if not isinstance(requests, list) or not requests:
        raise TemplateError(f"{filename}: 'requests' must be a non-empty list")
    if len(requests) > 50:
        raise TemplateError(f"{filename}: too many requests (max 50)")

    for i, req in enumerate(requests):
        _validate_request(req, filename, i)

    # safe POST opt-in (read-only by default)
    safe = bool(data.get("safe", False))
    data["safe"] = safe
    if safe:
        for req in requests:
            if req.get("method", "GET").upper() != "GET":
                if not data.get("safe_reason"):
                    raise TemplateError(
                        f"{filename}: POST/non-GET request requires 'safe: true' "
                        f"AND a 'safe_reason' explaining why it is read-only"
                    )


def _validate_request(req: dict, filename: str, idx: int) -> None:
    if not isinstance(req, dict):
        raise TemplateError(f"{filename}: request[{idx}] must be a mapping")

    method = str(req.get("method", "GET")).upper()
    if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
        raise TemplateError(f"{filename}: request[{idx}] bad method '{method}'")

    paths = req.get("path", ["/"])
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list) or not paths:
        raise TemplateError(f"{filename}: request[{idx}] 'path' must be a non-empty list")
    if len(paths) > MAX_PATHS_PER_TEMPLATE:
        raise TemplateError(
            f"{filename}: request[{idx}] has {len(paths)} paths "
            f"(max {MAX_PATHS_PER_TEMPLATE})"
        )
    for p in paths:
        if not isinstance(p, str):
            raise TemplateError(f"{filename}: request[{idx}] path entries must be strings")

    # headers
    headers = req.get("headers")
    if headers is not None and not isinstance(headers, dict):
        raise TemplateError(f"{filename}: request[{idx}] 'headers' must be a mapping")

    matchers = req.get("matchers")
    if matchers is None:
        # single matcher block allowed at request level
        m = req.get("matcher")
        if m is None:
            raise TemplateError(f"{filename}: request[{idx}] needs 'matchers' or 'matcher'")
        # normalize: a single dict matcher -> one block
        if isinstance(m, dict) and "conditions" not in m:
            matchers = [{"operator": "or", "conditions": [m]}]
        else:
            matchers = [m]
    if isinstance(matchers, dict):
        # Nuclei-style block: {operator, conditions:[...]}
        matchers = [matchers]
    if not isinstance(matchers, list):
        raise TemplateError(f"{filename}: request[{idx}] 'matchers' must be a list/dict")
    normalized = []
    for block in matchers:
        if isinstance(block, dict) and "conditions" in block:
            conds = block["conditions"]
            if not isinstance(conds, list):
                raise TemplateError(f"{filename}: matcher block 'conditions' must be a list")
            for c in conds:
                _validate_matcher(c, filename, idx)
            normalized.append(block)
        else:
            _validate_matcher(block, filename, idx)
            normalized.append({"operator": str(block.get("operator", "or")).lower(),
                               "conditions": [block]})
    req["matchers"] = normalized  # canonical list form for the engine
    if not normalized:
        raise TemplateError(f"{filename}: request[{idx}] has no matchers")

    mcond = req.get("matchers_condition", "and")
    if str(mcond).lower() not in VALID_CONDITIONS:
        raise TemplateError(
            f"{filename}: request[{idx}] matchers_condition must be 'and'/'or'"
        )

    extractors = req.get("extractors")
    if extractors is not None:
        if not isinstance(extractors, list):
            raise TemplateError(f"{filename}: request[{idx}] 'extractors' must be a list")
        for ex in extractors:
            if not isinstance(ex, dict):
                raise TemplateError(f"{filename}: extractor must be a mapping")
            if ex.get("type") not in ("regex", "kval"):
                raise TemplateError(
                    f"{filename}: extractor type must be 'regex' or 'kval'"
                )


def _validate_matcher(m: dict, filename: str, idx: int) -> None:
    if not isinstance(m, dict):
        raise TemplateError(f"{filename}: request[{idx}] matcher must be a mapping")
    mtype = m.get("type")
    if mtype not in VALID_MATCHER_TYPES:
        raise TemplateError(
            f"{filename}: request[{idx}] matcher type '{mtype}' invalid "
            f"(must be one of {sorted(VALID_MATCHER_TYPES)})"
        )
    op = str(m.get("operator", "or")).lower()
    if op not in VALID_CONDITIONS:
        raise TemplateError(f"{filename}: request[{idx}] matcher operator must be 'and'/'or'")

    if mtype == "status":
        if not isinstance(m.get("values", []), list):
            raise TemplateError(f"{filename}: status matcher 'values' must be a list")
    elif mtype == "word":
        part = str(m.get("part", "body")).lower()
        if part not in VALID_MATCH_PARTS:
            raise TemplateError(f"{filename}: word matcher part '{part}' invalid")
        if not isinstance(m.get("words", []), list):
            raise TemplateError(f"{filename}: word matcher 'words' must be a list")
        if str(m.get("condition", "or")).lower() not in VALID_CONDITIONS:
            raise TemplateError(f"{filename}: word matcher condition must be 'and'/'or'")
    elif mtype == "regex":
        part = str(m.get("part", "body")).lower()
        if part not in VALID_MATCH_PARTS:
            raise TemplateError(f"{filename}: regex matcher part '{part}' invalid")
        pattern = m.get("pattern")
        if not isinstance(pattern, str):
            raise TemplateError(f"{filename}: regex matcher 'pattern' must be a string")
        try:
            re.compile(pattern)
        except re.error as e:
            raise TemplateError(f"{filename}: regex matcher bad pattern: {e}")
    elif mtype == "size":
        cmp = str(m.get("comparison", "gt")).lower()
        if cmp not in VALID_COMPARISONS:
            raise TemplateError(f"{filename}: size matcher comparison '{cmp}' invalid")
        if not isinstance(m.get("size"), int):
            raise TemplateError(f"{filename}: size matcher 'size' must be an integer")
    elif mtype == "binary":
        if not isinstance(m.get("hex"), str):
            raise TemplateError(f"{filename}: binary matcher 'hex' must be a string")
    elif mtype == "header":
        if not isinstance(m.get("header"), str):
            raise TemplateError(f"{filename}: header matcher 'header' must be a string")
        if not isinstance(m.get("values", []), list):
            raise TemplateError(f"{filename}: header matcher 'values' must be a list")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _load_one(path: str, seen_ids: set, category_hint: str | None = None) -> dict | None:
    """Load and validate a single YAML file. Returns template dict or None."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as e:
        raise TemplateError(f"{path}: failed to parse YAML: {e}")

    if not isinstance(data, dict):
        raise TemplateError(f"{path}: not a template mapping")

    # infer category from directory name
    if category_hint and data.get("category") in (None, "uncategorized"):
        data["category"] = category_hint

    validate_template(data, filename=os.path.basename(path))

    tid = data["id"]
    if tid in seen_ids:
        raise TemplateError(f"{path}: duplicate template id '{tid}'")
    seen_ids.add(tid)

    data["_file"] = os.path.basename(path)
    data["_built_in"] = category_hint is not None or path.startswith(_BUILTIN_DIR)
    return data


def load_templates(
    source=None,
    *,
    severity_filter=None,
    category_filter=None,
    tag_filter=None,
):
    """Load templates from a directory, file, or built-in templates.

    Args:
        source: path to a directory, a single .yaml/.yml file, or None to
            load all built-in templates.
        severity_filter: iterable of severity strings to keep (lower-cased).
        category_filter: iterable of category slugs to keep.
        tag_filter: iterable of tags; template kept if it has ANY of these.

    Returns:
        (templates, errors) where templates is a list of valid dicts and
        errors is a list of (filename, message) tuples for skipped templates.
    """
    seen_ids: set[str] = set()
    templates: list[dict] = []
    errors: list[tuple[str, str]] = []

    candidates: list[tuple[str, str | None]] = []  # (path, category_hint)

    if source is None:
        # all built-in category directories
        for dname, cat in CATEGORY_BY_DIR.items():
            dpath = os.path.join(_BUILTIN_DIR, dname)
            if os.path.isdir(dpath):
                for p in sorted(glob.glob(os.path.join(dpath, "*.y*ml"))):
                    candidates.append((p, cat))
    elif os.path.isfile(source):
        candidates.append((source, None))
    elif os.path.isdir(source):
        for p in sorted(glob.glob(os.path.join(source, "*.y*ml"))):
            candidates.append((p, None))
    else:
        errors.append((source, "path does not exist"))
        return templates, errors

    for path, cat in candidates:
        try:
            tpl = _load_one(path, seen_ids, cat)
        except TemplateError as e:
            errors.append((os.path.basename(path), str(e)))
            continue
        if tpl is None:
            continue
        # apply filters
        if severity_filter and tpl["severity"] not in severity_filter:
            continue
        if category_filter and tpl.get("category") not in category_filter:
            continue
        if tag_filter:
            ttags = set(str(t).lower() for t in (tpl.get("tags") or []))
            if not (ttags & set(tag_filter)):
                continue
        templates.append(tpl)

    return templates, errors


def builtin_template_count() -> int:
    """Return count of built-in templates available on disk."""
    count = 0
    for dname in CATEGORY_BY_DIR:
        dpath = os.path.join(_BUILTIN_DIR, dname)
        if os.path.isdir(dpath):
            count += len(glob.glob(os.path.join(dpath, "*.y*ml")))
    return count
