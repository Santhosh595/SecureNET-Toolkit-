"""PathProbe — response filtering and interesting-detection logic."""

from __future__ import annotations

# Default codes we treat as worth reporting.
DEFAULT_SHOW = {200, 201, 202, 203, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 502, 503}

# Categories used for color + summary.
CAT_FOUND = {200, 201, 202, 203, 204}
CAT_REDIRECT = {301, 302, 303, 307, 308}
CAT_PROTECTED = {401, 403}
CAT_ERROR = {500, 502, 503, 504}

INTERESTING_WORDS = [
    "password", "passwd", "key", "secret", "token", "admin", "root",
    "config", "database", "credential", "apikey", "api_key", "private",
    "auth", "session", "login", "phpmyadmin", ".env",
]


def category(status: int) -> str:
    if status in CAT_FOUND:
        return "found"
    if status in CAT_REDIRECT:
        return "redirect"
    if status in CAT_PROTECTED:
        return "protected"
    if status in CAT_ERROR:
        return "error"
    return "other"


def is_interesting_text(text: str) -> bool:
    low = text.lower()
    return any(w in low for w in INTERESTING_WORDS)


def passes_filter(result: dict, *, show: set[int] | None = None,
                  hide: set[int] | None = None,
                  filter_size: int | None = None,
                  filter_size_range: tuple[int, int] | None = None,
                  filter_words: list[str] | None = None,
                  wildcard: dict | None = None) -> bool:
    """Return True if the result should be reported.

    Order of checks:
      1. explicit hide list wins
      2. if show set provided, status must be in it
      3. size filters
      4. word filters (body contains forbidden text)
      5. wildcard noise
    """
    show = show if show is not None else DEFAULT_SHOW
    hide = hide or set()

    status = result["status"]
    if status == 0:
        return False  # transport error
    if status in hide:
        return False
    if show is not None and status not in show:
        return False

    size = result["size"]
    if filter_size is not None and size == filter_size:
        return False
    if filter_size_range is not None:
        lo, hi = filter_size_range
        if lo <= size <= hi:
            return False

    if filter_words:
        low = result.get("_text", "").lower()
        if any(w.lower() in low for w in filter_words):
            return False

    if wildcard and wildcard.get("wildcard_200") or (wildcard and wildcard.get("wildcard_302")):
        # imported lazily to avoid circular import
        from baseline import is_wildcard_noise
        if is_wildcard_noise(wildcard, result):
            return False

    return True


def annotate_interesting(result: dict) -> dict:
    """Mark interesting flag based on body text + protected/error status."""
    text = result.get("_text", "")
    if is_interesting_text(text):
        result["interesting"] = True
    elif result["status"] in CAT_PROTECTED:
        result["interesting"] = True
    elif result["status"] in CAT_ERROR:
        result["interesting"] = True
    else:
        result["interesting"] = False
    return result
