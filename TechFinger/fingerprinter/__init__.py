"""TechFinger — fingerprinter package."""

from __future__ import annotations

from .fetcher import fetch, Response, BROWSER_UA
from .engine import (
    fingerprint, match_tech, check_headers, correlate_cves,
    TechResult, HeaderCheck, CveCorrelation,
)
from .version_extractor import extract, normalize
from .confidence import score, label_for
from .favicon import match_favicon, favicon_md5

__all__ = [
    "fetch", "Response", "BROWSER_UA", "fingerprint", "match_tech",
    "check_headers", "correlate_cves", "TechResult", "HeaderCheck",
    "CveCorrelation", "extract", "normalize", "score", "label_for",
    "match_favicon", "favicon_md5",
]
