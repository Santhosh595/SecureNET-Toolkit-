"""VulnProbe engine package.

Submodules:
    loader       -- YAML template loading + schema validation
    scanner      -- HTTP request engine (session, rate limiting, threads)
    matchers     -- all 6 matcher type implementations
    extractors   -- value extraction logic
    ratelimiter  -- per-host request rate limiter
"""

from .loader import load_templates, validate_template, TemplateError
from .scanner import Scanner
from .matchers import evaluate_matcher
from .extractors import run_extractors
from .ratelimiter import RateLimiter

__all__ = [
    "load_templates",
    "validate_template",
    "TemplateError",
    "Scanner",
    "evaluate_matcher",
    "run_extractors",
    "RateLimiter",
]
