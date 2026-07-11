"""CloudSentry — GCP Logging checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.gcp.iam_checks import _info, _guard


def c_log_001(connector, meta):  # audit logs
    def fn(c, m):
        if c.client("logging") is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_log_002(connector, meta):  # IAM change metric
    def fn(c, m):
        if c.client("logging") is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_log_003(connector, meta):  # ownership change metric
    def fn(c, m):
        if c.client("logging") is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


GCP_LOGGING_CHECKS = {"GCP-LOG-001": c_log_001, "GCP-LOG-002": c_log_002, "GCP-LOG-003": c_log_003}
