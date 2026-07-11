"""CloudSentry — GCP Network checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.gcp.iam_checks import _info, _guard


def c_net_001(connector, meta):  # flow logs
    def fn(c, m):
        if c.client("compute") is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_net_002(connector, meta):  # DNS logging
    def fn(c, m):
        if c.client("compute") is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_net_003(connector, meta):  # legacy networks
    def fn(c, m):
        if c.client("compute") is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


GCP_NETWORK_CHECKS = {"GCP-NET-001": c_net_001, "GCP-NET-002": c_net_002, "GCP-NET-003": c_net_003}
