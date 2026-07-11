"""CloudSentry — GCP Compute checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.gcp.iam_checks import _info, _guard


def c_gce_001(connector, meta):  # SSH 0.0.0.0/0
    def fn(c, m):
        compute = c.client("compute")
        if compute is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_gce_002(connector, meta):  # RDP 0.0.0.0/0
    def fn(c, m):
        compute = c.client("compute")
        if compute is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_gce_003(connector, meta):  # default SA
    def fn(c, m):
        compute = c.client("compute")
        if compute is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


GCP_COMPUTE_CHECKS = {"GCP-GCE-001": c_gce_001, "GCP-GCE-002": c_gce_002, "GCP-GCE-003": c_gce_003}
