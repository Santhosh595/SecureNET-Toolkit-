"""CloudSentry — Azure Network (NSG) checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.azure.iam_checks import _info, _guard


def c_nsg_001(connector, meta):  # SSH from internet
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_nsg_002(connector, meta):  # RDP from internet
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_nsg_003(connector, meta):  # network watcher
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


AZ_NSG_CHECKS = {"AZ-NSG-001": c_nsg_001, "AZ-NSG-002": c_nsg_002, "AZ-NSG-003": c_nsg_003}
