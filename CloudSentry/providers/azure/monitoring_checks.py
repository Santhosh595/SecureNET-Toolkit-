"""CloudSentry — Azure Monitoring checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.azure.iam_checks import _info, _guard


def c_mon_001(connector, meta):  # policy alert
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_mon_002(connector, meta):  # nsg change alert
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_mon_003(connector, meta):  # keyvault diagnostics
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


AZ_MON_CHECKS = {"AZ-MON-001": c_mon_001, "AZ-MON-002": c_mon_002, "AZ-MON-003": c_mon_003}
