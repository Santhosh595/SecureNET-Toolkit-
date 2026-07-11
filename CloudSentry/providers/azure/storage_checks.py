"""CloudSentry — Azure Storage checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.azure.iam_checks import _info, _guard


def c_stg_001(connector, meta):  # public blob
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_stg_002(connector, meta):  # https only
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_stg_003(connector, meta):  # encryption
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


AZ_STG_CHECKS = {"AZ-STG-001": c_stg_001, "AZ-STG-002": c_stg_002, "AZ-STG-003": c_stg_003}
