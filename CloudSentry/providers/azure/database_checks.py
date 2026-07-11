"""CloudSentry — Azure Database checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.azure.iam_checks import _info, _guard


def c_db_001(connector, meta):  # SQL auditing
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_db_002(connector, meta):  # TDE
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_db_003(connector, meta):  # threat detection
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


AZ_DB_CHECKS = {"AZ-DB-001": c_db_001, "AZ-DB-002": c_db_002, "AZ-DB-003": c_db_003}
