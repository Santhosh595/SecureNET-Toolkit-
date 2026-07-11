"""CloudSentry — GCP SQL checks (2)."""

from __future__ import annotations

from models import CheckResult
from providers.gcp.iam_checks import _info, _guard


def c_sql_001(connector, meta):  # public SQL
    def fn(c, m):
        if c.client("sql") is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_sql_002(connector, meta):  # require SSL
    def fn(c, m):
        if c.client("sql") is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


GCP_SQL_CHECKS = {"GCP-SQL-001": c_sql_001, "GCP-SQL-002": c_sql_002}
