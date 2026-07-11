"""CloudSentry — Azure IAM checks (3)."""

from __future__ import annotations

from models import CheckResult


def _info(connector, meta) -> CheckResult:
    return CheckResult(check_id=meta["id"], name=meta["name"], provider="azure", category=meta["category"],
                       status="INFO", severity=meta["severity"], description=meta["description"],
                       risk=meta["risk"], remediation=meta["remediation"],
                       cis_ref=meta["cis"], owasp_ref=meta["owasp"],
                       affected=["(manual verification required)"])


def _guard(fn, connector, meta):
    if not connector.available:
        return _info(connector, meta)
    try:
        return fn(connector, meta)
    except Exception as e:
        msg = str(e)
        return CheckResult(check_id=meta["id"], name=meta["name"], provider="azure", category=meta["category"],
                           status="ERROR", severity=meta["severity"], description=f"Check error: {msg[:160]}",
                           remediation=meta["remediation"], cis_ref=meta["cis"], owasp_ref=meta["owasp"])


def c_iam_001(connector, meta):  # MFA for all users
    def fn(c, m):
        from azure.graphrbac import GraphRbacManagementClient  # type: ignore
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_iam_002(connector, meta):  # no guest admin
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_iam_003(connector, meta):  # custom owner roles minimized
    def fn(c, m):
        if c._cred is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


AZ_IAM_CHECKS = {"AZ-IAM-001": c_iam_001, "AZ-IAM-002": c_iam_002, "AZ-IAM-003": c_iam_003}
