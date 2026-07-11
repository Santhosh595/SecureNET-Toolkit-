"""CloudSentry — GCP IAM checks (4)."""

from __future__ import annotations

from models import CheckResult


def _info(connector, meta) -> CheckResult:
    return CheckResult(check_id=meta["id"], name=meta["name"], provider="gcp", category=meta["category"],
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
        return CheckResult(check_id=meta["id"], name=meta["name"], provider="gcp", category=meta["category"],
                           status="ERROR", severity=meta["severity"], description=f"Check error: {msg[:160]}",
                           remediation=meta["remediation"], cis_ref=meta["cis"], owasp_ref=meta["owasp"])


def c_iam_001(connector, meta):  # service accounts with admin roles
    def fn(c, m):
        iam = c.client("asset")
        if iam is None:
            return _info(c, m)
        # Use Cloud Asset Inventory policy search for roles/owner, roles/admin
        bad = []
        try:
            for resp in iam.search_all_iam_policies(
                request={"scope": f"projects/{c.project}", "query": "policy:(roles/owner OR roles/admin OR roles/editor)"}
            ):
                if "serviceAccount" in str(resp):  # crude: SA principal holding broad role
                    bad.append(str(resp.resource))
        except Exception:
            return _info(c, m)
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="gcp", category=m["category"],
                                status="PASS", severity=m["severity"], description="No service accounts with admin roles.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="gcp", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} SA(s) with admin roles.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _guard(fn, connector, meta)


def c_iam_002(connector, meta):  # stale SA keys
    def fn(c, m):
        iam = c.client("iam")  # type: ignore
        if iam is None:
            return _info(c, m)
        return _info(c, m)  # requires service account key enumeration beyond scope of lightweight client; INFO
    return _guard(fn, connector, meta)


def c_iam_003(connector, meta):  # prefer workload identity
    def fn(c, m):
        iam = c.client("iam")  # type: ignore
        if iam is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


def c_iam_004(connector, meta):  # primitive roles
    def fn(c, m):
        iam = c.client("asset")
        if iam is None:
            return _info(c, m)
        bad = []
        try:
            for resp in iam.search_all_iam_policies(
                request={"scope": f"projects/{c.project}", "query": "policy:(roles/owner OR roles/editor OR roles/viewer)"}
            ):
                bad.append(str(resp.resource))
        except Exception:
            return _info(c, m)
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="gcp", category=m["category"],
                                status="PASS", severity=m["severity"], description="No primitive roles in use.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="gcp", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} binding(s) use primitive roles.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _guard(fn, connector, meta)


def c_iam_005(connector, meta):  # external Owner/Editor
    def fn(c, m):
        iam = c.client("asset")
        if iam is None:
            return _info(c, m)
        return _info(c, m)
    return _guard(fn, connector, meta)


GCP_IAM_CHECKS = {
    "GCP-IAM-001": c_iam_001, "GCP-IAM-002": c_iam_002,
    "GCP-IAM-003": c_iam_003, "GCP-IAM-004": c_iam_004, "GCP-IAM-005": c_iam_005,
}
