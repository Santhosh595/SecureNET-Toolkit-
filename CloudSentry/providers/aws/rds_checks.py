"""CloudSentry — AWS RDS checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.aws.iam_checks import _throttled


def c_rds_001(connector, meta):  # public access
    def fn(c, m):
        rds = c.client("rds")
        insts = rds.describe_db_instances()["DBInstances"]
        bad = [i["DBInstanceIdentifier"] for i in insts if i.get("PubliclyAccessible")]
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="No publicly accessible RDS instances.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} RDS instance(s) publicly accessible.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_rds_002(connector, meta):  # storage encryption
    def fn(c, m):
        rds = c.client("rds")
        insts = rds.describe_db_instances()["DBInstances"]
        bad = [i["DBInstanceIdentifier"] for i in insts if not i.get("StorageEncrypted")]
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="All RDS instances encrypted at rest.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} RDS instance(s) without storage encryption.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_rds_003(connector, meta):  # automated backups
    def fn(c, m):
        rds = c.client("rds")
        insts = rds.describe_db_instances()["DBInstances"]
        bad = [i["DBInstanceIdentifier"] for i in insts if (i.get("BackupRetentionPeriod") or 0) == 0]
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="All RDS instances have automated backups.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} RDS instance(s) without backups.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


AWS_RDS_CHECKS = {
    "AWS-RDS-001": c_rds_001, "AWS-RDS-002": c_rds_002, "AWS-RDS-003": c_rds_003,
}
