"""CloudSentry — AWS CloudTrail checks (3)."""

from __future__ import annotations

from models import CheckResult
from providers.aws.iam_checks import _throttled


def c_ct_001(connector, meta):  # multi-region trail
    def fn(c, m):
        ct = c.client("cloudtrail")
        trails = ct.describe_trails()["trailList"]
        if not trails:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                               status="FAIL", severity=m["severity"], description="No CloudTrail configured.",
                               risk=m["risk"], remediation=m["remediation"], affected=["(none)"],
                               cis_ref=m["cis"], owasp_ref=m["owasp"])
        multi = [t["Name"] for t in trails if t.get("IsMultiRegionTrail")]
        if multi:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="Multi-region trail present.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description="No multi-region CloudTrail.",
                           risk=m["risk"], remediation=m["remediation"], affected=[t["Name"] for t in trails],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_ct_002(connector, meta):  # log validation
    def fn(c, m):
        ct = c.client("cloudtrail")
        trails = ct.describe_trails()["trailList"]
        bad = []
        for t in trails:
            st = ct.get_trail_status(Name=t["TrailARN"])
            if not st.get("LogFileValidationEnabled"):
                bad.append(t["Name"])
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="Log file validation enabled.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} trail(s) without validation.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_ct_003(connector, meta):  # trail bucket not public
    def fn(c, m):
        ct = c.client("cloudtrail")
        s3 = c.client("s3")
        trails = ct.describe_trails()["trailList"]
        public = []
        for t in trails:
            b = t.get("S3BucketName")
            if not b:
                continue
            try:
                acl = s3.get_bucket_acl(Bucket=b)
                for g in acl["Grants"]:
                    if g.get("Grantee", {}).get("Type") == "Group" and "AllUsers" in g["Grantee"].get("URI", ""):
                        public.append(b)
            except Exception:
                pass
        if not public:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="Trail S3 buckets not public.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(public)} trail bucket(s) public.",
                           risk=m["risk"], remediation=m["remediation"], affected=public,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


AWS_CT_CHECKS = {
    "AWS-CT-001": c_ct_001, "AWS-CT-002": c_ct_002, "AWS-CT-003": c_ct_003,
}
