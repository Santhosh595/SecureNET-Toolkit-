"""CloudSentry — AWS S3 checks (5)."""

from __future__ import annotations

from models import CheckResult
from providers.aws.iam_checks import _throttled


def _s3(connector):
    return connector.client("s3")


def c_s3_001(connector, meta):  # public read ACL
    def fn(c, m):
        s3 = _s3(c)
        buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
        public = []
        for b in buckets:
            try:
                acl = s3.get_bucket_acl(Bucket=b)
                for g in acl["Grants"]:
                    gtype = g.get("Grantee", {}).get("Type")
                    perm = g.get("Permission")
                    if gtype == "Group" and "AllUsers" in g["Grantee"].get("URI", "") and perm in ("READ", "FULL_CONTROL"):
                        public.append(b)
            except Exception:
                pass
        if not public:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="No buckets with public READ ACL.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(public)} bucket(s) with public READ ACL.",
                           risk=m["risk"], remediation=m["remediation"], affected=public[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_s3_002(connector, meta):  # public write ACL
    def fn(c, m):
        s3 = _s3(c)
        buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
        public = []
        for b in buckets:
            try:
                acl = s3.get_bucket_acl(Bucket=b)
                for g in acl["Grants"]:
                    if g.get("Grantee", {}).get("Type") == "Group" and "AllUsers" in g["Grantee"].get("URI", "") and g.get("Permission") in ("WRITE", "FULL_CONTROL"):
                        public.append(b)
            except Exception:
                pass
        if not public:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="No buckets with public WRITE ACL.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(public)} bucket(s) with public WRITE ACL.",
                           risk=m["risk"], remediation=m["remediation"], affected=public[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_s3_003(connector, meta):  # account block public access
    def fn(c, m):
        from providers.aws.connector import AWSConnector
        acct = AWSConnector()._session.client("account") if AWSConnector()._session else None
        if acct is None:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="INFO", severity=m["severity"], description="Account client unavailable.",
                                remediation=m["remediation"], affected=["(manual verification required)"],
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        try:
            st = acct.get_account_public_access_block()["PublicAccessBlockConfiguration"]
        except Exception:
            s3c = _s3(c)
            st = s3c.get_public_access_block(Bucket=s3c.list_buckets()["Buckets"][0]["Name"])["PublicAccessBlockConfiguration"]
        if all(st.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="Account-level Block Public Access enabled.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description="Account-level Block Public Access NOT fully enabled.",
                           risk=m["risk"], remediation=m["remediation"], affected=["account"],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_s3_004(connector, meta):  # versioning
    def fn(c, m):
        s3 = _s3(c)
        buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
        no_ver = []
        for b in buckets:
            try:
                if s3.get_bucket_versioning(Bucket=b).get("Status") != "Enabled":
                    no_ver.append(b)
            except Exception:
                pass
        if not no_ver:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="All buckets have versioning enabled.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(no_ver)} bucket(s) without versioning.",
                           risk=m["risk"], remediation=m["remediation"], affected=no_ver[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_s3_005(connector, meta):  # encryption
    def fn(c, m):
        s3 = _s3(c)
        buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
        no_enc = []
        for b in buckets:
            try:
                cfg = s3.get_bucket_encryption(Bucket=b)
                rules = cfg["ServerSideEncryptionConfiguration"]["Rules"]
                if not any(r.get("ApplyServerSideEncryptionByDefault") for r in rules):
                    no_enc.append(b)
            except Exception:
                no_enc.append(b)
        if not no_enc:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="All buckets have SSE enabled.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(no_enc)} bucket(s) without SSE.",
                           risk=m["risk"], remediation=m["remediation"], affected=no_enc[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


AWS_S3_CHECKS = {
    "AWS-S3-001": c_s3_001, "AWS-S3-002": c_s3_002, "AWS-S3-003": c_s3_003,
    "AWS-S3-004": c_s3_004, "AWS-S3-005": c_s3_005,
}
