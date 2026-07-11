"""CloudSentry — AWS IAM checks (10).

Each function receives (connector, meta) and returns a CheckResult.
When credentials are absent, all checks return INFO status describing
how to verify manually. boto3 ThrottlingException triggers a TIMEOUT skip.
"""

from __future__ import annotations

import time

from models import CheckResult


def _info(connector, meta) -> CheckResult:
    return CheckResult(
        check_id=meta["id"], name=meta["name"], provider="aws", category=meta["category"],
        status="INFO", severity=meta["severity"], description=meta["description"],
        risk=meta["risk"], remediation=meta["remediation"],
        cis_ref=meta["cis"], owasp_ref=meta["owasp"],
        affected=["(manual verification required)"],
    )


def _throttled(fn, connector, meta):
    if not connector.available:
        return _info(connector, meta)
    try:
        return fn(connector, meta)
    except Exception as e:  # Throttling / timeout
        msg = str(e)
        if "Throttling" in msg or "timeout" in msg.lower():
            return CheckResult(check_id=meta["id"], name=meta["name"], provider="aws",
                               category=meta["category"], status="TIMEOUT", severity=meta["severity"],
                               description="Check skipped: AWS throttling/timeout.", remediation=meta["remediation"],
                               cis_ref=meta["cis"], owasp_ref=meta["owasp"])
        return CheckResult(check_id=meta["id"], name=meta["name"], provider="aws",
                           category=meta["category"], status="ERROR", severity=meta["severity"],
                           description=f"Check error: {msg[:160]}", remediation=meta["remediation"],
                           cis_ref=meta["cis"], owasp_ref=meta["owasp"])


def _iam(connector):
    return connector.client("iam")


def c_iam_001(connector, meta):  # Root MFA
    def fn(c, m):
        iam = _iam(c)
        summary = iam.get_account_summary()["SummaryMap"]
        enabled = summary.get("AccountMFAEnabled", 0)
        if enabled:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="Root account MFA is enabled.",
                                remediation=m["remediation"], cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description="Root account MFA is NOT enabled.",
                           risk=m["risk"], remediation=m["remediation"], affected=["root"],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_002(connector, meta):  # Root access keys
    def fn(c, m):
        iam = _iam(c)
        summary = iam.get_account_summary()["SummaryMap"]
        present = summary.get("AccountAccessKeysPresent", 0)
        if present == 0:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="No root access keys present.",
                                remediation=m["remediation"], cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description="Root account has access keys.",
                           risk=m["risk"], remediation=m["remediation"], affected=["root"],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_003(connector, meta):  # password min length
    def fn(c, m):
        iam = _iam(c)
        try:
            pol = iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntity:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="FAIL", severity=m["severity"], description="No IAM password policy configured.",
                                risk=m["risk"], remediation=m["remediation"], affected=["password-policy"],
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        length = pol.get("MinimumPasswordLength", 0)
        if length >= 14:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description=f"Min length {length} >= 14.",
                                remediation=m["remediation"], cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"Min length {length} < 14.",
                           risk=m["risk"], remediation=m["remediation"], affected=["password-policy"],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_004(connector, meta):  # requires uppercase
    def fn(c, m):
        iam = _iam(c)
        try:
            pol = iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntity:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="FAIL", severity=m["severity"], description="No password policy.",
                                remediation=m["remediation"], affected=["password-policy"], cis_ref=m["cis"], owasp_ref=m["owasp"])
        if pol.get("RequireUppercaseCharacters", False):
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="Uppercase required.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description="Uppercase not required.",
                           risk=m["risk"], remediation=m["remediation"], affected=["password-policy"],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_005(connector, meta):  # requires symbols
    def fn(c, m):
        iam = _iam(c)
        try:
            pol = iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntity:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="FAIL", severity=m["severity"], description="No password policy.",
                                remediation=m["remediation"], affected=["password-policy"], cis_ref=m["cis"], owasp_ref=m["owasp"])
        if pol.get("RequireSymbols", False):
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="Symbols required.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description="Symbols not required.",
                           risk=m["risk"], remediation=m["remediation"], affected=["password-policy"],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_006(connector, meta):  # max age
    def fn(c, m):
        iam = _iam(c)
        try:
            pol = iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntity:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="FAIL", severity=m["severity"], description="No password policy.",
                                remediation=m["remediation"], affected=["password-policy"], cis_ref=m["cis"], owasp_ref=m["owasp"])
        age = pol.get("MaxPasswordAge", 0)
        if age and age <= 90:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description=f"Max age {age} <= 90.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"Max age {age} (>90 or unset).",
                           risk=m["risk"], remediation=m["remediation"], affected=["password-policy"],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_007(connector, meta):  # reuse prevention
    def fn(c, m):
        iam = _iam(c)
        try:
            pol = iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntity:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="FAIL", severity=m["severity"], description="No password policy.",
                                remediation=m["remediation"], affected=["password-policy"], cis_ref=m["cis"], owasp_ref=m["owasp"])
        prev = pol.get("PasswordReusePrevention", 0)
        if prev >= 24:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description=f"Reuse prevention {prev} >= 24.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"Reuse prevention {prev} < 24.",
                           risk=m["risk"], remediation=m["remediation"], affected=["password-policy"],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_008(connector, meta):  # MFA for console users
    def fn(c, m):
        iam = _iam(c)
        users = iam.list_users()["Users"]
        no_mfa = []
        for u in users:
            if u.get("PasswordLastUsed"):
                try:
                    mf = iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
                    if not mf:
                        no_mfa.append(u["UserName"])
                except Exception:
                    no_mfa.append(u["UserName"])
        if not no_mfa:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="All console users have MFA.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(no_mfa)} console user(s) without MFA.",
                           risk=m["risk"], remediation=m["remediation"], affected=no_mfa[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_009(connector, meta):  # inline policies
    def fn(c, m):
        iam = _iam(c)
        users = iam.list_users()["Users"]
        inline = []
        for u in users:
            try:
                if iam.list_user_policies(UserName=u["UserName"])["PolicyNames"]:
                    inline.append(u["UserName"])
            except Exception:
                pass
        if not inline:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="No inline user policies.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(inline)} user(s) with inline policies.",
                           risk=m["risk"], remediation=m["remediation"], affected=inline[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_iam_010(connector, meta):  # key rotation
    def fn(c, m):
        iam = _iam(c)
        users = iam.list_users()["Users"]
        stale = []
        now = time.time()
        for u in users:
            try:
                keys = iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
                for k in keys:
                    if k["Status"] == "Active":
                        used = k.get("CreateDate")
                        if used and (now - used.timestamp()) > 90 * 86400:
                            stale.append(f"{u['UserName']}:{k['AccessKeyId']}")
            except Exception:
                pass
        if not stale:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="All active keys rotated < 90d.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(stale)} key(s) older than 90 days.",
                           risk=m["risk"], remediation=m["remediation"], affected=stale[:50],
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


AWS_IAM_CHECKS = {
    "AWS-IAM-001": c_iam_001, "AWS-IAM-002": c_iam_002, "AWS-IAM-003": c_iam_003,
    "AWS-IAM-004": c_iam_004, "AWS-IAM-005": c_iam_005, "AWS-IAM-006": c_iam_006,
    "AWS-IAM-007": c_iam_007, "AWS-IAM-008": c_iam_008, "AWS-IAM-009": c_iam_009,
    "AWS-IAM-010": c_iam_010,
}
