"""CloudSentry core — multi-cloud security posture checks (Prowler/ScoutSuite-style).

Runs read-only configuration/posture checks across AWS, GCP, and Azure.
When cloud credentials are present it performs safe read-only API calls; otherwise it
reports the check as INFO with guidance, so the tool is always runnable and safe.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class CheckResult:
    provider: str
    check_id: str
    title: str
    status: str          # PASS | WARN | FAIL | INFO
    severity: str        # critical | high | medium | low | info
    detail: str = ""
    region: str = "global"


@dataclass
class Check:
    check_id: str
    title: str
    severity: str
    provider: str
    fn: Callable[[], CheckResult]


CHECKS: list[Check] = []


def register(check_id, title, severity, provider):
    def deco(fn):
        CHECKS.append(Check(check_id, title, severity, provider, fn))
        return fn
    return deco


# ----------------------------- AWS checks -----------------------------

@register("AWS-001", "S3 buckets should not be public", "high", "aws")
def aws_s3_public():
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        return CheckResult("aws", "AWS-001", "S3 buckets should not be public", "INFO",
                           "high", "Set AWS credentials to run this read-only check.")
    try:
        import boto3
        s3 = boto3.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        public = []
        for b in buckets:
            name = b["Name"]
            try:
                acl = s3.get_public_access_block(Bucket=name)
                cfg = acl.get("PublicAccessBlockConfiguration", {})
                if not cfg.get("BlockPublicAcls") or not cfg.get("BlockPublicPolicy"):
                    public.append(name)
            except Exception:
                public.append(name)
        if public:
            return CheckResult("aws", "AWS-001", "S3 buckets should not be public", "FAIL",
                               "high", f"Public/insecure buckets: {', '.join(public)}")
        return CheckResult("aws", "AWS-001", "S3 buckets should not be public", "PASS",
                           "high", f"Checked {len(buckets)} buckets.")
    except Exception as e:
        return CheckResult("aws", "AWS-001", "S3 buckets should not be public", "INFO",
                           "high", f"Could not inspect S3: {e}")


@register("AWS-002", "IAM root account MFA enabled", "critical", "aws")
def aws_root_mfa():
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        return CheckResult("aws", "AWS-002", "IAM root account MFA enabled", "INFO",
                           "critical", "Set AWS credentials to run this read-only check.")
    try:
        import boto3
        iam = boto3.client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountMFAEnabled"):
            return CheckResult("aws", "AWS-002", "IAM root account MFA enabled", "PASS",
                               "critical", "Root MFA is enabled.")
        return CheckResult("aws", "AWS-002", "IAM root account MFA enabled", "FAIL",
                           "critical", "Root account MFA is NOT enabled.")
    except Exception as e:
        return CheckResult("aws", "AWS-002", "IAM root account MFA enabled", "INFO",
                           "critical", f"Could not inspect IAM: {e}")


@register("AWS-003", "No IAM access keys for root account", "high", "aws")
def aws_root_keys():
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        return CheckResult("aws", "AWS-003", "No IAM access keys for root account", "INFO",
                           "high", "Set AWS credentials to run this read-only check.")
    try:
        import boto3
        iam = boto3.client("iam")
        keys = iam.list_access_keys(UserName="root").get("AccessKeyMetadata", [])
        if keys:
            return CheckResult("aws", "AWS-003", "No IAM access keys for root account", "FAIL",
                               "high", f"Root has {len(keys)} access key(s).")
        return CheckResult("aws", "AWS-003", "No IAM access keys for root account", "PASS",
                           "high", "No root access keys found.")
    except Exception as e:
        return CheckResult("aws", "AWS-003", "No IAM access keys for root account", "INFO",
                           "high", f"Could not inspect IAM: {e}")


# ----------------------------- GCP checks -----------------------------

@register("GCP-001", "Default service account not used by compute", "medium", "gcp")
def gcp_default_sa():
    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return CheckResult("gcp", "GCP-001", "Default service account not used by compute", "INFO",
                           "medium", "Set GOOGLE_APPLICATION_CREDENTIALS to run read-only checks.")
    return CheckResult("gcp", "GCP-001", "Default service account not used by compute", "INFO",
                       "medium", "GCP credentials present — extend compute API checks as needed.")


# ----------------------------- Azure checks -----------------------------

@register("AZ-001", "Storage accounts use HTTPS-only", "medium", "azure")
def az_storage_https():
    if not os.environ.get("AZURE_SUBSCRIPTION_ID"):
        return CheckResult("azure", "AZ-001", "Storage accounts use HTTPS-only", "INFO",
                           "medium", "Set AZURE_SUBSCRIPTION_ID to run read-only checks.")
    return CheckResult("azure", "AZ-001", "Storage accounts use HTTPS-only", "INFO",
                       "medium", "Azure credentials present — extend storage API checks as needed.")


# ----------------------------- Engine -----------------------------

def run_checks(providers: list[str] | None = None) -> list[CheckResult]:
    """Run all registered checks (optionally filtered by provider)."""
    results: list[CheckResult] = []
    for check in CHECKS:
        if providers and check.provider not in providers:
            continue
        try:
            results.append(check.fn())
        except Exception as e:
            results.append(CheckResult(check.provider, check.check_id, check.title,
                                       "INFO", check.severity, f"Check error: {e}"))
    return results


def summarize(results: list[CheckResult]) -> dict:
    sev_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for r in results:
        sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
        status_counts[r.status] = status_counts.get(r.status, 0) + 1
    return {"total": len(results), "by_severity": sev_counts, "by_status": status_counts}
