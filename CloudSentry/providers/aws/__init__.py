"""CloudSentry — AWS provider entry point (runs all 25 checks)."""

from __future__ import annotations

from providers.aws.connector import AWSConnector
from providers.aws.iam_checks import AWS_IAM_CHECKS
from providers.aws.s3_checks import AWS_S3_CHECKS
from providers.aws.cloudtrail import AWS_CT_CHECKS
from providers.aws.vpc_checks import AWS_VPC_CHECKS
from providers.aws.rds_checks import AWS_RDS_CHECKS
from catalog import checks_for

AWS_CHECKS = {**AWS_IAM_CHECKS, **AWS_S3_CHECKS, **AWS_CT_CHECKS, **AWS_VPC_CHECKS, **AWS_RDS_CHECKS}


def run_all(profile=None, region=None, providers_filter=None, on_result=None) -> list:
    """Run all AWS checks. Returns list[CheckResult]. Uses INFO mode if no creds."""
    from models import CheckResult
    connector = AWSConnector(profile=profile, region=region)
    results = []
    for meta in checks_for("aws"):
        fn = AWS_CHECKS.get(meta["id"])
        if not fn:
            continue
        res = fn(connector, meta)
        results.append(res)
        if on_result:
            on_result(res)
    return results
