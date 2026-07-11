"""CloudSentry — GCP provider entry point (runs all 20 checks)."""

from __future__ import annotations

from providers.gcp.connector import GCPConnector
from providers.gcp.iam_checks import GCP_IAM_CHECKS
from providers.gcp.gcs_checks import GCP_GCS_CHECKS
from providers.gcp.compute_checks import GCP_COMPUTE_CHECKS
from providers.gcp.logging_checks import GCP_LOGGING_CHECKS
from providers.gcp.sql_checks import GCP_SQL_CHECKS
from providers.gcp.network_checks import GCP_NETWORK_CHECKS
from catalog import checks_for

GCP_CHECKS = {**GCP_IAM_CHECKS, **GCP_GCS_CHECKS, **GCP_COMPUTE_CHECKS,
              **GCP_LOGGING_CHECKS, **GCP_SQL_CHECKS, **GCP_NETWORK_CHECKS}


def run_all(project=None, on_result=None) -> list:
    from models import CheckResult
    connector = GCPConnector(project=project)
    results = []
    for meta in checks_for("gcp"):
        fn = GCP_CHECKS.get(meta["id"])
        if not fn:
            continue
        res = fn(connector, meta)
        results.append(res)
        if on_result:
            on_result(res)
    return results
