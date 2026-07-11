"""CloudSentry — Azure provider entry point (runs all 15 checks)."""

from __future__ import annotations

from providers.azure.connector import AzureConnector
from providers.azure.iam_checks import AZ_IAM_CHECKS
from providers.azure.storage_checks import AZ_STG_CHECKS
from providers.azure.network_checks import AZ_NSG_CHECKS
from providers.azure.monitoring_checks import AZ_MON_CHECKS
from providers.azure.database_checks import AZ_DB_CHECKS
from catalog import checks_for

AZ_CHECKS = {**AZ_IAM_CHECKS, **AZ_STG_CHECKS, **AZ_NSG_CHECKS, **AZ_MON_CHECKS, **AZ_DB_CHECKS}


def run_all(subscription=None, on_result=None) -> list:
    from models import CheckResult
    connector = AzureConnector(subscription=subscription)
    results = []
    for meta in checks_for("azure"):
        fn = AZ_CHECKS.get(meta["id"])
        if not fn:
            continue
        res = fn(connector, meta)
        results.append(res)
        if on_result:
            on_result(res)
    return results
