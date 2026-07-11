"""CloudSentry — providers package aggregator."""

from __future__ import annotations

from catalog import CHECKS, CHECK_BY_ID, checks_for, all_check_ids
from providers.aws import run_all as aws_run_all
from providers.gcp import run_all as gcp_run_all
from providers.azure import run_all as azure_run_all


def run_provider(provider: str, on_result=None, **kwargs) -> list:
    if provider == "aws":
        return aws_run_all(on_result=on_result, **kwargs)
    if provider == "gcp":
        return gcp_run_all(on_result=on_result, **kwargs)
    if provider == "azure":
        return azure_run_all(on_result=on_result, **kwargs)
    return []


def run_audit(providers=None, on_result=None, **kwargs) -> list:
    """Run checks across one or more providers. Returns list[CheckResult]."""
    if not providers:
        providers = ["aws", "gcp", "azure"]
    out = []
    for p in providers:
        out.extend(run_provider(p, on_result=on_result, **kwargs))
    return out
