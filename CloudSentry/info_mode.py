"""CloudSentry — INFO mode (no credentials).

When no cloud credentials are present, CloudSentry does NOT error and does NOT
prompt for input. Instead it runs in INFO mode: it lists every check with its
description, what it looks for, how to verify it manually, and how to configure
credentials to enable automated checking. Each check's status is INFO.
"""

from __future__ import annotations

from catalog import CHECKS, checks_for
from models import CheckResult

# How to configure credentials per provider (shown in INFO mode).
CRED_SETUP = {
    "aws": [
        "Export keys: export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...",
        "Or use a profile in ~/.aws/credentials and pass --profile <name>.",
        "Or run on an EC2 instance with an attached IAM role (instance metadata).",
    ],
    "gcp": [
        "Set the service-account key: export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json",
        "Or run: gcloud auth application-default login",
        "Pass the project with --project <PROJECT_ID>.",
    ],
    "azure": [
        "Log in with the CLI: az login",
        "Or set: AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET (+ AZURE_SUBSCRIPTION_ID).",
        "Pass the subscription with --subscription <SUB_ID>.",
    ],
}


def build_info_results(providers=None) -> list[CheckResult]:
    """Return INFO-mode CheckResult for every check (filtered by providers)."""
    if not providers:
        providers = ["aws", "gcp", "azure"]
    out = []
    for meta in CHECKS:
        if meta["provider"] not in providers:
            continue
        out.append(CheckResult(
            check_id=meta["id"], name=meta["name"], provider=meta["provider"],
            category=meta["category"], status="INFO", severity=meta["severity"],
            description=meta["description"], risk=meta["risk"],
            remediation=meta["remediation"], cis_ref=meta["cis"], owasp_ref=meta["owasp"],
            affected=["(manual verification required — no credentials detected)"],
        ))
    return out


def cred_setup_lines(provider: str) -> list[str]:
    return CRED_SETUP.get(provider, [])
