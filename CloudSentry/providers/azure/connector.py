"""CloudSentry — Azure connector (azure-mgmt / azure-identity, optional).

Credential detection order:
  1. AZURE_* environment variables (AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET
     or AZURE_SUBSCRIPTION_ID)
  2. az CLI logged-in token (DefaultAzureCredential resolves this)
If absent, `available` is False and INFO mode is used. Credentials are never stored/logged.
"""

from __future__ import annotations

import os

try:
    from azure.identity import DefaultAzureCredential  # type: ignore
    from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient  # type: ignore
    AZURE = True
except ImportError:
    DefaultAzureCredential = None  # type: ignore
    SubscriptionClient = ResourceManagementClient = None  # type: ignore
    AZURE = False


def detect_credentials() -> tuple[bool, str]:
    if os.environ.get("AZURE_CLIENT_ID") and os.environ.get("AZURE_TENANT_ID"):
        return True, "AZURE_* environment variables"
    if os.environ.get("AZURE_SUBSCRIPTION_ID"):
        return True, "AZURE_SUBSCRIPTION_ID env var"
    if AZURE:
        try:
            cred = DefaultAzureCredential()
            # Try to read subscriptions to confirm auth works
            list(SubscriptionClient(cred).subscriptions.list())
            return True, "az CLI / DefaultAzureCredential"
        except Exception:
            pass
    return False, "no Azure credentials (run 'az login' or set AZURE_* env vars)"


class AzureConnector:
    def __init__(self, subscription: str | None = None):
        self.subscription = subscription
        self.available, self.detail = detect_credentials()
        self._cred = None
        if self.available and AZURE:
            try:
                self._cred = DefaultAzureCredential()
            except Exception:
                self._cred = None

    def client(self, name: str):
        if not self._cred or not self.available:
            return None
        try:
            if name == "subscription":
                return SubscriptionClient(self._cred)
            if name == "resource":
                return ResourceManagementClient(self._cred, self.subscription)
        except Exception:
            return None
        return None
