"""CloudSentry — GCP connector (google-cloud, optional).

Credential detection order:
  1. GOOGLE_APPLICATION_CREDENTIALS env var (path to service account JSON)
  2. gcloud application-default login (ADC) token
If neither present, `available` is False and INFO mode is used.
Credentials are never stored or logged.
"""

from __future__ import annotations

import os


def detect_credentials(project: str | None = None) -> tuple[bool, str]:
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return True, "GOOGLE_APPLICATION_CREDENTIALS env var"
    # ADC: a default credential file exists under the gcloud config dir
    adc_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
    if os.path.exists(adc_path):
        return True, "gcloud application-default credentials"
    return False, "no GCP credentials (set GOOGLE_APPLICATION_CREDENTIALS or run gcloud auth application-default login)"


class GCPConnector:
    def __init__(self, project: str | None = None):
        self.project = project
        self.available, self.detail = detect_credentials(project)
        self._clients = {}

    def client(self, name: str):
        """Lazily import + return a google-cloud client by service name.

        Returns None if the library is not installed or auth fails, so callers
        fall back to INFO mode.
        """
        if name in self._clients:
            return self._clients[name]
        if not self.available:
            return None
        try:
            if name == "iam":
                from google.cloud import iam  # noqa: F401
                self._clients[name] = True
            elif name == "asset":
                from google.cloud import asset_v1 as asset  # type: ignore
                self._clients[name] = asset.AssetServiceClient() if self.project else None
            elif name == "storage":
                from google.cloud import storage
                self._clients[name] = storage.Client(project=self.project)
            elif name == "compute":
                from google.cloud import compute_v1  # type: ignore
                self._clients[name] = compute_v1
            elif name == "logging":
                from google.cloud import logging as glog  # type: ignore
                self._clients[name] = glog.Client(project=self.project)
            elif name == "sql":
                from google.cloud import sql_v1 as sql  # type: ignore
                self._clients[name] = sql
            return self._clients[name]
        except Exception:
            return None
