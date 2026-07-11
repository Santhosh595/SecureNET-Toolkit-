"""CloudSentry — AWS connector (boto3, optional).

Detects credentials via the standard AWS chain and exposes a boto3 session.
If boto3 is not installed or no credentials are found, `available` is False
and the engine falls back to INFO mode. Credentials are never stored or logged.
"""

from __future__ import annotations

import os

try:
    import boto3  # type: ignore
    from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError  # type: ignore
    BOTO3 = True
except ImportError:
    boto3 = None  # type: ignore
    ClientError = NoCredentialsError = BotoCoreError = Exception  # type: ignore
    BOTO3 = False


def detect_credentials(profile: str | None = None) -> tuple[bool, str]:
    """Return (found, detail) describing how AWS credentials were detected."""
    if not BOTO3:
        return False, "boto3 not installed"
    # 1. env vars
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return True, "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars"
    # 2/3. shared cred/profile files (boto3 resolves automatically)
    try:
        sess = boto3.Session(profile_name=profile) if profile else boto3.Session()
        sess.get_credentials()
        ident = sess.client("sts").get_caller_identity()
        return True, f"profile {profile or 'default'} ({ident.get('Arn','?')})"
    except (NoCredentialsError, BotoCoreError):
        pass
    except ClientError:
        # credentials present but STS call failed -> still "found"
        return True, "local credentials (STS call failed)"
    return False, "no AWS credentials found in env, ~/.aws, or instance metadata"


class AWSConnector:
    def __init__(self, profile: str | None = None, region: str | None = None):
        self.profile = profile
        self.region = region
        self.available, self.detail = detect_credentials(profile)
        self._session = None
        if self.available and BOTO3:
            self._session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            if region:
                self._region = region
            else:
                self._region = self._session.region_name or "us-east-1"
        else:
            self._region = region or "us-east-1"

    @property
    def region_name(self) -> str:
        return self._region

    def client(self, svc: str, region: str | None = None):
        if not self._session:
            raise RuntimeError("AWS session unavailable (no credentials)")
        return self._session.client(svc, region_name=region or self._region)

    @staticmethod
    def all_regions() -> list[str]:
        if not (BOTO3 and AWSConnector()._session):
            return ["us-east-1"]
        try:
            ec2 = AWSConnector()._session.client("ec2", region_name="us-east-1")
            return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
        except Exception:
            return ["us-east-1"]
