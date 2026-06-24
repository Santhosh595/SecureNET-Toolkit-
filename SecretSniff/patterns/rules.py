"""SecretSniff — Secret detection patterns.

50+ regex patterns for API keys, tokens, credentials, and private keys.
Each pattern: (name, regex, severity, description)
"""

from __future__ import annotations
from dataclasses import dataclass
import re


@dataclass
class SecretPattern:
    """A secret detection rule."""
    name: str
    regex: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    confidence: str = "HIGH"  # HIGH / MEDIUM / LOW

    def __post_init__(self):
        self._compiled = re.compile(self.regex, re.IGNORECASE | re.MULTILINE)

    def search(self, text: str) -> list[re.Match]:
        return self._compiled.finditer(text)


# ── Cloud Providers ──
PATTERNS = [
    # === Cloud Providers ===
    SecretPattern(
        "AWS Access Key ID",
        r"\b(AKIA[0-9A-Z]{16})\b",
        "CRITICAL", "AWS Access Key ID (starts with AKIA)"
    ),
    SecretPattern(
        "AWS Secret Access Key",
        r"(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*['\"]?([0-9a-zA-Z/+]{40})['\"]?",
        "CRITICAL", "AWS Secret Access Key in assignment"
    ),
    SecretPattern(
        "AWS Session Token",
        r"(?i)(?:aws_session_token|session_token)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
        "CRITICAL", "AWS Session Token"
    ),
    SecretPattern(
        "GCP API Key",
        r"\b(AIza[0-9A-Za-z\-_]{35})\b",
        "CRITICAL", "GCP API Key (starts with AIza)"
    ),
    SecretPattern(
        "GCP Service Account JSON",
        r"(?i)\"type\"\s*:\s*\"service_account\".*\"private_key\"\s*:\s*\"-----BEGIN",
        "CRITICAL", "GCP Service Account private key in JSON"
    ),
    SecretPattern(
        "Azure Storage Key",
        r"(?i)(?:AccountKey|azure_storage_key)\s*[:=]\s*['\"]?([0-9a-zA-Z+/=]{88})['\"]?",
        "CRITICAL", "Azure Storage Account Key"
    ),
    SecretPattern(
        "Azure SAS Token",
        r"(?i)(?:sig=|sas_token=)[0-9a-zA-Z%\-_.]{30,}",
        "HIGH", "Azure Shared Access Signature token"
    ),
    SecretPattern(
        "DigitalOcean Token",
        r"\b(dop_v1_[a-f0-9]{64})\b",
        "CRITICAL", "DigitalOcean Personal Access Token"
    ),
    SecretPattern(
        "Heroku API Key",
        r"(?i)(?:heroku_api_key|heroku_key)\s*[:=]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
        "CRITICAL", "Heroku API Key"
    ),

    # === Version Control & CI ===
    SecretPattern(
        "GitHub Personal Token",
        r"\b(ghp_[a-zA-Z0-9]{36})\b",
        "CRITICAL", "GitHub Personal Access Token"
    ),
    SecretPattern(
        "GitHub OAuth Token",
        r"\b(gho_[a-zA-Z0-9]{36})\b",
        "CRITICAL", "GitHub OAuth Access Token"
    ),
    SecretPattern(
        "GitHub App Token",
        r"\b(ghs_[a-zA-Z0-9]{36})\b",
        "CRITICAL", "GitHub App Installation Token"
    ),
    SecretPattern(
        "GitHub Refresh Token",
        r"\b(ghr_[a-zA-Z0-9]{76})\b",
        "CRITICAL", "GitHub Refresh Token"
    ),
    SecretPattern(
        "GitLab Personal Token",
        r"\b(glpat-[a-zA-Z0-9\-]{20})\b",
        "CRITICAL", "GitLab Personal Access Token"
    ),
    SecretPattern(
        "CircleCI Token",
        r"(?i)(?:circle-token|CIRCLE_TOKEN)\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?",
        "HIGH", "CircleCI Personal Token"
    ),
    SecretPattern(
        "Travis CI Token",
        r"(?i)(?:travis_token|TRAVIS_TOKEN)\s*[:=]\s*['\"]?([a-zA-Z0-9]{22,})['\"]?",
        "HIGH", "Travis CI Token"
    ),
    SecretPattern(
        "Jenkins API Token",
        r"(?i)(?:jenkins_token|JENKINS_TOKEN|jenkins_api)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        "HIGH", "Jenkins API Token"
    ),

    # === Payment ===
    SecretPattern(
        "Stripe Secret Key",
        r"\b(sk_live_[a-zA-Z0-9]{24})\b",
        "CRITICAL", "Stripe Live Secret Key"
    ),
    SecretPattern(
        "Stripe Publishable Key",
        r"\b(pk_live_[a-zA-Z0-9]{24})\b",
        "HIGH", "Stripe Live Publishable Key"
    ),
    SecretPattern(
        "Stripe Test Key",
        r"\b(sk_test_[a-zA-Z0-9]{24})\b",
        "MEDIUM", "Stripe Test Secret Key"
    ),
    SecretPattern(
        "PayPal Client Secret",
        r"(?i)(?:paypal.*secret|client_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?",
        "CRITICAL", "PayPal Client Secret"
    ),
    SecretPattern(
        "Square Access Token",
        r"\b(sq0atp-[a-zA-Z0-9\-_]{22})\b",
        "CRITICAL", "Square Access Token"
    ),
    SecretPattern(
        "Braintree Token",
        r"(?i)(?:braintree.*token|braintree.*key)\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,})['\"]?",
        "CRITICAL", "Braintree Payment Token"
    ),

    # === Communication ===
    SecretPattern(
        "Slack Bot Token",
        r"\b(xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24})\b",
        "CRITICAL", "Slack Bot User OAuth Token"
    ),
    SecretPattern(
        "Slack Webhook URL",
        r"(?i)hooks\.slack\.com/services/T[a-zA-Z0-9]{8}/B[a-zA-Z0-9]{8}/[a-zA-Z0-9]{24}",
        "HIGH", "Slack Incoming Webhook URL"
    ),
    SecretPattern(
        "Slack App Token",
        r"\b(xapp-[0-9\-]+[a-zA-Z0-9\-]+)\b",
        "CRITICAL", "Slack App-Level Token"
    ),
    SecretPattern(
        "Twilio Account SID",
        r"\b(AC[a-zA-Z0-9]{32})\b",
        "CRITICAL", "Twilio Account SID"
    ),
    SecretPattern(
        "Twilio Auth Token",
        r"(?i)(?:twilio.*auth_token|TWILIO_AUTH_TOKEN)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        "CRITICAL", "Twilio Auth Token"
    ),
    SecretPattern(
        "SendGrid API Key",
        r"\b(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})\b",
        "CRITICAL", "SendGrid API Key"
    ),
    SecretPattern(
        "Mailgun API Key",
        r"\b(key-[a-zA-Z0-9]{32})\b",
        "CRITICAL", "Mailgun API Key"
    ),
    SecretPattern(
        "Mailchimp API Key",
        r"\b([a-f0-9]{32}-us[0-9]{2})\b",
        "CRITICAL", "Mailchimp API Key"
    ),

    # === Databases ===
    SecretPattern(
        "MongoDB URI",
        r"(?i)mongodb(?:\+srv)?://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+",
        "CRITICAL", "MongoDB connection URI with credentials"
    ),
    SecretPattern(
        "PostgreSQL URI",
        r"(?i)postgresql://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+",
        "CRITICAL", "PostgreSQL connection URI with credentials"
    ),
    SecretPattern(
        "MySQL URI",
        r"(?i)mysql://[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9\.\-]+",
        "CRITICAL", "MySQL connection URI with credentials"
    ),
    SecretPattern(
        "Redis URI with password",
        r"(?i)redis://:[^@\s]+@[a-zA-Z0-9\.\-]+",
        "CRITICAL", "Redis URI with password"
    ),
    SecretPattern(
        "DB Password Assignment",
        r"(?i)(?:DB_PASS|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
        "CRITICAL", "Database password in environment/config"
    ),

    # === Cryptographic ===
    SecretPattern(
        "RSA Private Key",
        r"-----BEGIN RSA PRIVATE KEY-----",
        "CRITICAL", "RSA Private Key"
    ),
    SecretPattern(
        "EC Private Key",
        r"-----BEGIN EC PRIVATE KEY-----",
        "CRITICAL", "Elliptic Curve Private Key"
    ),
    SecretPattern(
        "PGP Private Key",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "CRITICAL", "PGP Private Key Block"
    ),
    SecretPattern(
        "OpenSSH Private Key",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "CRITICAL", "OpenSSH Private Key"
    ),
    SecretPattern(
        "PKCS8 Private Key",
        r"-----BEGIN PRIVATE KEY-----",
        "CRITICAL", "PKCS8 Private Key"
    ),
    SecretPattern(
        "Certificate (private context)",
        r"-----BEGIN CERTIFICATE-----",
        "MEDIUM", "Certificate (flag if in private context)"
    ),

    # === AI & APIs ===
    SecretPattern(
        "OpenAI API Key",
        r"\b(sk-[a-zA-Z0-9]{48})\b",
        "CRITICAL", "OpenAI API Key"
    ),
    SecretPattern(
        "Anthropic API Key",
        r"\b(sk-ant-[a-zA-Z0-9\-_]{95})\b",
        "CRITICAL", "Anthropic API Key"
    ),
    SecretPattern(
        "HuggingFace Token",
        r"\b(hf_[a-zA-Z0-9]{34})\b",
        "CRITICAL", "HuggingFace API Token"
    ),
    SecretPattern(
        "Replicate Token",
        r"\b(r8_[a-zA-Z0-9]{40})\b",
        "CRITICAL", "Replicate API Token"
    ),

    # === Other ===
    SecretPattern(
        "NPM Auth Token",
        r"\b(npm_[a-zA-Z0-9]{36})\b",
        "CRITICAL", "NPM Authentication Token"
    ),
    SecretPattern(
        "PyPI Token",
        r"\b(pypi-[a-zA-Z0-9\-_]{210})\b",
        "CRITICAL", "PyPI Upload Token"
    ),
    SecretPattern(
        "Dockerhub Token",
        r"(?i)(?:dockerhub.*token|DOCKER_AUTH_TOKEN)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{24})['\"]?",
        "CRITICAL", "DockerHub Authentication Token"
    ),
    SecretPattern(
        "JWT Token",
        r"\b(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)\b",
        "HIGH", "JSON Web Token"
    ),
    SecretPattern(
        "Generic Secret Assignment",
        r"(?i)(?:secret[_-]?key|secret[_-]?token|secret[_-]?access)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "MEDIUM", "Generic secret key assignment"
    ),
    SecretPattern(
        "Generic Password Assignment",
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        "MEDIUM", "Generic password assignment"
    ),
    SecretPattern(
        "Generic API Key Assignment",
        r"(?i)(?:api[_-]?key|apikey|api_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "MEDIUM", "Generic API key assignment"
    ),
    SecretPattern(
        "IP with credentials in URL",
        r"(?i)(?:http|https|ftp|mongodb|postgres|mysql|redis)://[a-zA-Z0-9_\-]+:[^@\s]+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "CRITICAL", "Credentials embedded in URL"
    ),
]


def get_patterns() -> list[SecretPattern]:
    """Return all detection patterns."""
    return PATTERNS


def get_pattern_names() -> list[str]:
    """Return names of all patterns."""
    return [p.name for p in PATTERNS]
