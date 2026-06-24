"""SecretSniff - Context keyword lists for entropy analysis.

Keywords and patterns used to identify lines that likely contain secrets.
"""

from __future__ import annotations

# Keywords that indicate a line contains a secret
SECRET_KEYWORDS = [
    "key", "secret", "token", "password", "api", "apikey",
    "auth", "credential", "private", "access", "bearer",
    "jwt", "session", "encrypt", "decrypt", "sign",
    "aws", "gcp", "azure", "github", "stripe", "twilio",
    "sendgrid", "mailgun", "slack", "webhook",
    "passwd", "pwd", "access_token", "refresh_token",
    "client_secret", "client_id", "consumer_key",
    "consumer_secret", "signing_key", "hmac_key",
    "encryption_key", "master_key", "private_key",
    "database_url", "db_pass", "db_password",
    "mongo_uri", "postgres_uri", "redis_url",
]

# Keywords that indicate high-value targets
HIGH_VALUE_KEYWORDS = [
    "live", "production", "prod", "master", "main",
    "sk_live", "pk_live", "live_key", "live_secret",
]

# Placeholder patterns (low confidence)
PLACEHOLDER_PATTERNS = [
    "your_api_key_here", "replace_me", "xxx", "00000000",
    "example", "placeholder", "dummy", "fake_key",
    "test_key", "sample", "changeme", "insert_here",
    "REPLACE_ME", "YOUR_KEY_HERE", "TODO", "FIXME",
    "do_not_use", "dummy_value", "test_value",
]

# File extensions that are likely secret containers
SECRET_FILE_EXTENSIONS = [
    ".env", ".ini", ".cfg", ".conf", ".config",
    ".pem", ".key", ".p12", ".pfx",
    ".secret", ".credentials",
]

# File names that are likely secret containers
SECRET_FILE_NAMES = [
    ".env", ".envrc", "credentials", "secrets",
    "api_keys", "apikeys", "tokens", "auth",
    ".aws", ".gcp", ".azure",
    "service_account.json",
]


def is_placeholder(value: str) -> bool:
    """Check if a value is clearly a placeholder."""
    val_lower = value.lower().strip()
    for pattern in PLACEHOLDER_PATTERNS:
        if pattern in val_lower:
            return True
    # Check for repeated characters
    if len(set(val_lower)) <= 3 and len(val_lower) > 4:
        return True
    return False


def is_high_value_context(line: str) -> bool:
    """Check if a line contains high-value secret indicators."""
    line_lower = line.lower()
    return any(kw in line_lower for kw in HIGH_VALUE_KEYWORDS)
