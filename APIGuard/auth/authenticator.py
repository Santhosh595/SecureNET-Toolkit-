"""APIGuard — Authentication handler (Bearer, API key, Basic, Cookie, OAuth2, Custom)."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class AuthConfig:
    auth_type: str  # bearer, apikey, basic, cookie, oauth, header, none
    auth_value: str  # token, or "key:value" for apikey/header
    _redacted: str = "[REDACTED]"

    def __post_init__(self) -> None:
        # Sanitize
        self.auth_type = self.auth_type.lower().strip()

    @property
    def is_authenticated(self) -> bool:
        return self.auth_type != "none" and bool(self.auth_value)

    def get_headers(self) -> Dict[str, str]:
        """Return the HTTP headers needed for this auth type."""
        if self.auth_type == "bearer":
            return {"Authorization": f"Bearer {self.auth_value}"}
        elif self.auth_type == "apikey":
            if ":" in self.auth_value:
                key, val = self.auth_value.split(":", 1)
                return {key.strip(): val.strip()}
            return {"X-API-Key": self.auth_value}
        elif self.auth_type == "basic":
            # user:password
            encoded = base64.b64encode(self.auth_value.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        elif self.auth_type == "cookie":
            return {"Cookie": self.auth_value}
        elif self.auth_type == "oauth":
            return {"Authorization": f"Bearer {self.auth_value}"}
        elif self.auth_type == "header":
            if ":" in self.auth_value:
                key, val = self.auth_value.split(":", 1)
                return {key.strip(): val.strip()}
            return {}
        return {}

    def get_redacted_headers(self) -> Dict[str, str]:
        """Same as get_headers but with value redacted for logging/reporting."""
        h = self.get_headers()
        for k in h:
            h[k] = self._redacted
        return h

    @classmethod
    def parse(cls, auth_str: str) -> "AuthConfig":
        """Parse an --auth argument like 'bearer TOKEN' or 'apikey X-API-Key:VALUE' or 'none'."""
        auth_str = auth_str.strip()
        if not auth_str or auth_str.lower() == "none":
            return cls(auth_type="none", auth_value="")
        parts = auth_str.split(" ", 1)
        auth_type = parts[0].lower().strip()
        auth_value = parts[1].strip() if len(parts) > 1 else ""
        return cls(auth_type=auth_type, auth_value=auth_value)
