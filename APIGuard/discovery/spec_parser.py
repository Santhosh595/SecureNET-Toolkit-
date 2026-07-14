"""APIGuard — OpenAPI/Swagger spec parser (2.0, 3.0, 3.1)."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


class SpecParser:
    """Parse an OpenAPI/Swagger spec file into a list of endpoints."""

    def __init__(self, spec_path: str) -> None:
        self.spec_path = spec_path
        self.spec: Dict[str, Any] = {}
        self.endpoints: List[Dict[str, Any]] = []
        self.version: str = ""
        self._load()

    def _load(self) -> None:
        raw = open(self.spec_path, "rb").read()
        if self.spec_path.endswith((".yaml", ".yml")):
            if yaml is None:
                raise ImportError("PyYAML is required to parse YAML specs. pip install pyyaml")
            self.spec = yaml.safe_load(raw)
        else:
            self.spec = json.loads(raw)
        self.version = self.spec.get("swagger", self.spec.get("openapi", "unknown"))

    def parse(self) -> List[Dict[str, Any]]:
        """Return list of {method, path, parameters, auth_required, summary}."""
        paths = self.spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                    continue
                params = []
                for p in details.get("parameters", []):
                    params.append(p.get("name", "?"))
                sec = details.get("security", [])
                auth_req = 1 if sec else 0
                self.endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "parameters": ",".join(params) if params else "",
                    "auth_required": auth_req,
                    "summary": details.get("summary", ""),
                    "source": "spec",
                })
        # Also parse global security
        if not any(e["auth_required"] for e in self.endpoints):
            global_sec = self.spec.get("security", [])
            if global_sec:
                for e in self.endpoints:
                    e["auth_required"] = 1
        return self.endpoints

    def get_global_auth(self) -> str:
        sec_defs = self.spec.get("components", {}).get("securitySchemes", {}) or self.spec.get("securityDefinitions", {})
        for name, scheme in sec_defs.items():
            scheme_type = scheme.get("type", "")
            if scheme_type in ("http", "apiKey", "oauth2", "openIdConnect"):
                return scheme_type
        return ""
