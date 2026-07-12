"""ImgScan — Dockerfile static auditor (30 checks)."""

from __future__ import annotations

import os
import re
from typing import List

from .common import DockerFinding

SECRET_ENV_RE = re.compile(
    r"ENV\s+.*\b(AWS_SECRET|SECRET_KEY|SECRET_ACCESS|PASSWORD|PASSWD|PRIVATE_KEY|"
    r"API_KEY|TOKEN|ACCESS_KEY|DB_PASSWORD|GITHUB_TOKEN|BEARER)\b", re.I)
SECRET_ARG_RE = re.compile(r"ARG\s+.*\b(SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)\b", re.I)
SECRET_RUN_RE = re.compile(r'(curl|wget).{0,80}(Authorization|Bearer|token=|password=)', re.I)
SECRET_INLINE_RE = re.compile(r'(curl|wget).{0,120}(["\']\s*[^"\']{8,})', re.I)


def audit_dockerfile(path: str) -> List[DockerFinding]:
    """Run all 30 Dockerfile checks. Returns DockerFinding list."""
    findings: List[DockerFinding] = []

    def add(cid, line, sev, desc, rem):
        findings.append(DockerFinding(check_id=cid, line_number=line,
                                      severity=sev, description=desc,
                                      remediation=rem))

    if not os.path.isfile(path):
        add("DF-000", 0, "INFO", "Dockerfile not found.", "Provide a Dockerfile.")
        return findings

    lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    has_user = False
    has_healthcheck = False
    has_multistage = False
    from_base = ""
    line_of = {}
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        line_of[i] = line
        up = line.upper()

        # ---- Base image checks ----
        if up.startswith("FROM "):
            base = line[5:].strip().split(" ")[0]
            from_base = base
            # DF-001 latest tag
            if re.search(r":latest$", base) or (" AS " not in line and base.count(":") == 0 and "/" not in base and base != "scratch"):
                if re.search(r":latest$", base):
                    add("DF-001", i, "HIGH",
                        f"Base image '{base}' uses the :latest tag (unpredictable builds).",
                        "Pin to a specific version, e.g. FROM ubuntu:22.04.")
            # DF-002 unofficial registry
            if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:", base) or \
               ("/" in base and not base.startswith(("library/", "docker.io/")) and "." in base.split("/")[0]):
                add("DF-002", i, "MEDIUM",
                    f"Base image '{base}' is from a non-official registry path.",
                    "Use official images (docker.io/library/...) or a trusted registry.")
            # DF-003 distroless/minimal GOOD
            if "distroless" in base.lower() or base.lower().startswith(("alpine", "gcr.io/distroless")):
                add("DF-003", i, "INFO",
                    f"Base image '{base}' is minimal/distroless (good practice).",
                    "Keep using minimal base images.")
            # DF-004 deprecated image
            if base.lower().startswith(("ubuntu:14.04", "ubuntu:16.04", "debian:8", "debian:9", "centos:6", "centos:7")):
                add("DF-004", i, "HIGH",
                    f"Base image '{base}' is deprecated/EOL.",
                    "Upgrade to a supported LTS base image.")

        # ---- User privileges ----
        if up.startswith("USER "):
            has_user = True
            user = line[5:].strip()
            if user.lower() == "root":
                add("DF-006", i, "HIGH",
                    "USER is explicitly set to root.",
                    "Run the container as a non-root user, e.g. USER appuser.")
        # DF-007 SUID/SGID via chmod
        if "chmod" in line and ("4755" in line or "2755" in line or "+s" in line or "u+s" in line or "g+s" in line):
            add("DF-007", i, "MEDIUM",
                "SUID/SGID bit set via chmod (elevated privileges).",
                "Avoid setting SUID/SGID bits; review necessity.")

        # ---- Secrets ----
        if SECRET_ENV_RE.search(line):
            add("DF-008", i, "CRITICAL",
                "ENV may contain a secret (password/key/token).",
                "Use Docker secrets or runtime env injection; never bake secrets in.")
        if SECRET_ARG_RE.search(line):
            add("DF-009", i, "HIGH",
                "ARG used for a secret; ARG values persist in `docker history`.",
                "Pass secrets at build time via --secret, not ARG.")
        if SECRET_RUN_RE.search(line):
            add("DF-010", i, "CRITICAL",
                "Secret value (Authorization/Bearer/password) hardcoded in RUN.",
                "Move secrets out of the build; use secret mounts.")

        # ---- Layer hygiene ----
        if "apt-get install" in line and "--no-install-recommends" not in line:
            add("DF-011", i, "LOW",
                "apt-get install without --no-install-recommends pulls extras.",
                "Use `apt-get install --no-install-recommends`.")
        if "apt-get install" in line and "rm -rf /var/lib/apt/lists" not in line and "&&" not in line.replace("apt-get install", "X", 1):
            # only flag if cache not cleared in same chain
            if "rm -rf /var/lib/apt/lists" not in line:
                add("DF-012", i, "LOW",
                    "Package cache not cleared (bloats image).",
                    "Chain: `&& rm -rf /var/lib/apt/lists/*`.")
        if up.startswith("COPY .") or up.startswith("COPY") and " ." in line and line.strip().endswith("."):
            add("DF-014", i, "MEDIUM",
                "COPY . . copies the entire build context (may include secrets/.git).",
                "Use a .dockerignore and copy only needed paths.")

        # ---- Network exposure ----
        if up.startswith("EXPOSE "):
            for port in re.findall(r"(\d+)", line):
                p = int(port)
                if p < 1024:
                    add("DF-015", i, "MEDIUM",
                        f"EXPOSE on privileged port {p} (<1024).",
                        "Prefer unprivileged ports (>1024) unless required.")
                if p == 22:
                    add("DF-017", i, "HIGH",
                        "EXPOSE 22 — running SSH inside a container is discouraged.",
                        "Drop SSH; use `docker exec` for debugging.")

        # ---- Build best practices ----
        if up.startswith("HEALTHCHECK"):
            has_healthcheck = True
        if up.startswith("ADD ") and "ADD " in line and "COPY" not in line:
            add("DF-020", i, "LOW",
                "ADD used; COPY is preferred (ADD has extra unsafe features).",
                "Use COPY unless you need ADD's tar/remote fetch.")
        if re.search(r"curl\s+.*\|\s*(bash|sh)", line) or re.search(r"wget\s+.*\|\s*(bash|sh)", line):
            add("DF-021", i, "HIGH",
                "curl|bash (or wget|sh) pattern — remote code execution risk.",
                "Download, verify checksum, then run; avoid piping to a shell.")
        if re.search(r"\| ?(bash|sh)\b", line) and ("curl" in line or "wget" in line):
            add("DF-022", i, "HIGH",
                "wget|sh pattern detected — remote code execution risk.",
                "Avoid piping downloaded scripts directly to a shell.")

        # ---- Multi-stage / build tools ----
        if " AS " in line.upper() or re.search(r"\bAS build\b", line, re.I):
            has_multistage = True
        if re.search(r"(gcc|make|build-essential|g\+\+|cmake|go build)", line) and "RUN" in up:
            add("DF-024", i, "MEDIUM",
                "Build toolchain present (may leak into final image).",
                "Use multi-stage builds; keep compilers out of the final stage.")

        # ---- Package pinning ----
        if "apt-get install" in line:
            pkgs = re.findall(r"apt-get install(?:\s+--[\w-]+)*\s+([\w.\-]+)", line)
            for pkg in pkgs:
                if "=" not in pkg and pkg not in ("apt-get", "--no-install-recommends", "-y", "-yq"):
                    add("DF-025", i, "MEDIUM",
                        f"apt-get install without version pin: {pkg}.",
                        f"Pin: `apt-get install {pkg}=<version>`.")
        if re.search(r"pip install\s+[\w\-]+$", line) or re.search(r"pip install\s+(?!.*==)[\w\-]+ ", line):
            if "==" not in line and "requirements" not in line:
                add("DF-026", i, "MEDIUM",
                    "pip install without version pin.",
                    "Pin versions, e.g. `pip install flask==3.0.3`.")
        if "npm install" in line and "package-lock" not in line and "--package-lock" not in line:
            add("DF-027", i, "MEDIUM",
                "npm install without a lock file in image.",
                "Copy package-lock.json and run `npm ci`.")

    # ---- Post-pass checks ----
    if not has_user:
        add("DF-005", 0, "HIGH",
            "No USER instruction — container runs as root by default.",
            "Add `USER nonroot` before CMD/ENTRYPOINT.")
    if not has_healthcheck:
        add("DF-018", 0, "LOW",
            "No HEALTHCHECK instruction.",
            "Add a HEALTHCHECK to let the orchestrator detect unhealthy containers.")
    if not os.path.exists(os.path.join(os.path.dirname(path), ".dockerignore")):
        add("DF-019", 0, "MEDIUM",
            "No .dockerignore alongside the Dockerfile.",
            "Add a .dockerignore to exclude .git, secrets, node_modules.")
    if not has_multistage:
        add("DF-023", 0, "INFO",
            "No multi-stage build detected for a compiled language.",
            "Use multi-stage builds to shrink the final image.")

    return findings
