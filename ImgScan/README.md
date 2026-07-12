# ImgScan — Dependency & Container CVE Scanner

> Trivy-style read-only security scanning for dependencies and container images — Python, Node.js, Java, Ruby, Dockerfiles, and SBOMs.

ImgScan finds **known vulnerabilities (CVEs)** in your project's dependencies and flags **CISA Known Exploited Vulnerabilities (KEV)** with a red EXPLOITED badge. It scans dependency manifests, Dockerfiles (30 checks), and CycloneDX/SPDX SBOMs — fully **offline-first** with a bundled CVE rule set (500+ entries).

## Features

- **Multi-ecosystem**: Python (`requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `setup.py`, `poetry.lock`), Node.js (`package.json`, `package-lock.json`, `yarn.lock`), Java (`pom.xml`, `build.gradle`, `*.jar`), Ruby (`Gemfile.lock`).
- **pip-audit integration** with graceful offline fallback (no crash if absent).
- **30 Dockerfile security checks** across 8 categories (base image, privileges, secrets, layer hygiene, network, build practice, multi-stage, pinning).
- **CISA KEV integration** — exploited-in-wild flagging.
- **CycloneDX SBOM** parsing + generation (`--generate-sbom`).
- **CI/CD ready** — exit code `1` on CRITICAL/HIGH + **SARIF v2.1.0** export for GitHub Code Scanning.

## Install

```bash
cd ImgScan
pip install -r requirements.txt     # rich, flask, reportlab
# optional, for best Python coverage:
pip install pip-audit
```

## Usage

```bash
# Mode 1 — directory (auto-detect all manifests)
python main.py scan --path ./myproject

# Mode 2 — SBOM scan
python main.py scan --sbom sbom.json

# Mode 3 — Dockerfile audit
python main.py dockerfile --file Dockerfile

# Mode 4 — pip-audit mode (Python)
python main.py pip --requirements requirements.txt

# Mode 5 — single package check
python main.py check requests==2.25.1

# Generate a CycloneDX SBOM while scanning
python main.py scan --path ./myproject --generate-sbom sbom.json

# Export reports
python main.py scan --path ./myproject --json out.json --csv out.csv \
    --sarif out.sarif --pdf report.pdf
```

Flags: `--json`, `--csv`, `--sarif`, `--pdf`, `--generate-sbom FILE`, `--no-disclaimer`.

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5016
```

Tabs: Scan · Vulnerabilities (filter by severity/ecosystem/KEV, click row for detail drawer) · Dockerfile · SBOM · History · Export.

## Credential & Safety Notes

- **Read-only**: ImgScan never executes scanned code or modifies dependency files.
- **No internet required**: the bundled offline rule set in `data/` covers 500+ CVEs across Python/Node/Java/Ruby.
- **Keep rules fresh**: `python update_cves.py` fetches fresh data from the NVD API when online.
- **Disclaimer**: *ImgScan scans dependency manifests read-only. Only scan projects you own or maintain.*

## Severity & CVSS

| Severity | CVSS v3 |
|----------|---------|
| CRITICAL | 9.0–10.0 |
| HIGH | 7.0–8.9 |
| MEDIUM | 4.0–6.9 |
| LOW | 0.1–3.9 |

## Folder Structure

```
ImgScan/
├── main.py                  # CLI entry point
├── scanners/                # python / node / java / ruby / dockerfile auditors
├── parsers/                 # version_matcher, sbom_parser, sbom_generator
├── data/                    # offline_cve_rules, java_cve_rules, kev_list, cve_enrichment
├── output/                  # sarif.py, reporter.py (PDF)
├── database.py              # SQLite (scans / vulnerabilities / dockerfile_findings / sbom_components)
├── dashboard.py             # Flask app (port 5016)
├── templates/index.html
├── update_cves.py           # refresh offline CVE data from NVD
├── LEARN.md / README.md / requirements.txt
```

## Integration

Registered in `SecureNET-Control-Panel/securenet.yaml` (port 5016). Quick scan endpoint: `POST /api/quickscan/imgscan` with body `{"path": "./myproject"}`.
