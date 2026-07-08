# ImgScan — Container / Dependency CVE Scanner (Trivy-style)

**Author:** Santhosh L
**License:** MIT
**Maps to trending tool:** [aquasecurity/trivy](https://github.com/aquasecurity/trivy) (★36k+)

## Overview

ImgScan finds known vulnerabilities in software dependencies and container image components — the
SecureNET-styled, Python-native take on **Trivy**. It supports two inputs:

1. **Dependency scan** — a `requirements.txt`. If `pip-audit` is installed it delegates to it for
   full NVD coverage; otherwise it falls back to a small built-in offline CVE rule set.
2. **Image SBOM scan** — a CycloneDX/SPDX-style JSON SBOM produced by `trivy image --format cyclonedx`.

All scanning is **read-only and offline-first**.

## CLI Usage

```bash
# Scan a requirements file
python main.py --requirements requirements.txt

# Scan a Trivy-generated SBOM
python main.py --sbom image-sbom.json

# Both
python main.py --requirements requirements.txt --sbom image-sbom.json
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5016
```

## Project Structure

```
ImgScan/
├── main.py            # CLI entry point (Rich tables)
├── engine.py          # Dependency + SBOM CVE matcher
├── database.py        # SQLite persistence
├── dashboard.py       # Flask web dashboard
├── requirements.txt
└── README.md
```

## Legal Disclaimer

ImgScan performs read-only vulnerability assessment. Use only on artifacts you own or have
permission to analyze. The author assumes no liability for misuse.

## License

MIT License — free for personal, educational, and commercial use.
