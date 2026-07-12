# 🛡️ ImgScan — Learn Before You Use

Welcome! If you've never run a dependency / container vulnerability scanner before, this guide walks you through everything you need to know — no security background required.

## What is ImgScan?

ImgScan checks your project's dependency files (and Dockerfiles) for **known vulnerabilities (CVEs)** — the same job as [Trivy](https://trivy.dev). It tells you:

- which packages you use are vulnerable,
- how bad each one is (CVSS score + severity),
- whether attackers are **already exploiting it in the wild** (CISA KEV list),
- and the exact command to upgrade to a safe version.

## Why does this matter?

A single old `requests==2.20.0` can let an attacker steal credentials. Most breaches don't exploit fancy zero-days — they exploit **known, years-old bugs in forgotten dependencies**. ImgScan catches those before they reach production.

## Key terms (plain English)

- **CVE** — a publicly tracked vulnerability ("Common Vulnerability & Exposure"), e.g. `CVE-2021-44228` (Log4Shell).
- **CVSS** — a 0–10 danger score. 9+ critical, 7–8.9 high, 4–6.9 medium, 0.1–3.9 low.
- **KEV** — "Known Exploited Vulnerabilities": CVEs that real attackers are actively using right now. ImgScan marks these with a red **EXPLOITED** badge.
- **SBOM** — "Software Bill of Materials": a list of every component in your project (CycloneDX format).
- **Manifest** — your dependency file (`requirements.txt`, `package-lock.json`, `pom.xml`, `Gemfile.lock`).

## The 5 scanning modes

| Mode | Command | What it does |
|------|---------|--------------|
| Directory | `imgscan scan --path ./proj` | Auto-detects all manifests, scans every ecosystem |
| SBOM | `imgscan scan --sbom sbom.json` | Scans a CycloneDX/SPDX SBOM |
| Dockerfile | `imgscan dockerfile --file Dockerfile` | 30 security misconfiguration checks |
| pip-audit | `imgscan pip --requirements req.txt` | Uses `pip-audit` if installed, else offline rules |
| Single pkg | `imgscan check requests==2.25.1` | Checks one package@version |

## A real example

```
$ imgscan check requests==2.25.1 --no-disclaimer
┌──────────┬─────────┬────────────────┬──────────┬──────┬──────────┬────────┐
│ requests │ 2.25.1  │ CVE-2023-32681 │ MEDIUM  │ 6.1  │ —        │ 2.31.0 │
└──────────┴─────────┴────────────────┴──────────┴──────┴──────────┴────────┘
```
→ Fix: `pip install requests==2.31.0`

## Important cautions

- ImgScan is **read-only**: it never runs your code or edits your files.
- It **never requires internet** — a bundled offline CVE rule set (500+ entries) ships in `data/`.
- For maximum coverage install `pip-audit` (`pip install pip-audit`); ImgScan uses it automatically when present.
- Keep the offline database fresh: `python update_cves.py` (fetches from NVD when online).
- Exit code is **1** if any CRITICAL/HIGH is found — wire it into CI/CD.

## Learning path

1. Run `imgscan check django==2.2.0` to see a critical.
2. Run a directory scan on a real project.
3. Audit a Dockerfile with `imgscan dockerfile --file Dockerfile`.
4. Export SARIF and drop it into a GitHub Actions workflow.

Happy (safe) shipping! 🚀
