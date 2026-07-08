# VulnProbe — Template-Based Vulnerability Scanner (Nuclei-style)

**Author:** Santhosh L
**License:** MIT
**Maps to trending tool:** [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) (★29k+)

## Overview

VulnProbe is a lightweight, template-driven HTTP probe engine in the spirit of **Nuclei**.
Instead of bundling thousands of templates, it ships a small, readable YAML template set that
sends templated requests to a target and evaluates **matchers** (status code / word / regex) to
surface misconfigurations, exposed files, and version disclosure. New checks are added by
dropping a `.yaml` file into `templates/` — no code changes required.

All probes are **read-only** and safe by design (no fuzzing, no payloads), making VulnProbe
suitable for authorized recon and continuous self-scanning.

## How It Works

Each template declares:
- `info` — name, severity, description
- `requests` — HTTP method + path to hit
- `matchers` — conditions that, if met, produce a finding (`status`, `word`, `regex`; `and`/`or`)

```yaml
id: exposed-sensitive-files
info:
  name: Exposed Sensitive Files
  severity: medium
requests:
  - method: GET
    path: /.env
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["API_KEY", "DB_PASSWORD"]
        condition: or
    matchers-condition: and
```

## CLI Usage

```bash
# Scan a target with all bundled templates
python main.py https://example.com

# Report only high/critical findings
python main.py https://example.com --severity high,critical

# Use a custom template directory
python main.py https://example.com --templates my-templates

# Skip the disclaimer prompt
python main.py https://example.com --no-disclaimer
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5013
```

Enter a target URL and view findings grouped by severity.

## Project Structure

```
VulnProbe/
├── main.py            # CLI entry point (Rich tables)
├── engine.py          # Template loader + matcher engine
├── database.py        # SQLite persistence
├── dashboard.py       # Flask web dashboard
├── templates/         # YAML probe templates
├── requirements.txt
└── README.md
```

## Legal Disclaimer

**VulnProbe is for authorized testing only.** Scan only hosts you own or have explicit written
permission to test. The author assumes no liability for misuse.

## License

MIT License — free for personal, educational, and commercial use.
