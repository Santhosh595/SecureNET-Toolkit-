# SecretSniff — Hardcoded Secret & API Key Scanner

**Author:** Santhosh L
**License:** MIT

## Overview

SecretSniff is a production-grade DevSecOps secret scanning tool that detects 50+ types of hardcoded secrets in codebases, git history, environment files, and CI/CD pipelines. Fully local, offline, and open source.

## Why Hardcoded Secrets Are Critical

Hardcoded secrets in source code have caused major security breaches. Attackers scan public repositories for leaked credentials using automated tools. A single exposed AWS key or GitHub token can compromise entire infrastructure. SecretSniff helps prevent this by catching secrets before they reach production.

## Detection Methods

1. **Regex Pattern Matching** — 50+ compiled regex patterns for known secret formats
2. **Shannon Entropy Analysis** — Detects high-entropy strings that are likely random secrets
3. **Keyword + Value Pairs** — Identifies assignment patterns like `API_KEY = "..."`

## Detected Secret Patterns (50+)

| Category | Patterns |
|----------|----------|
| **Cloud Providers** | AWS Access Key, AWS Secret Key, GCP API Key, GCP Service Account, Azure Storage Key, Azure SAS Token, DigitalOcean Token, Heroku API Key |
| **Version Control & CI** | GitHub Personal Token, GitHub OAuth Token, GitHub App Token, GitHub Refresh Token, GitLab Token, CircleCI Token, Travis CI Token, Jenkins API Token |
| **Payment** | Stripe Secret Key, Stripe Publishable Key, PayPal Client Secret, Square Access Token, Braintree Token |
| **Communication** | Slack Bot Token, Slack Webhook URL, Slack App Token, Twilio Account SID, Twilio Auth Token, SendGrid API Key, Mailgun API Key, Mailchimp API Key |
| **Databases** | MongoDB URI, PostgreSQL URI, MySQL URI, Redis URI with password, DB Password Assignment |
| **Cryptographic** | RSA Private Key, EC Private Key, PGP Private Key, OpenSSH Private Key, PKCS8 Private Key, Certificate |
| **AI & APIs** | OpenAI API Key, Anthropic API Key, HuggingFace Token, Replicate Token |
| **Other** | NPM Auth Token, PyPI Token, Dockerhub Token, JWT Token, Generic Secret, Generic Password, Generic API Key, IP with credentials in URL |

## CLI Usage

```bash
# Scan a directory
python main.py scan --path ./myproject

# Scan a git repository (current tree)
python main.py scan --repo ./myrepo

# Scan git history (all commits)
python main.py scan --repo ./myrepo --history

# Scan git history (last 100 commits)
python main.py scan --repo ./myrepo --history --depth 100

# Scan from stdin
cat config.yml | python main.py scan --stdin

# Include test files
python main.py scan --path . --include-tests

# Export to SARIF (GitHub Code Scanning)
python main.py scan --path . --output results.sarif

# Export to JUnit XML (CI/CD)
python main.py scan --path . --output results.xml

# Export to PDF
python main.py scan --path . --output report.pdf

# Save baseline
python main.py baseline --path . --save baseline.json

# Compare against baseline
python main.py scan --path . --baseline baseline.json

# Install pre-commit hook
python main.py install-hook
```

## Pre-commit Hook

```bash
# Install the hook
python main.py install-hook

# The hook will now run on every git commit
# It blocks commits with CRITICAL or HIGH findings
# Bypass (not recommended): git commit --no-verify
```

## CI/CD Integration

### GitHub Actions

```yaml
name: SecretSniff
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python main.py scan --path . --output results.sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
secret_scan:
  stage: test
  script:
    - pip install -r requirements.txt
    - python main.py scan --path . --output results.xml
  artifacts:
    reports:
      junit: results.xml
```

## Allowlist System

Create a `.secretsniff-ignore` file in your repo root:

```
# Ignore by rule name
rule:Generic Password

# Ignore by path
path:tests/fixtures/

# Ignore by value pattern
pattern:fake_key_for_testing

# Ignore by commit hash
commit:abc123def
```

Or use inline ignores:
```python
API_KEY = "hardcoded_value"  # secretsniff:ignore
```

## Baseline Mode

For brownfield repositories with existing secrets:

```bash
# Save current state as accepted baseline
python main.py baseline --save baseline.json

# Future scans only report NEW findings
python main.py scan --path . --baseline baseline.json
```

## Project Structure

```
SecretSniff/
├── main.py                  # CLI entry point (Rich output)
├── scanner/
│   ├── file_scanner.py      # File/directory scanning
│   ├── git_scanner.py       # Git repo + history scanning
│   ├── env_scanner.py       # Env file targeting
│   └── entropy.py           # Shannon entropy calculator
├── patterns/
│   ├── rules.py             # All 50+ regex patterns
│   └── keywords.py          # Context keyword lists
├── allowlist.py             # Allowlist management
├── baseline.py              # Baseline comparison
├── output/
│   ├── sarif.py             # SARIF format export
│   ├── junit.py             # JUnit XML export
│   └── reporter.py          # PDF report generation
├── hooks/
│   └── pre_commit.sh        # Git pre-commit hook template
├── database.py              # SQLite operations
├── dashboard/
│   ├── app.py               # Flask web dashboard
│   └── templates/
│       └── index.html       # Dashboard UI
├── config/
│   └── default_config.yaml  # Default configuration
├── requirements.txt
└── README.md
```

## Remediation Guidance

For each finding, SecretSniff recommends:

1. **Immediate**: Revoke and rotate the exposed key
2. **Short-term**: Move secrets to environment variables
3. **Long-term**: Use a secrets manager:
   - AWS: AWS Secrets Manager / Parameter Store
   - GCP: Secret Manager
   - Azure: Key Vault
   - Generic: HashiCorp Vault, Doppler, 1Password Secrets

## Legal Disclaimer

**SecretSniff is for scanning repositories you own or have explicit authorization to audit.**

- Unauthorized access to computer systems is illegal.
- All scanning is performed locally. No data is transmitted externally.
- Report findings responsibly if discovered in third-party repositories.

## License

MIT License — free for personal, educational, and commercial use.
