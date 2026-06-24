# SecretSniff - Hardcoded Secret & API Key Scanner

**Author:** Santhosh L
**License:** MIT

## Overview

SecretSniff is a production-grade DevSecOps secret scanning tool that detects 50+ types of hardcoded secrets in codebases, git history, environment files, and CI/CD pipelines. Fully local, offline, and open source. Comparable to Gitleaks and TruffleHog but designed for maximum privacy and zero network dependencies.

## Why Hardcoded Secrets Are Critical

Hardcoded secrets in source code have caused major security breaches:

- **Uber (2026):** Attackers accessed Uber's source code repository because credentials were hardcoded in the source files. The breach affected internal services and sensitive data.
- **Samsung (2026):** Researchers found hardcoded API keys in Samsung's public source code repositories, exposing access to Android system-level services.
- **General Threat:** Attackers continuously scan public repositories like GitHub using automated tools. A single exposed AWS key can lead to complete cloud infrastructure compromise and massive financial loss.

SecretSniff helps prevent this by catching secrets before they reach production or get pushed to version control.

## Detection Methods

1. **Regex Pattern Matching** - 50+ compiled regex patterns for known secret formats
2. **Shannon Entropy Analysis** - Detects high-entropy strings that are likely random secrets
3. **Keyword + Value Pairs** - Identifies assignment patterns like `API_KEY = "..."`

## Detected Secret Patterns (50+)

### Cloud Providers (8)
| # | Pattern | Regex Match | Severity |
|---|---------|-------------|----------|
| 1 | AWS Access Key ID | `AKIA[0-9A-Z]{16}` | CRITICAL |
| 2 | AWS Secret Access Key | `[0-9a-zA-Z/+]{40}` near aws secret | CRITICAL |
| 3 | AWS Session Token | Base64 100+ chars near aws_session_token | CRITICAL |
| 4 | GCP API Key | `AIza[0-9A-Za-z\-_]{35}` | CRITICAL |
| 5 | GCP Service Account JSON | `"type": "service_account"` + `"private_key"` | CRITICAL |
| 6 | Azure Storage Key | `AccountKey` + base64 88 chars | CRITICAL |
| 7 | Azure SAS Token | `sig=` in Azure storage URL | HIGH |
| 8 | DigitalOcean Token | `dop_v1_[a-f0-9]{64}` | CRITICAL |
| 9 | Heroku API Key | UUID format near heroku key | CRITICAL |

### Version Control & CI (7)
| # | Pattern | Regex Match | Severity |
|---|---------|-------------|----------|
| 10 | GitHub Personal Token | `ghp_[a-zA-Z0-9]{36}` | CRITICAL |
| 11 | GitHub OAuth Token | `gho_[a-zA-Z0-9]{36}` | CRITICAL |
| 12 | GitHub App Token | `ghs_[a-zA-Z0-9]{36}` | CRITICAL |
| 13 | GitHub Refresh Token | `ghr_[a-zA-Z0-9]{76}` | CRITICAL |
| 14 | GitLab Personal Token | `glpat-[a-zA-Z0-9\-]{20}` | CRITICAL |
| 15 | CircleCI Token | `circle-token` + `[a-f0-9]{40}` | HIGH |
| 16 | Travis CI Token | 22+ chars near travis_token | HIGH |
| 17 | Jenkins API Token | 32 hex chars near jenkins | HIGH |

### Payment (5)
| # | Pattern | Regex Match | Severity |
|---|---------|-------------|----------|
| 18 | Stripe Secret Key | `sk_live_[a-zA-Z0-9]{24}` | CRITICAL |
| 19 | Stripe Publishable Key | `pk_live_[a-zA-Z0-9]{24}` | HIGH |
| 20 | Stripe Test Key | `sk_test_[a-zA-Z0-9]{24}` | MEDIUM |
| 21 | PayPal Client Secret | 32+ chars near paypal secret | CRITICAL |
| 22 | Square Access Token | `sq0atp-[a-zA-Z0-9\-_]{22}` | CRITICAL |
| 23 | Braintree Token | 32+ chars near braintree | CRITICAL |

### Communication (7)
| # | Pattern | Regex Match | Severity |
|---|---------|-------------|----------|
| 24 | Slack Bot Token | `xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}` | CRITICAL |
| 25 | Slack Webhook URL | `hooks.slack.com/services/T.../B...` | HIGH |
| 26 | Slack App Token | `xapp-[0-9\-]+[a-zA-Z0-9\-]+` | CRITICAL |
| 27 | Twilio Account SID | `AC[a-zA-Z0-9]{32}` | CRITICAL |
| 28 | Twilio Auth Token | 32 hex chars near twilio | CRITICAL |
| 29 | SendGrid API Key | `SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}` | CRITICAL |
| 30 | Mailgun API Key | `key-[a-zA-Z0-9]{32}` | CRITICAL |
| 31 | Mailchimp API Key | `[a-f0-9]{32}-us[0-9]{2}` | CRITICAL |

### Databases (5)
| # | Pattern | Regex Match | Severity |
|---|---------|-------------|----------|
| 32 | MongoDB URI | `mongodb://user:pass@host` | CRITICAL |
| 33 | PostgreSQL URI | `postgresql://user:pass@host` | CRITICAL |
| 34 | MySQL URI | `mysql://user:pass@host` | CRITICAL |
| 35 | Redis URI with password | `redis://:password@host` | CRITICAL |
| 36 | DB Password Assignment | `DB_PASS\|DATABASE_PASSWORD\|POSTGRES_PASSWORD` etc. | CRITICAL |

### Cryptographic (6)
| # | Pattern | Regex Match | Severity |
|---|---------|-------------|----------|
| 37 | RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| 38 | EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | CRITICAL |
| 39 | PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | CRITICAL |
| 40 | OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | CRITICAL |
| 41 | PKCS8 Private Key | `-----BEGIN PRIVATE KEY-----` | CRITICAL |
| 42 | Certificate | `-----BEGIN CERTIFICATE-----` | MEDIUM |

### AI & APIs (4)
| # | Pattern | Regex Match | Severity |
|---|---------|-------------|----------|
| 43 | OpenAI API Key | `sk-[a-zA-Z0-9]{48}` | CRITICAL |
| 44 | Anthropic API Key | `sk-ant-[a-zA-Z0-9\-_]{95}` | CRITICAL |
| 45 | HuggingFace Token | `hf_[a-zA-Z0-9]{34}` | CRITICAL |
| 46 | Replicate Token | `r8_[a-zA-Z0-9]{40}` | CRITICAL |

### Other (7)
| # | Pattern | Regex Match | Severity |
|---|---------|-------------|----------|
| 47 | NPM Auth Token | `npm_[a-zA-Z0-9]{36}` | CRITICAL |
| 48 | PyPI Token | `pypi-[a-zA-Z0-9\-_]{210}` | CRITICAL |
| 49 | Dockerhub Token | 24 chars near dockerhub token | CRITICAL |
| 50 | JWT Token | `eyJ...\.eyJ...\.[a-zA-Z0-9\-_]+` | HIGH |
| 51 | Generic Secret Assignment | `secret[_-]?key\s*=\s*["'][^"']{8,}["']` | MEDIUM |
| 52 | Generic Password Assignment | `password\s*=\s*["'][^"']{4,}["']` | MEDIUM |
| 53 | Generic API Key Assignment | `api[_-]?key\s*=\s*["'][^"']{8,}["']` | MEDIUM |
| 54 | IP with credentials in URL | `http://user:pass@ip` | CRITICAL |

**Total: 54 patterns**

## CLI Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Scan a directory
python main.py scan --path ./myproject

# Scan a git repository (working tree)
python main.py scan --repo ./myrepo

# Scan git history (all commits)
python main.py scan --repo ./myrepo --history

# Scan git history (last 100 commits)
python main.py scan --repo ./myrepo --history --depth 100

# Scan from stdin
cat config.yml | python main.py scan --stdin

# Include test files
python main.py scan --path . --include-tests

# Don't respect .gitignore
python main.py scan --path . --no-gitignore

# Group findings by file
python main.py scan --path . --group-by-file

# Export to SARIF (GitHub Code Scanning)
python main.py scan --path . --output results.sarif

# Export to JUnit XML (Jenkins, CircleCI)
python main.py scan --path . --output results.xml

# Export to PDF
python main.py scan --path . --output report.pdf

# Save baseline (brownfield repos)
python main.py baseline --path . --save baseline.json

# Compare against baseline (only new findings)
python main.py scan --path . --baseline baseline.json

# Show known + new findings
python main.py scan --path . --baseline baseline.json --show-known

# Install pre-commit hook
python main.py install-hook

# Launch web dashboard
python main.py dashboard --port 5800
```

## Pre-commit Hook Setup

```bash
# Navigate to your repository
cd ./myrepo

# Install hook (scans staged files only)
python main.py install-hook

# The hook will now run on every git commit
# It blocks commits with CRITICAL or HIGH findings

# Bypass (not recommended)
git commit --no-verify

# To uninstall, remove the hook
rm .git/hooks/pre-commit
```

## CI/CD Integration

### GitHub Actions

```yaml
name: SecretSniff Security Scan
on: [push, pull_request]
jobs:
  secretsniff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v4
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run SecretSniff
        run: python main.py scan --path . --output results.sarif --no-disclaimer
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
secret_scan:
  stage: test
  script:
    - pip install -r requirements.txt
    - python main.py scan --path . --output results.xml --no-disclaimer
  artifacts:
    reports:
      junit: results.xml
  allow_failure: false
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Secret Scan') {
            steps {
                sh 'pip install -r requirements.txt'
                sh 'python main.py scan --path . --output results.xml --no-disclaimer'
            }
        }
    }
    post {
        always {
            junit 'results.xml'
        }
    }
}
```

## Allowlist System

### .secretsniff-ignore file (repo root)

```
# Ignore by rule name
rule:Generic Password
rule:High Entropy String

# Ignore by path
path:tests/fixtures/
path:benchmarks/

# Ignore by value pattern
pattern:fake_key_for_testing
pattern:example.com

# Ignore by commit hash
commit:abc123def456
```

### Inline ignore

```python
API_KEY = "hardcoded_value"  # secretsniff:ignore
password = "test123"  # secretsniff:ignore
```

### Global config (~/.secretsniff/config.yaml)

```yaml
allowlist:
  rules:
    - Generic Password
  paths:
    - tests/
  patterns:
    - my_test_key_prefix
  commits:
    - abc123
```

## Baseline Mode

For brownfield repositories that have existing secrets you cannot immediately fix:

```bash
# 1. Save current findings as accepted baseline
python main.py baseline --save baseline.json

# 2. Future scans only report NEW findings
python main.py scan --path . --baseline baseline.json

# 3. Show all (known + new)
python main.py scan --path . --baseline baseline.json --show-known

# 4. When ready, remove baseline and re-scan
python main.py scan --path .
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings detected |
| 2 | Scan error |

## Project Structure

```
SecretSniff/
├── main.py                  # CLI entry point (Rich output)
├── scanner/
│   ├── file_scanner.py      # File/directory scanning (threaded)
│   ├── git_scanner.py       # Git repo + history scanning
│   ├── env_scanner.py       # Env file targeting
│   └── entropy.py           # Shannon entropy calculator
├── patterns/
│   ├── rules.py             # All 50+ regex patterns
│   └── keywords.py          # Context keyword lists
├── allowlist.py             # Allowlist management
├── baseline.py              # Baseline comparison + merge
├── output/
│   ├── sarif.py             # SARIF 2.1.0 format export
│   ├── junit.py             # JUnit XML export
│   └── reporter.py          # PDF report with remediation
├── hooks/
│   └── pre_commit.sh        # Git pre-commit hook
├── database.py              # SQLite operations
├── config/
│   └── default_config.yaml  # Default configuration
├── dashboard/
│   ├── app.py               # Flask web dashboard (port 5800)
│   └── templates/
│       └── index.html       # Full dashboard UI
├── requirements.txt
└── README.md
```

## Dashboard

Launch the web dashboard for visual scan management:

```bash
python main.py dashboard
# Opens at http://127.0.0.1:5800
```

### Dashboard Features:
- **Scan Control**: Input path/repo, enable history scan, set depth
- **Findings Table**: Filterable by severity, searchable, expandable context
- **Charts**: Top triggered rules, most affected files, author leaderboard
- **Allowlist Manager**: Add/remove ignore rules from UI
- **Export**: JSON, CSV, SARIF, JUnit from dashboard

## Remediation Guidance

For each finding, SecretSniff recommends:

1. **Immediate**: Revoke and rotate the exposed key
2. **Short-term**: Move secrets to environment variables
3. **Long-term**: Use a dedicated secrets manager:

| Platform | Recommended Tool |
|----------|-----------------|
| AWS | AWS Secrets Manager / Parameter Store |
| GCP | Secret Manager |
| Azure | Key Vault |
| Multi-cloud | HashiCorp Vault, Doppler, 1Password Secrets |

## False Positive Reduction

SecretSniff reduces false positives through:
- **Placeholder detection**: Skips `your_api_key_here`, `REPLACE_ME`, `xxx`, `00000000`
- **Test file skipping**: Auto-skips `*_test.py`, `*.test.js`, `test_*.py`, `spec_*`
- **Doc file skipping**: Skips `*.md`, `*.rst`, `docs/`
- **Context-aware entropy**: Only flags high-entropy strings near secret keywords
- **Confidence levels**: HIGH for regex matches, LOW for entropy-only matches

## Security Guarantees

- **Secret redaction**: Secret values are NEVER printed or stored in full. Only first 4 + last 4 characters are shown.
- **Offline operation**: No external API calls, no telemetry, no network access required.
- **Local storage**: All scan history stored in local SQLite database.
- **No data exfiltration**: SecretSniff never sends any scanned content to external services.

## Legal Disclaimer

**SecretSniff is for scanning repositories you own or have explicit authorization to audit.**

- Unauthorized access to computer systems is illegal under CFAA, Computer Misuse Act, and similar laws worldwide.
- All scanning is performed locally on your machine.
- If you discover secrets in third-party repositories, follow responsible disclosure practices.
- The authors are not responsible for misuse of this tool.

## License

MIT License - free for personal, educational, and commercial use.
