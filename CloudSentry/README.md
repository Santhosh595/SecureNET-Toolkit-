# CloudSentry — Multi-Cloud Security Posture (Prowler/ScoutSuite-style)

**Author:** Santhosh L
**License:** MIT
**Maps to trending tools:** [Prowler](https://github.com/prowler-cloud/prowler) / [ScoutSuite](https://github.com/nccgroup/ScoutSuite)

## Overview

CloudSentry performs **read-only** security posture checks across AWS, GCP, and Azure — the
Python-native, SecureNET-styled answer to **Prowler** and **ScoutSuite**. When cloud credentials
are present in the environment it executes safe read-only API calls (e.g. S3 public-access block,
IAM root MFA, root access keys). Without credentials it reports `INFO` with guidance, so the tool
is always runnable and never mutates cloud state.

## Checks

| ID | Provider | Check | Severity |
|----|----------|-------|----------|
| AWS-001 | AWS | S3 buckets not public | high |
| AWS-002 | AWS | IAM root account MFA enabled | critical |
| AWS-003 | AWS | No IAM access keys for root | high |
| GCP-001 | GCP | Default service account not used by compute | medium |
| AZ-001  | Azure | Storage accounts HTTPS-only | medium |

## CLI Usage

```bash
# Run all providers
python main.py

# Run only AWS checks
python main.py --provider aws

# Run AWS + GCP
python main.py --provider aws --provider gcp
```

## Credentials (optional, read-only)

```bash
export AWS_ACCESS_KEY_ID=...      AWS_SECRET_ACCESS_KEY=...      # AWS
export GOOGLE_APPLICATION_CREDENTIALS=/path.json                 # GCP
export AZURE_SUBSCRIPTION_ID=...                                 # Azure
```

## Web Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5015
```

## Project Structure

```
CloudSentry/
├── main.py            # CLI entry point (Rich tables)
├── engine.py          # Check registry + read-only cloud checks
├── database.py        # SQLite persistence
├── dashboard.py       # Flask web dashboard
├── requirements.txt
└── README.md
```

## Legal Disclaimer

**CloudSentry is read-only and for authorized use on infrastructure you own or manage.**
The author assumes no liability for misuse.

## License

MIT License — free for personal, educational, and commercial use.
