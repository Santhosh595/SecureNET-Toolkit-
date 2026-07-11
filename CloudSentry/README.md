# CloudSentry — Multi-Cloud Security Posture Auditor

> Prowler / ScoutSuite-style read-only configuration auditing for AWS, GCP, and Azure.

CloudSentry performs **60+ read-only security checks** across IAM, storage,
network, logging, and database configurations, maps findings to **CIS
Benchmarks** and the **OWASP Cloud Top 10**, and generates exact CLI
remediation commands. It is **safe by design**: with no credentials it runs
in INFO mode and never prompts, errors, or stores secrets.

## Features

- **60+ checks**: 25 AWS, 20 GCP, 15 Azure — all read-only.
- **INFO mode**: works without credentials; lists every check with manual-verification steps and credential-setup guidance.
- **CIS Benchmark + OWASP Cloud Top 10 mapping** with per-provider pass percentages.
- **Exact CLI remediation** for every failing finding.
- **Multi-cloud combined audit** with compliance scoring.
- **CLI + Flask dashboard (7 tabs) + PDF remediation report**.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# INFO mode — no credentials needed (lists all checks)
python main.py --info

# Audit all providers (uses detected credentials; INFO for the rest)
python main.py

# Audit a single provider
python main.py --provider aws
python main.py --provider aws --profile default --region us-east-1
python main.py --provider gcp --project my-project
python main.py --provider azure --subscription <SUB_ID>

# Export a report
python main.py --output report.json
python main.py --output report.pdf
```

## Web dashboard

```bash
python dashboard.py      # http://127.0.0.1:5015
```

Tabs: **Audit · Posture Overview · Findings · Compliance · Resources · History · Report**.

`GET /status` returns:

```json
{"tool":"CloudSentry","status":"running","port":5015,
 "providers_available":["aws","gcp"],"active_audit":false}
```

## Credential handling (safe by design)

| Provider | Detection order |
|----------|----------------|
| **AWS** | `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` → `~/.aws/credentials` → `~/.aws/config` → EC2 instance metadata |
| **GCP** | `GOOGLE_APPLICATION_CREDENTIALS` → `gcloud auth application-default login` |
| **Azure** | `AZURE_*` env vars → `az login` token |

If no credentials are found for a provider, that provider's checks run in
**INFO mode** — no error, no prompt. Credentials are never stored in SQLite
or logged.

## Required (read-only) permissions

CloudSentry requests only read-only IAM permissions. Minimal policies:

- **AWS**: `iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `iam:ListUsers`,
  `iam:ListMFADevices`, `iam:ListAccessKeys`, `s3:ListBuckets`, `s3:GetBucketAcl`,
  `s3:GetBucketEncryption`, `s3:GetPublicAccessBlock`, `cloudtrail:DescribeTrails`,
  `ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs`, `ec2:DescribeFlowLogs`,
  `rds:DescribeDBInstances`, `sts:GetCallerIdentity`.
- **GCP**: `roles/viewer` (or narrower `cloudasset.assets.searchAllIamPolicies`,
  `storage.buckets.getIamPolicy`, `compute.instances.list`, `logging.logs.list`).
- **Azure**: `Reader` on the subscription (plus `Microsoft.Authorization/*/read`
  for role assignments).

## Compliance mapping

Every check maps to a CIS control (`CIS AWS 1.4`, etc.) and an OWASP Cloud
Top 10 category (`OC2 (Asset Management)`, etc.). The dashboard shows pass
percentages per benchmark and how many of the 10 OWASP categories are clear.

## Output

Per check: `check_id, name, provider, category, status, severity, affected
resources, description, risk, remediation, cis_ref, owasp_ref`. SQLite stores
`audits`, `findings`, and `resources` tables; export to JSON/CSV/PDF.

## Disclaimer

> CloudSentry uses read-only API calls only. Ensure you have authorization to
> audit the cloud accounts being assessed.

## Important limits

- All cloud SDKs are optional; missing SDKs trigger INFO mode automatically.
- Rate limiting: AWS `ThrottlingException` triggers an exponential backoff.
- Per-check timeout: a check taking > 30s is skipped with `TIMEOUT` status.
- `--all-regions` scans every AWS region (slower, more complete).
