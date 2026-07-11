# 🛡️ CloudSentry — Learn Before You Use

Welcome! If you've never run a multi-cloud security posture auditor before, this guide walks you through everything you need to know — no cloud-security background required.

## What Is This Tool?

**CloudSentry** checks the security configuration of your **AWS, GCP, and Azure** accounts — the way a security auditor would, by reading settings rather than attacking anything. It looks for misconfigurations like public storage buckets, missing MFA, open firewall rules, and disabled logging.

Think of it like a **safety inspection for your cloud accounts** — it tells you where the "locks are left open," without ever touching your data or making changes.

## How Does It Work? (the simple version)

CloudSentry runs **60+ read-only checks** across three providers:

| Provider | Checks | Example checks |
|----------|--------|----------------|
| **AWS** | 25 | Root MFA, public S3 buckets, open security groups |
| **GCP** | 20 | All-users bucket access, disabled audit logs, public SQL |
| **Azure** | 15 | Public storage blobs, internet-exposed SSH/RDP, missing MFA |

Each check asks a yes/no question about your configuration and reports **PASS**, **FAIL**, **INFO**, **ERROR**, or **TIMEOUT**.

## The Two Modes (this is the important part)

### INFO Mode (default, no credentials)
If CloudSentry can't find your cloud credentials, it **does not error and does not ask you for anything**. Instead it lists every check, explains what it looks for, and tells you how to verify it manually. This is perfect for learning what good cloud hygiene looks like.

### Live Mode (with credentials)
When credentials are present, CloudSentry makes **safe, read-only API calls** (like "list my buckets and their ACLs") and tells you exactly which resources are misconfigured.

## Key Terms

| Term | Meaning |
|------|---------|
| **IAM** | Identity & Access Management — who can do what |
| **CIS Benchmark** | A well-known checklist of secure cloud configuration |
| **OWASP Cloud Top 10** | Top 10 cloud security risk categories |
| **Severity** | How bad a finding is: critical → high → medium → low → info |
| **Public ACL** | A permission that lets *anyone on the internet* access a resource |
| **MFA** | Multi-Factor Authentication (a second login step) |

## Real Example

```
[AWS-S3-001] No S3 buckets with public read ACL    FAIL ✗
  └─ Affected: my-company-data, old-backups-2019
[AWS-IAM-001] Root account MFA enabled              FAIL ✗
```

This tells you two real risks: two buckets are world-readable, and your root account lacks MFA. Each finding includes an **exact CLI command to fix it**.

## What CloudSentry CANNOT Do

- It **never changes** your cloud resources (read-only by design).
- It **never stores or logs** your credentials.
- Without credentials it only **shows you what to check** — it can't see your actual config.
- It doesn't fix things for you — it gives you the remediation command.

## ⚠️ Cautions

- Only audit accounts you are **authorized** to assess.
- Live mode performs real API calls that may be **rate-limited** by your cloud provider (CloudSentry backs off automatically).
- A **PASS** means the config looked good at scan time; configurations change — re-audit regularly.

## 🎓 Learning Path

1. Run `python main.py --info` to see all 60 checks with explanations.
2. Read the findings for one provider (start with AWS).
3. Set up read-only credentials for one provider and run a live audit.
4. Work through the **CRITICAL** and **HIGH** findings first.
5. Re-run after fixing to watch your compliance score improve.

## 📚 Further Reading

- CIS AWS Foundations Benchmark
- CIS GCP Benchmark
- CIS Microsoft Azure Foundations Benchmark
- OWASP Cloud Security Top 10
- AWS / GCP / Azure Well-Architected Security Pillars
