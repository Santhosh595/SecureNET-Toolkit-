# 🛠️ SecretSniff — Learn Before You Use

## What Is This Tool? (The Simple Version)

Imagine you wrote your bank PIN on a sticky note and
accidentally emailed a photo of your desk to 1000 people.
SecretSniff finds those sticky notes in your code before
you publish it.

It scans codebases, git history, and environment files
for 50+ types of hardcoded secrets like API keys, tokens,
and passwords.

## Why Does This Exist? (The Problem It Solves)

Developers accidentally commit secrets to code repositories
all the time. An AWS key in a public GitHub repo can be
found by attackers within minutes. The result: massive
cloud bills, data breaches, or complete infrastructure
takeover.

SecretSniff catches these mistakes before they reach
version control or after they've been committed.

## Who Uses This in Real Life?

- DevOps engineers protecting CI/CD pipelines
- Security teams auditing code repositories
- Developers running pre-commit checks
- Compliance officers ensuring no secrets in code

## How Does It Work? (Step by Step, Plain English)

1. You point it at a directory, file, or git repository
2. It recursively scans all files (skipping binaries)
3. For each file, it checks against 50+ regex patterns
   [text matching rules] for known secret formats:
   - AWS Access Keys (start with AKIA...)
   - GitHub Tokens (start with ghp_...)
   - Stripe Keys (start with sk_live_...)
   - OpenAI Keys (start with sk-...)
   - Database connection strings with passwords
   - Private keys (RSA, EC, PGP, SSH)
   - And 45 more patterns
4. It also uses entropy analysis [measuring how
   random a string is] to find unknown secret formats
5. It can scan git history to find secrets that were
   committed and then "deleted" (but still in history)
6. It redacts found secrets in output (shows only
   first 4 and last 4 characters)
7. It generates a report with file, line number,
   rule matched, and severity

## Key Terms Explained (Glossary)

**API Key** — a password for programs (not people) to
access services. Like a backstage pass for software.

**Secret** — any credential that should be kept private.
Passwords, tokens, keys, certificates.

**Hardcoded** — written directly in source code instead
of being loaded from a safe location. Like writing your
password on a post-it note on your monitor.

**Git History** — every change ever made to a repository.
Even "deleted" code is still in history. Like trying to
erase something written in pen.

**Entropy** — a measure of randomness. Secrets look
random. "password123" has low entropy.
"xJ9kLm2pQ8vR4wN" has high entropy.

**Regex** — pattern matching for text. Like a very
specific search that finds patterns, not exact words.

**Environment Variable** — a setting stored outside
code. The proper way to store secrets. Like keeping
your password in a locked drawer instead of on your desk.

**Secrets Manager** — a dedicated service for storing
secrets (AWS Secrets Manager, HashiVault, Doppler).
Like a bank vault for credentials.

## What Does the Output Mean?

| Result | What It Means | What To Do |
|--------|---------------|------------|
| CRITICAL | Production secret exposed | Revoke immediately |
| HIGH | Real secret found | Rotate the credential |
| MEDIUM | Possible secret | Verify and remove if real |
| LOW | Looks like a secret | Review, probably safe |

## Real Example Walkthrough

You run: `python main.py scan --path ./myproject`

SecretSniff finds:

```
CRITICAL: AWS Access Key ID @ src/config.py:12
  AKIAIOSFODNN7EXAMPLE
  Redacted: AKIA****EXAMPLE

HIGH: GitHub Token @ .env:3
  ghp_xxxxxxxxxxxx
  Redacted: ghp_****xxxx

MEDIUM: High Entropy String @ tests/test_api.py:45
  "sk_test_1234567890abcdef"
  Redacted: sk_t****cdef
```

The CRITICAL finding means your AWS key is in source
code. You must revoke it in AWS IAM console immediately,
even if the code was never committed.

## What This Tool CANNOT Do (Limitations)

- It may produce false positives on test/example code
- It cannot detect secrets protected by custom
  obfuscation
- It cannot scan private repositories you don't have
  access to
- It cannot revoke secrets automatically

## ⚠️ Cautions and Warnings

### Before You Use This Tool:
- Only scan repositories you own or have permission
- If SecretSniff finds real secrets: REVOKE THEM
  IMMEDIATELY even if the code was never public
- Git history is permanent — "deleting" a commit
  doesn't remove it from history

### What Can Go Wrong:
- Real secrets found in output should be treated as
  compromised
- Scanning without authorization may violate policies
- False positives may waste investigation time

### Legal Warning:
Using this tool on systems without permission may violate:
- India: IT Act 2000, Section 43 and 66
- USA: Computer Fraud and Abuse Act (CFAA)
- And equivalent laws in your country

## 🎓 Learning Path (What to Learn Next)

- **Git secrets management** — learn git-secrets,
  pre-commit hooks, and .gitignore best practices
- **Secrets managers** — learn AWS Secrets Manager,
  HashiCorp Vault, Doppler, 1Password Secrets
- **Secure coding practices** — understand how to
  handle credentials in applications
- **Incident response** — what to do when secrets
  are leaked

## 📚 Further Reading

- [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [TryHackMe: Secret Key](https://tryhackme.com) — free rooms
- [Wikipedia: Credential Stuffing](https://en.wikipedia.org/wiki/Credential_stuffing)
