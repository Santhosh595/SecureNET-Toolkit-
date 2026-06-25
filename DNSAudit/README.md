# DNSAudit - Comprehensive DNS Security Auditor

**Author:** Santhosh L
**License:** MIT

## Overview

DNSAudit performs comprehensive DNS security audits across 12 categories including email authentication (SPF/DKIM/DMARC), DNSSEC validation, zone transfer exposure, subdomain takeover detection, and DNS hijacking indicators. Generates A-F grades with prioritized remediation plans.

## Why DNS Security Matters

DNS is the backbone of internet security. Misconfigured DNS records enable:
- **Email spoofing** - Attackers send emails appearing to come from your domain
- **Phishing attacks** - Fake sites impersonating your domain
- **Credential theft** - Users tricked into entering credentials on spoofed sites
- **Domain hijacking** - Attackers redirect traffic to malicious servers
- **Data exfiltration** - Zone transfers expose entire infrastructure

## Audit Categories (12)

| # | Category | What It Checks | Severity |
|---|----------|---------------|----------|
| 1 | SPF | Record exists, syntax, lookup count, policy | CRITICAL if missing |
| 2 | DKIM | Selectors found, key size, algorithm | CRITICAL if weak |
| 3 | DMARC | Policy, percentage, alignment, maturity | CRITICAL if missing |
| 4 | DNSSEC | Enabled, algorithms, key sizes, signatures | HIGH if disabled |
| 5 | Zone Transfer | AXFR vulnerability per nameserver | CRITICAL if open |
| 6 | Subdomain Takeover | Dangling CNAMEs to 15 cloud services | CRITICAL if confirmed |
| 7 | DNS Hijacking | Multi-resolver comparison, discrepancies | HIGH if detected |
| 8 | Mail Server | MX config, TLS, open relay, PTR records | CRITICAL if open relay |
| 9 | Nameserver | Redundancy, lame delegation, consistency | CRITICAL if lame |
| 10 | CAA | Certificate Authority Authorization | MEDIUM if missing |
| 11 | DNS Inventory | All record types, SOA analysis, anomalies | INFO |
| 12 | DANE/TLSA | Certificate pinning, DNSSEC binding | MEDIUM if missing |

## CLI Usage

```bash
# Basic scan
python main.py example.com

# Custom resolver
python main.py example.com --resolver 8.8.8.8

# Export report
python main.py example.com --output report.json
python main.py example.com --output report.pdf

# Brief output (failures only)
python main.py example.com --brief

# Specific categories only
python main.py example.com --categories "SPF,DKIM,DMARC"

# Bulk scan
python main.py bulk --file domains.txt --output results.json

# Launch dashboard
python main.py dashboard --port 5900
```

## Scoring System

Per category: 0-10 points
- CRITICAL finding: -4 per finding
- HIGH finding: -2 per finding
- MEDIUM finding: -1 per finding

Overall: sum / 120 * 100

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 95-100 | Exemplary DNS security |
| A | 85-94 | Strong configuration |
| B | 70-84 | Good with minor issues |
| C | 50-69 | Needs improvement |
| D | 30-49 | Significant risks |
| F | <30 | Critical vulnerabilities |

Hard caps:
- Zone transfer open = cap at F
- No SPF + No DMARC + No DKIM = cap at D
- Subdomain takeover confirmed = cap at C

## Remediation Examples

### SPF Record
```
v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all
```

### DMARC Record (Progression)
```
# Level 1: Monitor
v=DMARC1; p=none; rua=mailto:dmarc@example.com

# Level 2: Quarantine
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com

# Level 3: Reject (recommended)
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; adkim=s; aspf=s
```

### CAA Record
```
example.com. IN CAA 0 issue "letsencrypt.org"
example.com. IN CAA 0 issuewild "letsencrypt.org"
example.com. IN CAA 0 iodef "mailto:security@example.com"
```

## Legal Disclaimer

**DNSAudit is for auditing domains you own or have explicit authorization to test.**

- All checks are read-only passive queries
- Zone transfer attempts are standard security tests
- Open relay tests abort after RCPT TO (no email sent)
- The authors are not responsible for misuse

## License

MIT License - free for personal, educational, and commercial use.
