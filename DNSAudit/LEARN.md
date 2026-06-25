# 🛠️ DNSAudit — Learn Before You Use

## What Is This Tool? (The Simple Version)

Your domain is like your home address. DNS records are
the instructions that tell the internet how to find you
and who is allowed to send mail on your behalf. DNSAudit
checks if those instructions are correct and safe — or
if someone could impersonate you.

It audits any domain across 12 security categories and
gives you an A-F grade with a remediation plan.

## Why Does This Exist? (The Problem It Solves)

Without proper DNS security:
- Anyone can send emails appearing to come from your
  domain (email spoofing)
- Attackers can redirect your traffic to malicious
  sites (DNS hijacking)
- Your domain can be taken over via forgotten
  subdomains
- Phishing attacks become trivial

DNSAudit finds all these issues before attackers exploit
them.

## Who Uses This in Real Life?

- Security engineers auditing domain infrastructure
- Penetration testers [people paid to find security
  holes before hackers do]
- System administrators hardening their domains
- Compliance auditors checking email security

## How Does It Work? (Step by Step, Plain English)

1. You give it a domain name (like example.com)
2. It runs 12 audit categories:
   - SPF: checks if your email sender policy exists
     and is properly configured
   - DKIM: checks if your email signing keys are
     strong and valid
   - DMARC: checks if your email enforcement policy
     is active and strict
   - DNSSEC: checks if your DNS records are
     cryptographically signed
   - Zone Transfer: tests if your DNS zone can be
     downloaded by anyone (bad)
   - Subdomain Takeover: checks if forgotten
   subdomains point to unclaimed services
   - DNS Hijacking: compares results across multiple
     resolvers to detect tampering
   - Mail Server: checks if your email servers are
     properly configured and secure
   - Nameserver: checks if your DNS servers are
     redundant and properly configured
   - CAA: checks which certificate authorities are
     allowed to issue certs for your domain
   - DNS Inventory: catalogs all your DNS records
     and flags anomalies
   - DANE/TLSA: checks if your TLS certificates
     are pinned to DNSSEC
3. It calculates a score per category (0-10)
4. It assigns an overall grade (A+ to F)
5. It generates a prioritized remediation plan

## Key Terms Explained (Glossary)

**DNS** — the internet's phone book. Translates domain
names (google.com) into IP addresses (142.250.80.46).

**SPF** — Sender Policy Framework. A DNS record that
says which servers are allowed to send email for your
domain. Like a guest list for a party.

**DKIM** — DomainKeys Identified Mail. A way to sign
emails so recipients know they really came from you.
Like a wax seal on a letter.

**DMARC** — Domain-based Message Authentication. Tells
receiving servers what to do with emails that fail
SPF/DKIM checks. Like a bouncer enforcing the guest list.

**DNSSEC** — DNS Security Extensions. Cryptographically
signs DNS records so they can't be tampered with. Like
a notarized document.

**Zone Transfer** — when one DNS server copies its
records from another. If open to anyone, attackers
can map your entire infrastructure.

**Subdomain Takeover** — when a subdomain points to
a cloud service that no longer exists. An attacker
can claim that service and take over the subdomain.

**MX Record** — tells the internet where to deliver
email for your domain. Like a mail forwarding address.

**Nameserver** — the server that holds your DNS records.
Like the office that maintains the phone book.

**CAA Record** — says which Certificate Authorities
are allowed to issue SSL certificates for your domain.
Like a list of approved passport offices.

## What Does the Output Mean?

| Result | What It Means | What To Do |
|--------|---------------|------------|
| CRITICAL | Severe vulnerability | Fix right now |
| HIGH | Significant risk | Fix this week |
| MEDIUM | Needs improvement | Plan the fix |
| LOW | Minor issue | Fix when convenient |
| GOOD | Properly configured | Nothing needed |

## Real Example Walkthrough

You run: `python main.py example.com`

DNSAudit finds:

```
SPF:    Score 6/10  — SPF exists but uses ~all (softfail)
DKIM:   Score 8/10  — DKIM found with 2048-bit key
DMARC:  Score 4/10  — DMARC exists but p=none (monitoring only)
DNSSEC: Score 0/10  — DNSSEC not enabled
Zone:   Score 10/10 — Zone transfer properly blocked
...

Overall Grade: C (58/120)

Top 3 Fixes:
1. Enable DNSSEC at your registrar
2. Change DMARC policy from p=none to p=reject
3. Change SPF from ~all to -all
```

## What This Tool CANNOT Do (Limitations)

- It cannot fix DNS misconfigurations — changes must
  be made at your domain registrar
- It tests from your location, not globally
- Some checks require the domain to be publicly
  resolvable
- It cannot detect issues on private/internal domains

## ⚠️ Cautions and Warnings

### Before You Use This Tool:
- Only audit domains you own or have written permission
  to test
- The zone transfer test sends a request to the target
  nameserver (standard security test, but be aware)

### What Can Go Wrong:
- Zone transfer attempts may be logged by the target
- Multiple resolver queries may trigger rate limits
- Scanning without authorization may violate policies

### Legal Warning:
Using this tool on systems without permission may violate:
- India: IT Act 2000, Section 43 and 66
- USA: Computer Fraud and Abuse Act (CFAA)
- And equivalent laws in your country

## 🎓 Learning Path (What to Learn Next)

- **Email security** — understand how SPF, DKIM, and
  DMARC work together to prevent spoofing
- **DNSSEC deployment** — learn how to enable DNSSEC
  at common registrars
- **DNS infrastructure** — understand how authoritative
  and recursive DNS work
- **Cloud security** — learn about subdomain takeover
  prevention and DNS monitoring

## 📚 Further Reading

- [OWASP DNS Security](https://owasp.org/www-project-web-security-testing-guide/)
- [DMARC.org](https://dmarc.org/) — official DMARC resource
- [MXToolbox](https://mxtoolbox.com/) — free DNS checking
- [Wikipedia: DNSSEC](https://en.wikipedia.org/wiki/DNSSEC)
