# 🛠️ TLScan — Learn Before You Use

## What Is This Tool? (The Simple Version)

When you visit a website with a padlock in your browser,
TLScan is the engineer who checks if that padlock is
actually strong enough or if it's a cheap one that anyone
could break.

It tests SSL/TLS [the technology that creates the secure
connection between you and a website] across protocols,
ciphers, certificates, and known vulnerabilities.

## Why Does This Exist? (The Problem It Solves)

Many websites have outdated or misconfigured SSL/TLS.
Some still support protocols from the 1990s that are
known to be broken. Others have expired certificates
or use weak encryption.

TLScan finds these issues and grades the configuration
from A+ to F, just like SSL Labs does.

## Who Uses This in Real Life?

- Security engineers auditing web server configurations
- System administrators hardening their servers
- Penetration testers [people paid to find security
  holes before hackers do]
- Compliance auditors checking PCI-DSS requirements

## How Does It Work? (Step by Step, Plain English)

1. You give it a domain name (like example.com)
2. It connects to the server on port 443 [the standard
   port for secure web traffic]
3. It tests which protocol versions the server supports
   (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
4. It enumerates all cipher suites [the specific
   encryption methods the server accepts]
5. It extracts and analyzes the SSL certificate
   (who issued it, when it expires, what domains
   it covers)
6. It checks for 10 known CVEs [publicly known
   security vulnerabilities]:
   - POODLE (SSLv3 + CBC)
   - BEAST (TLS 1.0 + CBC)
   - CRIME (TLS compression)
   - BREACH (HTTP compression)
   - Heartbleed (OpenSSL bug)
   - ROBOT (RSA oracle)
   - SWEET32 (3DES ciphers)
   - DROWN (SSLv2)
   - Logjam (weak DH params)
   - Certificate pinning issues
7. It calculates a score and assigns a grade
8. It shows you a prioritized remediation plan

## Key Terms Explained (Glossary)

**SSL/TLS** — the technology that encrypts traffic
between your browser and a website. Like a sealed
envelope for your data.

**Certificate** — a digital document that proves a
website is who it claims to be. Like a passport.

**Cipher Suite** — a combination of encryption
algorithms used for one connection. Like choosing
which lock, key, and seal to use together.

**Protocol Version** — which version of SSL/TLS
is being used. Newer is better. TLS 1.3 is current.

**CVE** — Common Vulnerabilities and Exposures.
A public list of known security flaws. Each gets
a unique number.

**Forward Secrecy** — even if the server's private
key is stolen later, past traffic stays encrypted.
Like changing locks after every guest leaves.

**Certificate Chain** — the path from your website's
certificate up to a trusted root certificate authority.
Like a chain of trust: your manager trusts you, their
manager trusts them, up to the CEO.

**CA** — Certificate Authority. A trusted organization
that issues SSL certificates. Like a passport office.

## What Does the Output Mean?

| Result | What It Means | What To Do |
|--------|---------------|------------|
| SECURE | Configuration is strong | Nothing, great job |
| GOOD | Minor issues only | Review recommendations |
| MODERATE | Some real weaknesses | Plan upgrades soon |
| WEAK | Significant problems | Fix immediately |
| CRITICAL | Severe vulnerabilities | Fix right now |

## Real Example Walkthrough

You run: `python main.py example.com`

TLScan connects and finds:
- Supports TLS 1.2 and TLS 1.3 (good)
- Certificate valid until 2025-01-15 (good)
- No SSLv3 or TLS 1.0 (good)
- Forward secrecy supported (good)
- Grade: A

But for an old server you might find:
- Supports SSLv3 (CRITICAL — POODLE vulnerable)
- Certificate expired 30 days ago (CRITICAL)
- No forward secrecy (HIGH)
- Grade: F

## What This Tool CANNOT Do (Limitations)

- It cannot fix the issues it finds — that's up to
  the server administrator
- It tests from your location, not globally
- It cannot detect issues behind CDNs or load balancers
- Some checks require actual network connections

## ⚠️ Cautions and Warnings

### Before You Use This Tool:
- Only scan domains you own or have written permission
  to audit
- Some aggressive scans may trigger security alerts
  on the target

### What Can Go Wrong:
- Scanning without permission may be seen as hostile
- Your IP may be logged or blocked
- Some tests send malformed packets that could crash
  very old servers

### Legal Warning:
Using this tool on systems without permission may violate:
- India: IT Act 2000, Section 43 and 66
- USA: Computer Fraud and Abuse Act (CFAA)
- And equivalent laws in your country

## 🎓 Learning Path (What to Learn Next)

- **SSL/TLS handshake** — understand exactly how the
  secure connection is established
- **Certificate management** — learn how to properly
  obtain, install, and renew certificates
- **Web server hardening** — learn to configure Apache,
  Nginx, and other servers securely
- **HSTS and certificate pinning** — advanced browser-side
  protections

## 📚 Further Reading

- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/) — the gold standard
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Mozilla SSL Configuration](https://ssl-config.mozilla.org/) — recommended configs
- [Wikipedia: TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)
