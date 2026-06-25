# 🛠️ SubProbe — Learn Before You Use

## What Is This Tool? (The Simple Version)

Imagine a company has a main office (example.com) but also has
other buildings you don't know about: mail.example.com,
admin.example.com, dev.example.com. SubProbe finds all those
hidden buildings.

It searches for subdomains [smaller addresses that belong to
a main address] of any domain using three different methods:
wordlist brute-force, certificate records, and DNS analysis.

## Why Does This Exist? (The Problem It Solves)

Companies often forget about old subdomains. A staging server
that was set up years ago might still be running with default
passwords. An old subdomain pointing to a deleted cloud service
can be taken over by attackers.

SubProbe finds these forgotten entry points before hackers do.

## Who Uses This in Real Life?

- Penetration testers [people paid to find security holes
  before hackers do]
- Bug bounty hunters [people who earn money by finding and
  reporting security issues]
- Security engineers doing asset discovery
- Red teamers [attackers hired to test defenses]

## How Does It Work? (Step by Step, Plain English)

1. You give it a domain name (like example.com)
2. It tries common subdomain names from a built-in list
   (www, mail, admin, api, dev, staging, etc.)
3. For each guess, it asks DNS [the internet's phone book]
   if that subdomain exists
4. It also checks certificate transparency logs [public
   records of every SSL certificate ever issued]
5. It queries DNS records directly for any hostnames
   hiding in MX, NS, or TXT records
6. It checks if found subdomains are alive (responding
   to HTTP requests)
7. It flags "interesting" ones (those returning 403 or
   200 status codes)
8. It shows you a clean report of everything found

## Key Terms Explained (Glossary)

**Subdomain** — a smaller address that belongs to a main
address. Like "mail.google.com" is a subdomain of "google.com".

**DNS** — the internet's phone book. It translates domain
names (google.com) into IP addresses (142.250.80.46).

**CNAME** — a DNS record that points one domain to another.
Like a forwarding address.

**A Record** — a DNS record that points a domain directly
to an IP address.

**Certificate Transparency** — public logs of every SSL
certificate ever issued. Like a public record of every
lock installed on every door.

**Wordlist** — a file containing thousands of common words
used to guess subdomains. Like trying common passwords.

**Wildcard DNS** — when a domain catches ALL subdomain
queries (even random ones). This can hide real subdomains.

**HTTP Status Code** — a number a web server sends back.
200 means "found", 404 means "not found", 403 means
"exists but forbidden".

## What Does the Output Mean?

| Result | What It Means | What To Do |
|--------|---------------|------------|
| LIVE | Subdomain is active and responding | Check if it should be public |
| DEAD | Subdomain exists in DNS but not responding | Probably safe, just inactive |
| REDIRECT | Subdomain forwards elsewhere | Verify the redirect target is safe |
| INTERESTING | Returns 200 or 403 (exists but protected) | Investigate — could be admin panel |
| FILTERED | Port is behind a firewall | Normal for secure services |

## Real Example Walkthrough

Let's say you run: `python main.py example.com`

The tool will:
1. Try 500+ common subdomains against example.com
2. Find that "www.example.com" resolves to 93.184.216.34
3. Find "mail.example.com" with a CNAME record
4. Check certificate logs and find "api.example.com"
5. Test each found subdomain with HTTP requests
6. Show you a table like:

```
Subdomain              IP              Status    Source
www.example.com        93.184.216.34   LIVE      WORDLIST
mail.example.com       —               LIVE      DNS_RECORD
api.example.com        104.16.85.20    LIVE      CT_LOG
dev.example.com        —               DEAD      WORDLIST
admin.example.com      104.16.86.20    INTERESTING  WORDLIST
```

The "INTERESTING" flag on admin.example.com tells you:
"This exists but is protected. Worth checking if it
should be publicly reachable at all."

## What This Tool CANNOT Do (Limitations)

- It cannot find subdomains with no public DNS record
- It may miss subdomains with unusual names not in
  its wordlist
- It cannot scan websites you don't have permission
  to scan
- It does not tell you what is inside the subdomains,
  only that they exist
- Wildcard DNS configurations can produce false
  positives

## ⚠️ Cautions and Warnings

### Before You Use This Tool:
- You must only use this on domains you OWN or have
  WRITTEN PERMISSION to test
- Ask yourself: "Would I be okay if someone did
  this to my own domain?"
- When in doubt, don't run the scan

### What Can Go Wrong:
- Scanning someone else's domain without permission
  may be considered unauthorized access
- Your IP might be logged and blocked by the target
- Aggressive scanning could trigger rate limiting
  or DDoS protection

### Legal Warning:
Using this tool on domains without permission may violate:
- India: IT Act 2000, Section 43 and 66
  (unauthorized access, up to 3 years imprisonment)
- USA: Computer Fraud and Abuse Act (CFAA)
- And equivalent laws in your country

The fact that a tool is free and open source does NOT
make it legal to use anywhere you want. A lockpick is
a legal tool. Using it on someone else's lock is not.

## 🎓 Learning Path (What to Learn Next)

- **DNS fundamentals** — understand how A, CNAME, MX,
  NS records work and why they matter
- **SSL/TLS certificates** — learn how certificate
  transparency logs work
- **Web application security** — understand what
  those discovered subdomains might contain
- **OSINT techniques** — learn other ways attackers
  map out an organization's infrastructure

## 📚 Further Reading

- [OWASP Subdomain Takeover Guide](https://owasp.org/www-project-web-security-testing-guide/latest/)
- [PortSwigger Web Academy](https://portswigger.net/web-security) — free
- [TryHackMe: Passive Recon](https://tryhackme.com) — free room
- [Wikipedia: DNS](https://en.wikipedia.org/wiki/Domain_Name_System)
