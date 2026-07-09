# 🛠️ VulnProbe — Learn Before You Use

Welcome! If you've never used a template-based vulnerability scanner before, this guide walks you through everything you need to know — no technical background required. By the end you'll understand what VulnProbe does, how it works, and how to use it responsibly.

---

## What Is This Tool?

Imagine a **checklist of doors and windows** someone leaves open on a building — an unlocked admin panel, a backup file sitting in the web root, a server that proudly announces its version number. Attackers walk past buildings looking for exactly those.

**VulnProbe automates that walk — but for websites, and it only *looks* (read-only).**

It works like [Nuclei](https://github.com/projectdiscovery/nuclei): you give it a target URL, and it runs a library of **probe templates** — tiny YAML files, each one describing "request this path, and if the response looks like X, that's a finding." It never logs in, never submits forms, never sends a DELETE. Every request is a plain `GET`.

---

## Why Does This Exist?

Before you harden a web app (or test one you're authorized to), you need a fast, repeatable inventory of what is **exposed**:

- An admin or debug panel reachable by anyone on the internet
- A `.env`, backup, or config file left in the web root
- A server banner leaking its exact version (and therefore its known CVEs)
- Missing security headers or weak TLS posture
- Default credentials on a known login path

VulnProbe turns "I wonder if anything is exposed" into a one-command report. **It reports; it does not exploit.** That's a deliberate boundary — see *What This Tool CANNOT Do*.

---

## Who Uses This in Real Life?

| Role | What They Use VulnProbe For |
|------|--------------------------|
| **Penetration Testers** | As the first recon pass on an authorized web target — fast exposure mapping before deeper testing. |
| **Bug Bounty Hunters** | To sweep a target's attack surface for low-hanging exposed panels and files. |
| **Security Auditors** | To evidence "what is publicly reachable" for compliance reports. |
| **Web Developers / DevOps** | To catch leaked backups, debug endpoints, or version banners before shipping. |
| **Blue Teams** | To continuously verify their own perimeter has nothing accidentally exposed. |

---

## How Does It Work?

VulnProbe follows a simple, Nuclei-style process:

1. **You give it a target** — a URL (`https://app.example.com`), a domain, or `@wordlist.txt` of many targets.
2. **It loads probe templates** — 60+ YAML files grouped into 8 categories (exposed panels, sensitive files, version leaks, default creds, misconfigurations, CVEs, API security, SSL/headers).
3. **It resolves the target** — follows redirects to the final host (but refuses to follow an open-redirect *to a different domain*).
4. **For each template, it sends an HTTP request** — a `GET` to a path like `/admin` or `/.env`, subject to a per-host rate limit.
5. **It runs the template's matchers** — checks like *status is 200, AND body contains "Dashboard"*. Six matcher types exist: `status`, `word`, `regex`, `size`, `binary`, `header`. Multiple conditions combine with `AND`/`OR`.
6. **On a match, it records a finding** — severity, URL, matched path, the condition that fired, and any extracted values (e.g. the page `<title>`).
7. **It shows you a report** — a findings table, statistics, and exportable JSON / CSV / PDF with remediation advice.

Under the hood it uses `requests`, a connection pool, and a thread pool — so 60 templates across many targets finish in seconds, while still rate-limiting each host.

---

## Key Terms Explained

| Term | Simple Explanation |
|------|-------------------|
| **Template** | A YAML file describing one check: which path to request and what response counts as a finding. Like a single line in a security checklist. |
| **Probe** | Running a template against a target — sending the request and evaluating matchers. |
| **Matcher** | A rule that decides "is this a finding?" Examples: status code equals 200, body contains a word, response size in a range. |
| **Severity** | How bad a finding is: `critical` → `high` → `medium` → `low` → `info`. |
| **Read-only** | VulnProbe only sends safe `GET` requests. It never mutates state on the target. |
| **Rate limit** | A cap on how many requests per minute go to one host, so you don't flood or DoS it. |
| **Open redirect protection** | VulnProbe won't chase a redirect that bounces you to a *different* domain — that could leak your scan to a third party. |
| **Extractor** | A rule that pulls a value out of a matched response (e.g. a version string or CSRF token) for the report. |

---

## What Does the Output Mean?

After a scan you get a findings table:

| Column | What It Means |
|--------|---------------|
| **Severity** | How serious (critical/high/medium/low/info). |
| **Template** | Which probe triggered (e.g. `exposed-admin-panel`). |
| **URL** | The host that was scanned. |
| **Path** | The exact request path that matched (`/admin`). |
| **HTTP** | The response status code. |
| **Matched** | Which matcher condition fired (`status == 200 AND word contains "Dashboard"`). |

### Severity Levels

| Severity | Meaning |
|----------|---------|
| **critical** | Immediate, high-impact exposure (e.g. an exposed `.env` with secrets, a publicly reachable admin console). |
| **high** | Serious exposure that should be locked down promptly (e.g. default-cred login page, known CVE endpoint). |
| **medium** | Useful recon signal or weak configuration (e.g. version banner leak, missing security header). |
| **low** | Minor info disclosure or hygiene issue. |
| **info** | Context only — not a vulnerability by itself. |

---

## Real Example Walkthrough

Say you're auditing `https://shop.example.com` (a site you own or have written permission to test).

**Step 1 — Run the scan**

```bash
python main.py https://shop.example.com --severity high,critical
```

**Step 2 — Watch findings stream in**

```text
[progress] 42/60 templates · 3 found
[HIGH] exposed-git-config        https://shop.example.com/.git/config
[HIGH] exposed-admin-panel        https://shop.example.com/admin
```

**Step 3 — Read the report**

| Severity | Template | Path | HTTP | Matched |
|----------|----------|------|------|---------|
| HIGH | exposed-git-config | `/.git/config` | 200 | status AND word "gitdir" |
| HIGH | exposed-admin-panel | `/admin` | 200 | status AND word "Dashboard" |

**Step 4 — Take action**

- The `/.git/config` exposure means the entire source history may be downloadable — remove `.git` from the web root and rotate any secrets it contained.
- The `/admin` panel is world-reachable — put it behind a VPN or IP allowlist and enforce MFA.

**The site is now significantly more secure** — VulnProbe showed you two doors you didn't know were open.

---

## What This Tool CANNOT Do

VulnProbe is useful, but understand its limits:

- ❌ **Cannot exploit** — it only detects. It won't log in, run a payload, or prove a vulnerability is exploitable.
- ❌ **Cannot authenticate** — it scans as an unauthenticated visitor; authenticated-only exposure isn't covered.
- ❌ **Cannot find everything** — only what its templates look for. A missing template means a missed finding.
- ❌ **Cannot guarantee zero false positives** — a `word` matcher can match benign content. Always verify a finding manually.
- ❌ **Cannot bypass rate limits / WAFs** — it respects your configured rate limit and won't hammer a host.
- ❌ **Does not follow cross-domain redirects** — by design, to avoid leaking your scan.

---

## ⚠️ Cautions and Warnings

> **CRITICAL: Scanning a system you do not own or lack written permission to test is ILLEGAL** in most jurisdictions, including under the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and the Information Technology Act, 2000 (India). Unauthorized scanning is frequently treated as an attempted intrusion.

### Golden Rules of Ethical Scanning

1. **Only scan systems you own or have explicit written permission to scan.**
2. **Get it in writing** — an email from the owner saying "you may scan this" protects you.
3. **Respect scope** — stick to the hosts, paths, and rates you agreed on.
4. **Use a low rate limit** — the default 150 req/min per host is conservative; lower it for fragile targets.
5. **Practice on your own lab** — stand up a local vulnerable app (OWASP Juice Shop, DVWA) to learn safely.

---

## 🎓 Learning Path

### Beginner
1. Read this document end to end.
2. Run a scan against a local mock or your own site — watch the findings stream.
3. Open a few templates in `VulnProbe/templates/` to see how `matchers` are written.

### Intermediate
4. Learn HTTP fundamentals — requests, responses, status codes, headers (MDN Web Docs).
5. Study the six matcher types and write your own template (see `TEMPLATES.md`).
6. Compare VulnProbe output to [Nuclei](https://github.com/projectdiscovery/nuclei) on the same target.

### Advanced
7. Understand rate limiting, connection pooling, and open-redirect risks.
8. Build a custom template set for your org's common misconfigurations.
9. Pipe JSON output into your SIEM or a continuous scanning pipeline.

---

## 📚 Further Reading

### Tools & References
- [Nuclei by ProjectDiscovery](https://github.com/projectdiscovery/nuclei) — the engine VulnProbe's template model is inspired by.
- [Nuclei Template Documentation](https://docs.projectdiscovery.io/templates) — the original template schema.
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — methodology for authorized testing.

### Learning
- [MDN: HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP) — how requests and responses work.
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — the most critical web risks.
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — a legal, intentionally vulnerable app to practice on.

### Practice Environments
- [HackTheBox](https://www.hackthebox.com/) — legal penetration-testing labs.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — free web security training.

---

*Remember: VulnProbe only looks — it never touches. Stay authorized, stay rate-limited, and stay ethical.* 🛡️
