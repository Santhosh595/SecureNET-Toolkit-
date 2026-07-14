# 🛡️ APIGuard — Learn Before You Use

Welcome! If you've never tested an API for security vulnerabilities before, this guide walks you through everything you need to know — no security background required. By the end you'll understand what API security testing is, how APIGuard works, and how to use it responsibly.

---

## What Is This Tool?

Imagine you run a website with an API that powers your mobile app. Behind that API are **objects** (users, orders, invoices), **authentication** (who gets in), **authorization** (what they can do), and a dozen other moving parts that can leak data if misconfigured.

**APIGuard automates the process of checking for the OWASP API Security Top 10** — the ten most critical API vulnerabilities published by OWASP. It sends carefully crafted requests to your API endpoints and reports back on what it finds, never modifying any data unless you explicitly opt in.

---

## Why Does This Exist?

APIs are everywhere — every mobile app, every single-page application, every IoT device talks to an API. And unlike traditional web apps, APIs are designed to be called by machines, which means:

- **Attackers automate against them.** A single BOLA (API1) vulnerability can let an attacker read every user's private data by enumerating IDs.
- **Authentication is notoriously hard to get right.** A missing token check on one endpoint leaks everything.
- **Rate limits are often missing.** Without them, attackers can brute-force credentials or enumerate resources at will.
- **Most companies don't know what their API inventory looks like.** Old, forgotten endpoints from two versions ago are a gold mine for attackers.

APIGuard finds these issues **before attackers do** — safely, read-only, and with clear severity scoring.

---

## Who Uses This in Real Life?

| Role | What They Use APIGuard For |
|------|---------------------------|
| **Penetration Testers** | Authorized API security assessments — systematic OWASP coverage. |
| **Bug Bounty Hunters** | Fast recon on API targets looking for BOLA, auth bypass, and injection. |
| **Security Auditors** | Evidence-based reports for compliance (PCI DSS, SOC 2, ISO 27001). |
| **AppSec Engineers** | CI/CD integration — catch API regressions before they ship. |
| **Developers** | Self-test their API endpoints during development. |

---

## How Does It Work?

APIGuard follows a simple process:

1. **You give it a target URL** — the base URL of your API (e.g. `https://api.example.com/v2`).
2. **It discovers endpoints** — if you provide an OpenAPI spec, it parses all paths; otherwise it probes a built-in wordlist of common API paths.
3. **It authenticates** — six auth modes (none, bearer, apikey, basic, cookie, OAuth2) — your token is **never stored** in plain text.
4. **It runs OWASP category tests** — each test sends targeted requests (e.g. for BOLA it tries resource IDs ±1 and ±2; for injection it sends a single quote first and stops on 500).
5. **It records findings** — severity, endpoint, method, evidence, and which OWASP category it maps to.
6. **It shows a report** — a rich dashboard with stats, findings table, OWASP coverage matrix, history, and JSON export.

### Safety by Design

- **Rate-limit testing** caps at 20 requests — it proves the point, not floods your API.
- **SSRF probes** target `127.0.0.1` only — no external callback services.
- **Injection testing** sends a single special character first; if it causes a 500, it stops that test immediately.
- **BOLA fuzzing** stays within ±1 and ±2 of your resource ID — no brute-forcing thousands of IDs.
- **Bearer tokens** are stored as `[REDACTED]` in the SQLite database.
- **Destructive requests** require the explicit `--unsafe` flag and are clearly labelled.

---

## Key Terms Explained

| Term | Simple Explanation |
|------|-------------------|
| **BOLA / IDOR** | Broken Object Level Authorization — you can access someone else's data by changing an ID in the URL (API1). |
| **BFLA** | Broken Function Level Authorization — you can call an admin endpoint as a regular user (API5). |
| **SSRF** | Server-Side Request Forgery — the API fetches URLs you give it, potentially hitting internal services (API7). |
| **Mass Assignment** | Sending extra fields the API didn't expect, and having them silently accepted (API3). |
| **OWASP API Top 10** | The ten most critical API security risks, updated by OWASP. APIGuard covers all 10 + injection. |
| **Severity** | How bad a finding is: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO`. |
| **Auth Mode** | How APIGuard authenticates to your API (bearer token, API key, basic auth, cookie, or OAuth2). |
| **OpenAPI Spec** | A standard way to describe REST APIs (paths, methods, parameters). APIGuard uses it for endpoint discovery. |
| **CVSS** | Common Vulnerability Scoring System — a 0–10 score for vulnerability severity. |

---

## What Does the Output Mean?

After a scan you get:

| Column | What It Means |
|--------|---------------|
| **OWASP** | Which API Security Top 10 category (API1–API10 or INJECTION). |
| **Method** | HTTP method used (GET, POST, PUT, etc.). |
| **Endpoint** | The API path that was tested. |
| **Test** | The specific test that triggered (e.g. "BOLA ±1 IDOR check"). |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO. |
| **Evidence** | The raw response snippet that proves the issue. |

### Severity Levels

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | Immediate data leak or full compromise — e.g. BOLA exposing every user's data, or SSRF reaching internal hosts. |
| **HIGH** | Serious weakness that should be fixed urgently — e.g. broken auth, missing rate limits leading to brute-force. |
| **MEDIUM** | Moderate risk — e.g. excessive data exposure, missing security headers. |
| **LOW** | Minor disclosure or hygiene issue. |
| **INFO** | Context only — not a vulnerability by itself. |

---

## Real Example Walkthrough

Say you're auditing `https://api.shop.example.com/v2` (a system you own or have written permission to test).

**Step 1 — Run the scan**

```bash
python main.py https://api.shop.example.com/v2 --auth "bearer YOUR_TOKEN"
```

**Step 2 — Watch findings stream in**

```text
[1/11] Testing API1 — BOLA/IDOR ...
  ⚠  BOLA ±1: GET /v2/users/1001 → 200 OK (leaks user data)
  ⚠  BOLA ±2: GET /v2/users/1002 → 200 OK (leaks user data)
[CVE-MATCH] CVE-2025-1234 maps to API5 (BFLA)
  ⚠  BFLA: POST /v2/admin/users → 403 (expected), but GET /v2/admin/users → 200 OK
```

**Step 3 — Read the report**

| OWASP | Method | Endpoint | Test | Severity | Evidence |
|-------|--------|----------|------|----------|----------|
| API1 | GET | /v2/users/1001 | BOLA ±1 IDOR | HIGH | 200 OK, user data returned |
| API5 | GET | /v2/admin/users | BFLA escalation | HIGH | 200, admin endpoint reachable as user |

**Step 4 — Take action**

- The BOLA vulnerability means attackers can read every user's profile by cycling IDs. Fix: enforce object-level authorization checks on every endpoint.
- The BFLA issue means admin functions are accessible without admin privileges. Fix: validate roles on every function-level endpoint.

**The API is now measurably more secure** — APIGuard found two critical-class issues in under a minute.

---

## What This Tool CANNOT Do

- ❌ **Cannot exploit** — it identifies vulnerabilities but does not prove exploitation potential.
- ❌ **Cannot test GraphQL deeply** — focused on REST APIs (though basic injection tests work on GraphQL endpoints).
- ❌ **Cannot bypass WAFs** — it respects rate limits and doesn't try to evade detection.
- ❌ **Cannot test authenticated-only endpoints without credentials** — you must supply valid auth credentials.
- ❌ **Cannot guarantee zero false positives** — always verify findings manually.
- ❌ **Cannot brute-force** — BOLA fuzzing is intentionally limited to ±1 and ±2.

---

## ⚠️ Cautions and Warnings

> **CRITICAL: Scanning a system you do not own or lack written permission to test is ILLEGAL** in most jurisdictions, including under the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and the Information Technology Act, 2000 (India). Unauthorized API scanning is treated as attempted intrusion.

### Golden Rules of Ethical API Testing

1. **Only scan APIs you own or have explicit written permission to test.**
2. **Get it in writing** — an email from the API owner saying "you may test this."
3. **Respect scope** — test only the endpoints and rate limits you agreed on.
4. **Never use destructive flags** without a clear, documented agreement.
5. **Start with `--unsafe` never enabled** — escalate only when you've proven the need.

---

## 🎓 Learning Path

### Beginner
1. Read this document end to end.
2. Set up a local test API (e.g. [crAPI](https://github.com/OWASP/crAPI) or [vAPI](https://github.com/roottusk/vapi)) and scan it.
3. Run `python main.py http://localhost:5000` and watch the findings.

### Intermediate
4. Learn HTTP methods, status codes, and RESTful API design.
5. Study each OWASP API Top 10 category: what it is, why it matters, how to test it.
6. Try the five auth modes against a test API.

### Advanced
7. Write integration tests that run APIGuard in CI against your staging API.
8. Combine APIGuard with other SecureNET tools (VulnProbe for web, APIGuard for API).
9. Export findings as JSON and pipe into a SIEM or ticketing system.

---

## 📚 Further Reading

### Tools & References
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) — the authoritative list.
- [OWASP crAPI](https://github.com/OWASP/crAPI) — intentionally vulnerable API for practice.
- [vAPI](https://github.com/roottusk/vapi) — another vulnerable API lab.

### Learning
- [MDN: HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP) — how requests and responses work.
- [Understanding REST APIs](https://restfulapi.net/) — API concepts for beginners.

### Practice Environments
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — free API security labs.
- [HackTheBox](https://www.hackthebox.com/) — legal penetration-testing labs.

---

*Remember: APIGuard checks — it never exploits. Stay authorized, stay rate-limited, and stay ethical.* 🛡️
