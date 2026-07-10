# 🛠️ PathProbe — Learn Before You Use

Welcome! If you've never used a content-discovery / directory-bruteforcing tool before, this guide walks you through everything you need to know — no technical background required. By the end you'll understand what PathProbe does, how it works, and how to use it responsibly.

---

## What Is This Tool?

Imagine a building with hundreds of doors — but only a few are on the floor plan. Some lead to supply closets, some to the server room, and a couple are left unlocked by mistake. **PathProbe is a way to quietly check every door** to see which ones open.

**PathProbe is a multi-threaded web content discovery tool** in the style of [feroxbuster](https://github.com/ffuf/feroxbuster) and [dirsearch](https://github.com/maurosoria/dirsearch). You give it a website and a **wordlist** (a list of common path names like `admin`, `login`, `backup`), and it requests each one — `https://site.com/admin`, `https://site.com/login`, … — to find pages and files the public site map never links to.

It only ever sends **read-only `GET` requests**. It never logs in, never submits forms, never deletes anything.

---

## Why Does This Exist?

Websites hide far more than their homepage shows. Leftover admin panels, backup archives, exposed config files, and forgotten API endpoints are a goldmine for attackers — and a blind spot for defenders.

PathProbe helps **good guys** find those doors first:
- An `/admin` panel reachable by anyone
- A `/backup.zip` or `.env` file left in the web root
- A `/api/users` endpoint that shouldn't be public
- A debug route (`/phpinfo.php`, `/actuator`) exposed to the internet

It reports what exists; it doesn't exploit it.

---

## Who Uses This in Real Life?

| Role | What They Use PathProbe For |
|------|--------------------------|
| **Penetration Testers** | Mapping a target's hidden attack surface during authorized engagements. |
| **Bug Bounty Hunters** | Sweeping for exposed panels, files, and API endpoints. |
| **Web Developers / DevOps** | Catching leaked backups or debug endpoints before shipping. |
| **Security Auditors** | Evidencing "what is publicly reachable" for compliance. |
| **Blue Teams** | Continuously verifying their own perimeter has nothing accidentally exposed. |

---

## How Does It Work?

PathProbe follows a feroxbuster-style workflow:

1. **You give it a target** — a URL (`https://app.example.com`).
2. **It loads a wordlist** — built-in (`common`, `api`, `files`, `large`) or your own file. Multiple wordlists are merged and de-duplicated.
3. **It builds the request list** — for each word it constructs `base + / + word`, optionally appending extensions (`/admin` → `/admin.php`, `/admin.bak`) and/or a prefix (`/api/v1/admin`).
4. **It probes in parallel** — a thread pool (default 50, max 200) fires `GET` requests through a connection pool, rotating realistic browser User-Agents.
5. **It filters the noise** — only "interesting" status codes are kept (200/201/204 found, 301/302 redirects, 401/403 protected, 405/500 errors). 404s are dropped.
6. **It detects wildcards** — before scanning, it probes 3 random UUID paths. If the server returns 200 for *everything* with similar length, it switches to content-length filtering so you're not buried in false positives.
7. **It recurses (optional)** — when a 200/301 path looks like a directory, it can scan *inside* it, building a full tree up to a depth you set.
8. **It reports** — a live stream of findings, a summary, and JSON / CSV / plain-text export.

---

## Key Terms Explained

| Term | Simple Explanation |
|------|-------------------|
| **Wordlist** | A file of path names to try (`admin`, `login`, `.env`…). Like a phonebook of doors to check. |
| **Extension fuzzing** | Trying `/admin` **and** `/admin.php`, `/admin.bak`, `/admin.zip` — covers files with extensions. |
| **Prefix** | Prepending a path to every word (`/api/v1`) so you scan `api/v1/admin`, `api/v1/users`, … |
| **Wildcard** | A misconfigured server that returns 200 for *any* path. PathProbe detects and filters this automatically. |
| **Recursive** | When `/admin` is a directory, also scan `/admin/login`, `/admin/users`, etc. |
| **Interesting** | A finding flagged because it's a protected/error status, or its body mentions `password`, `secret`, `token`, `admin`, etc. |
| **Rate limit** | Cap on requests per second so you don't flood (or DoS) the target. |
| **Read-only** | PathProbe only sends `GET`. It never mutates the target. |

---

## What Does the Output Mean?

Each found path shows:

| Field | What It Means |
|-------|---------------|
| **Status** | HTTP code (color-coded): green = found, yellow = redirect, red = protected/error. |
| **URL** | The full discovered path. |
| **Size** | Response body length in bytes. |
| **Time** | How long the server took to respond (ms). |
| **Redirect** | Where a 301/302 points (e.g. `/login` → `/login/`). |
| **★** | Marked interesting (protected/error status or sensitive keyword in body). |

### Status Categories

| Code(s) | Category | Meaning |
|---------|----------|---------|
| 200, 201, 204 | FOUND | Page/file exists and is readable. |
| 301, 302, 307, 308 | REDIRECT | Exists but moved — follow the `Location`. |
| 401, 403 | PROTECTED | Exists but needs auth / is forbidden — high signal. |
| 405 | EXISTS | Path exists, wrong method. |
| 500, 502, 503 | ERROR | Server issue — path likely exists. |
| 404, 400 | SKIPPED | Doesn't exist (filtered out by default). |

---

## Real Example Walkthrough

Say you're auditing `https://shop.example.com` (a site you own or have written permission to test).

**Step 1 — Run the scan**

```bash
python main.py https://shop.example.com --wordlist common --extensions php,bak,zip
```

**Step 2 — Watch findings stream in**

```text
200  4823B   45ms  https://shop.example.com/admin
403   892B   23ms  https://shop.example.com/.htpasswd ⚠
301     0B   12ms  https://shop.example.com/login → /login/
200 12045B   67ms  https://shop.example.com/backup.zip ★ INTERESTING
```

**Step 3 — Read the summary**

```text
Total requests: 1500
Interesting findings: 3
Protected (401/403): 1
Redirects: 1
Errors: 0
Total time: 0:00:18
```

**Step 4 — Take action**

- `backup.zip` (★) — a downloadable backup may leak source/secrets; remove it from the web root.
- `.htpasswd` (⚠ 403) — exists but protected; confirm it isn't readable and isn't duplicated elsewhere.
- `/login` → `/login/` — a normal redirect; not a finding by itself.

---

## What This Tool CANNOT Do

- ❌ **Cannot exploit** — it only detects existence. It won't log in or prove a bug is exploitable.
- ❌ **Cannot authenticate** — it scans as an anonymous visitor; auth-only content is out of scope.
- ❌ **Cannot guarantee completeness** — only what the wordlist covers. A missing word = a missed path.
- ❌ **Cannot eliminate all false positives** — wildcard detection is good but not perfect; verify findings.
- ❌ **Does not follow cross-domain redirects** — by design, to avoid leaking your scan.

---

## ⚠️ Cautions and Warnings

> **CRITICAL: Scanning a system you do not own or lack written permission to test is ILLEGAL** in most jurisdictions (Computer Fraud and Abuse Act — US; Computer Misuse Act — UK; Information Technology Act, 2000 — India). Unauthorized scanning is often treated as an attempted intrusion.

### Golden Rules
1. **Only scan systems you own or have explicit written permission to scan.**
2. **Get it in writing** — an email from the owner protects you.
3. **Respect scope** — stick to agreed hosts, paths, and rates.
4. **Use a conservative rate limit** — default 50 threads is fine; lower it for fragile targets.
5. **Practice on your own lab** — run it against a local DVWA / OWASP Juice Shop.

---

## 🎓 Learning Path

### Beginner
1. Read this document end to end.
2. Run `--wordlist common` against a local mock or your own site; watch the stream.
3. Open `wordlists/common.txt` to see what gets tested.

### Intermediate
4. Learn HTTP: requests, responses, status codes, headers (MDN Web Docs).
5. Try extension fuzzing (`--extensions php,bak`) and prefixing (`--prefix /api/v1`).
6. Compare PathProbe output to feroxbuster / dirsearch on the same target.

### Advanced
7. Understand wildcard detection and content-length filtering.
8. Build a custom wordlist for your org's common paths.
9. Pipe JSON export into your SIEM or a recurring scan pipeline.

---

## 📚 Further Reading

- [feroxbuster](https://github.com/ffuf/feroxbuster) — the fast content-discovery tool that inspired PathProbe.
- [dirsearch](https://github.com/maurosoria/dirsearch) — classic directory brute-forcer.
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — authorized testing methodology.
- [MDN: HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP) — how requests/responses work.
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — the most critical web risks.
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — legal, intentionally vulnerable app to practice on.

---

*Remember: PathProbe only looks — it never touches. Stay authorized, stay rate-limited, and stay ethical.* 🛡️
