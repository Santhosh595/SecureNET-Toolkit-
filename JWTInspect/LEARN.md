# 🛠️ JWTInspect — Learn Before You Use

## What Is This Tool? (The Simple Version)

A JWT is like a wristband at a concert. It says who you
are and what areas you can access. JWTInspect checks if
that wristband can be faked, copied, or modified.

It decodes any JWT token, runs 8 security tests against
it, and tells you exactly how an attacker could forge
or abuse it.

## Why Does This Exist? (The Problem It Solves)

JWTs [JSON Web Tokens — a way to prove who you are
when using an app] are used everywhere: login sessions,
API access, password resets. But many developers
implement them incorrectly.

A misconfigured JWT lets attackers impersonate other
users, escalate privileges, or bypass authentication
entirely. JWTInspect finds these misconfigurations
before attackers exploit them.

## Who Uses This in Real Life?

- Security engineers auditing authentication systems
- Penetration testers [people paid to find security
  holes before hackers do]
- Bug bounty hunters [people who earn money by finding
  and reporting security issues]
- Developers testing their own JWT implementations

## How Does It Work? (Step by Step, Plain English)

1. You paste a JWT token (the long string of letters
   and numbers)
2. It decodes the header and payload [the two parts
   of the token that contain information]
3. It runs 8 automated security tests:
   - Is the algorithm set to "none"? (allows forging)
   - Is the signing secret weak? (can be cracked)
   - Can the algorithm be swapped from RS256 to HS256?
   - Does the token expire? (or is it valid forever?)
   - Is sensitive data visible in the payload?
   - Is the "kid" header injectable?
   - Are external key URLs (jku/x5u) trusted?
   - Do claims differ between two tokens?
4. It generates proof-of-concept forged tokens for
   any vulnerability found
5. It shows you an overall verdict: SECURE, WEAK,
   VULNERABLE, or CRITICALLY VULNERABLE

## Key Terms Explained (Glossary)

**JWT** — JSON Web Token. A string that proves who you
are. Like a concert wristband that gets you backstage.

**Header** — the first part of a JWT. Says which
algorithm was used to sign it.

**Payload** — the second part of a JWT. Contains the
actual data (user ID, role, expiry time).

**Signature** — the third part. Proves the token hasn't
been tampered with. Like a hologram on a concert wristband.

**Algorithm** — the method used to create the signature.
HS256 uses a shared secret. RS256 uses a private key.

**alg:none** — a dangerous setting that disables
signature verification entirely. Like a concert with
no security at all.

**HS256** — HMAC with SHA-256. Uses a shared secret
to sign tokens. Both server and client know the secret.

**RS256** — RSA with SHA-256. Uses a private key to
sign and a public key to verify. More secure.

**Claim** — a piece of data inside the JWT payload.
Like "role": "admin" or "exp": 1234567890.

**Expiry (exp)** — when the token stops working.
Like an expiration date on a concert wristband.

## What Does the Output Mean?

| Result | What It Means | What To Do |
|--------|---------------|------------|
| PASS | This check found no issues | Nothing, move on |
| INFO | Informational finding | Review, low priority |
| WARNING | Something could be better | Plan to fix soon |
| FAIL | Vulnerability detected | Fix this immediately |
| CRITICAL | Severe vulnerability | Fix right now |

## Real Example Walkthrough

You find this JWT in your browser after logging in:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.dGhpcyBpcyBhIGZha2Ugc2lnbmF0dXJl
```

You paste it into JWTInspect and get:

```
=== Decoded Token ===
Header: {"alg": "HS256", "typ": "JWT"}
Payload: {"sub": "1234567890", "role": "user", "iat": 1516239022}

=== Security Tests ===
[PASS] Algorithm is not 'none'
[FAIL] Secret cracked: 'secret123' (weak password)
[WARNING] Token has no expiry claim
[PASS] No sensitive data in payload
[WARNING] No 'kid' header (good, but check server-side)

=== Verdict: VULNERABLE ===
```

This tells you the server is using "secret123" as its
signing key. An attacker can forge tokens for any user
by guessing this weak secret.

## What This Tool CANNOT Do (Limitations)

- It cannot test server-side validation directly
- It only analyzes the token structure, not the
  server's implementation
- It cannot crack strong secrets (256+ bit keys)
- It requires you to already have a valid token
  to analyze

## ⚠️ Cautions and Warnings

### Before You Use This Tool:
- Only test tokens you own or have permission to test
- Never use forged tokens to access systems you
  don't own
- This tool generates proof-of-concept tokens for
  educational purposes only

### What Can Go Wrong:
- Using forged tokens to access systems is fraud
- Testing production systems may log your activity
- Cracking secrets may take significant compute time

### Legal Warning:
Using this tool on systems without permission may violate:
- India: IT Act 2000, Section 43 and 66
- USA: Computer Fraud and Abuse Act (CFAA)
- And equivalent laws in your country

## 🎓 Learning Path (What to Learn Next)

- **OAuth 2.0 and OpenID Connect** — understand how
  JWTs fit into modern authentication
- **Session management** — learn secure alternatives
  to JWT for login systems
- **Cryptography basics** — understand why some
  algorithms are stronger than others
- **API security** — learn how to properly validate
  tokens server-side

## 📚 Further Reading

- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger: JWT Attacks](https://portswigger.net/web-security/jwt) — free
- [TryHackMe: JWT](https://tryhackme.com) — free room
- [Wikipedia: JWT](https://en.wikipedia.org/wiki/JSON_Web_Token)
