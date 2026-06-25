# 🛠️ HeaderScan — Learn Before You Use

Welcome! If you've never heard of HTTP security headers or wondered what a "grade" for a website means, you're in the right place. This guide will walk you through everything you need to know about HeaderScan — no technical background required.

---

## What Is This Tool?

Think of it like this:

> **Imagine you're about to move into a new building.** Before you sign the lease, you'd want to check a security checklist:
>
> - Are all the doors locked?
> - Are the windows latched?
> - Is the alarm system turned on?
> - Are there security cameras?
> - Is the fire escape accessible?

**HeaderScan does the exact same thing — but for websites.**

When your browser visits a website, the website sends back a set of "headers" — invisible instructions that tell your browser how to behave safely. HeaderScan checks those instructions to see if the website has its "doors locked and windows latched." If a website is missing important security headers, HeaderScan will flag it and give it a grade from A (great) to F (dangerous).

---

## Why Does This Exist?

Without proper security headers, a hacker can trick your browser into doing things you never intended — like:

- **Running malicious code** on your computer without you knowing
- **Stealing your login credentials** by redirecting you to a fake page
- **Tracking you across websites** without your permission
- **Tricking you into clicking hidden buttons** that perform actions on your behalf

Security headers are like the rules that keep your browser safe. When a website doesn't set them, it's like leaving the front door wide open. HeaderScan helps you spot those open doors before someone walks through them.

---

## Who Uses This in Real Life?

| Role | Why They Use It |
|------|----------------|
| **Security Engineers** | To audit company websites and ensure they meet security standards |
| **Web Developers** | To check their site before launching it to the public |
| **Penetration Testers** | To find weaknesses in a website as part of authorized security testing |
| **Bug Bounty Hunters** | To discover security flaws and report them for rewards |
| **IT Administrators** | To verify that all company websites follow security policies |

Even if you're just a curious beginner, understanding these concepts makes you safer online.

---

## How Does It Work?

Here's what happens when you run HeaderScan, step by step:

1. **You enter a website URL** — for example, `https://example.com`
2. **HeaderScan sends a request** — it asks the website for its homepage, just like your browser would
3. **The website responds** — along with the page content, it sends back HTTP headers (hidden metadata)
4. **HeaderScan examines 10 key security headers** — it checks whether each important security header is present and properly configured
5. **Each header gets scored** — present and correct headers earn points; missing or misconfigured headers lose points
6. **A final grade is calculated** — based on the total score, the website receives a letter grade from A to F
7. **Results are displayed** — you see which headers are present, which are missing, and what you can do to fix them

---

## Key Terms Explained

Before diving deeper, let's learn the vocabulary:

| Term | Simple Explanation |
|------|-------------------|
| **HTTP** | The language your browser and websites use to talk to each other. When you type a website address, your browser sends an HTTP request and the website sends back an HTTP response. |
| **Header** | A piece of hidden information attached to every web response. Think of it like the envelope of a letter — it contains instructions about how to handle the contents. |
| **CSP (Content Security Policy)** | A header that tells your browser: "Only load scripts and content from these approved sources." It's like a bouncer at a club who only lets people on the guest list inside. |
| **HSTS (HTTP Strict Transport Security)** | A header that forces your browser to always use a secure (encrypted) connection. It's like a rule that says "you can only enter through the locked, guarded door — never the open back entrance." |
| **XSS (Cross-Site Scripting)** | An attack where a hacker injects malicious code into a website that then runs in your browser. It's like someone slipping a fake instruction note into a stack of legitimate documents. |
| **Clickjacking** | An attack where a hacker tricks you into clicking something different from what you see. It's like putting a transparent button over a real button — you think you're clicking "Play Video" but you're actually clicking "Transfer Money." |
| **MIME Type** | A label that tells the browser what kind of file it's receiving — is it HTML? An image? A script? It's like labeling boxes when moving so you know what's inside without opening them. |
| **Referrer** | Information about which website sent you to the current page. It's like a return address on a letter — it tells the destination where you came from. |

---

## What Does the Output Mean?

When HeaderScan finishes, you'll see something like this:

| Grade | Meaning | What It Means for You |
|-------|---------|----------------------|
| **A** | Excellent | The website has strong security headers. Well protected. |
| **B** | Good | Most security headers are in place, but a few could be improved. |
| **C** | Fair | Some important headers are missing. The site has moderate risk. |
| **D** | Poor | Several critical security headers are missing. The site is vulnerable. |
| **F** | Failing | Major security headers are absent. The site is at high risk of attacks. |

### Individual Header Results

For each header checked, you'll see one of these statuses:

| Status | Meaning |
|--------|---------|
| ✅ **Present** | The header is there and properly configured. Good! |
| ⚠️ **Present but misconfigured** | The header exists but isn't set up correctly. Needs fixing. |
| ❌ **Missing** | The header is completely absent. This is a security gap. |

---

## Real Example Walkthrough

Let's walk through what happens when you scan `https://example.com`:

1. **You run:** `python header_scan.py https://example.com`

2. **HeaderScan sends a request** to the server and receives the response headers.

3. **It checks each header:**

   | Header | Status | Notes |
   |--------|--------|-------|
   | Content-Security-Policy | ❌ Missing | No CSP header found |
   | Strict-Transport-Security | ✅ Present | `max-age=31536000` |
   | X-Content-Type-Options | ✅ Present | `nosniff` |
   | X-Frame-Options | ✅ Present | `DENY` |
   | X-XSS-Protection | ❌ Missing | No XSS protection header |
   | Referrer-Policy | ⚠️ Present but weak | `unsafe-url` leaks referrer info |
   | Permissions-Policy | ❌ Missing | No permissions policy set |
   | X-Permitted-Cross-Domain-Policies | ❌ Missing | Not configured |
   | Cross-Origin-Opener-Policy | ❌ Missing | Not configured |
   | Cross-Origin-Resource-Policy | ❌ Missing | Not configured |

4. **Final Grade: D**

5. **Recommendations:** Add a Content-Security-Policy header, enable X-XSS-Protection, strengthen the Referrer-Policy, and consider adding the missing Cross-Origin headers.

---

## What This Tool CANNOT Do

It's important to understand HeaderScan's limitations:

- ❌ **It does NOT scan the actual content** of a website (HTML, JavaScript, images)
- ❌ **It does NOT test for software vulnerabilities** like SQL injection or server exploits
- ❌ **It does NOT check if the website's code is secure** — only its headers
- ❌ **It does NOT guarantee safety** — a site with an A grade can still have other problems
- ❌ **It does NOT fix anything** — it only reports what it finds

**Think of it this way:** HeaderScan checks the locks on the doors, but it doesn't inspect what's inside the house. A locked door is good, but it doesn't mean the house is completely safe.

---

## ⚠️ Cautions and Warnings

### Only Scan What You Own or Have Permission to Audit

- **NEVER** scan a website without explicit authorization from the owner
- Scanning someone else's website without permission may be **illegal** in your jurisdiction
- Even well-intentioned scanning can be interpreted as an attack

### Legal Warning

> **Unauthorized scanning of computer systems is a criminal offense in many countries**, including under:
> - The Computer Fraud and Abuse Act (CFAA) in the United States
> - The Computer Misuse Act in the United Kingdom
> - Similar legislation in the EU, Australia, Canada, and many other jurisdictions
>
> **Always get written permission** before scanning any system you do not own. If in doubt, don't scan it.

### Responsible Use

- Use HeaderScan only on your own websites, or on websites where you have been given explicit written authorization
- If you find vulnerabilities, report them responsibly to the website owner
- Do not use this tool to harass, intimidate, or harm others

---

## 🎓 Learning Path

If you're new to web security, here's a suggested order to build your knowledge:

1. **Start here** — Read this guide thoroughly
2. **Learn HTTP basics** — Understand how browsers and servers communicate (see Further Reading)
3. **Try HeaderScan on your own projects** — Practice in a safe environment
4. **Study each security header individually** — Understand what each one does and why it matters
5. **Learn about common attacks** — Study XSS, clickjacking, and other attacks that headers prevent
6. **Explore browser developer tools** — Open your browser's DevTools (F12) and look at the Network tab to see headers in real time
7. **Practice on intentionally vulnerable sites** — Use legal practice environments like OWASP WebGoat or DVWA (Damn Vulnerable Web Application)
8. **Get certified** — Consider certifications like CompTIA Security+ or the CEH (Certified Ethical Hacker)

---

## 📚 Further Reading

### Beginner-Friendly Resources
- [MDN Web Docs: HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) — Comprehensive reference of all HTTP headers
- [MDN Web Docs: Security](https://developer.mozilla.org/en-US/docs/Web/Security) — Overview of web security concepts
- [OWASP: HTTP Security Response Headers](https://owasp.org/www-project-secure-headers/) — The definitive guide to security headers

### Security Header Deep Dives
- [Content Security Policy Reference](https://content-security-policy.com/) — Everything about CSP
- [HSTS Preload List](https://hstspreload.org/) — Learn about HSTS and how to get on the preload list
- [SecurityHeaders.com](https://securityheaders.com/) — Free online header checker (similar to this tool)

### Understanding Attacks
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — The most critical web application security risks
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html) — How XSS works and how to stop it
- [Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) — Understanding and preventing clickjacking

### Practice Environments
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) — A deliberately insecure app for learning
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Free online security training
- [HackTheBox](https://www.hackthebox.com/) — Legal penetration testing practice labs

---

*Remember: Security is not a destination — it's a journey. Every header you add, every vulnerability you fix, makes the web a little safer for everyone.* 🛡️
