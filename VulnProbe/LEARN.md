# LEARN.md — VulnProbe for Beginners

VulnProbe is a **template-based HTTP vulnerability scanner** in the style of
[Nuclei](https://github.com/projectdiscovery/nuclei). This guide explains the
core ideas so you can run it, read its output, and even write your own templates.

---

## 1. What problem does it solve?

When you test a web server, many weaknesses are *detectable with a single
read-only HTTP request*:

- Is there an admin panel at `/admin`?
- Is `.git/config` accidentally served?
- Does the `Server` header leak `Apache/2.4.51`?
- Is `/metrics` (Prometheus) exposed to the world?

VulnProbe encodes each check as a **template** (a YAML file). At scan time it
sends the request and checks the response against **matchers**. No payloads are
ever written or exploited — detection only.

---

## 2. The mental model

```
template.yaml
   ├── id / name / severity / category / tags
   └── requests:
         ├── path(s) to request
         └── matchers:   ← "what makes this a finding?"
               ├── type: status   (HTTP code)
               ├── type: word     (text in body/header)
               ├── type: regex    (pattern in body/header)
               ├── type: size     (response byte size)
               ├── type: binary   (magic bytes / hex)
               └── type: header   (header name + value)
```

If the matchers pass, VulnProbe records a **finding** with the severity, the
matched path, the extracted values, and the remediation advice.

---

## 3. Run your first scan

```bash
# inside VulnProbe/
source .venv/bin/activate
python main.py https://your-test-site.example.com
```

You'll see a disclaimer (you must confirm authorization), then a live progress
bar, then findings stream in as they are found, and a summary table at the end.

Try a **dry run** to see exactly what would be sent without sending anything:

```bash
python main.py https://your-test-site.example.com --dry-run
```

---

## 4. Reading a finding

```
[HIGH] exposed-admin-panel → https://x.com/admin
```

means: template `exposed-admin-panel` triggered on path `/admin`, severity HIGH.

In the **dashboard → Findings** tab you can click a row to see:
- the full request path and headers,
- the response status / size / time,
- which matcher condition fired,
- the extracted values,
- the remediation text.

---

## 5. Controlling scan scope

| Goal | Flag |
|------|------|
| Only HIGH/CRITICAL | `--severity high,critical` |
| Only exposed panels | `--category exposed-panels` |
| Only templates tagged `admin` | `--tags admin` |
| Slower & gentler | `--rate-limit 60 --threads 10` |
| Scan many URLs | put them in a file, pass `@file.txt` |
| Scan a domain | just pass `example.com` (tries http + https) |

---

## 6. Writing your first template

Create `my-first.yaml`:

```yaml
id: my-login-page
name: Detect Login Page
description: Demo template that flags any page containing "login".
author: You
severity: INFO
category: default-creds
tags: [login, demo]
requests:
  - method: GET
    path: [/login, /admin/login]
    matchers:
      operator: OR
      conditions:
        - type: status
          values: [200, 401]
        - type: word
          part: body
          words: [login, "sign in"]
          condition: OR
```

Run it alongside the built-ins:

```bash
python main.py https://target.com --templates ./my-templates
```

Or validate it in the dashboard (**Template Library → Validate YAML**).

> Templates *must* be read-only. If you ever need a non-GET method, you must set
> `safe: true` and explain `safe_reason`. VulnProbe will refuse otherwise.

---

## 7. Safety rules (important)

- **Authorized testing only.** Only scan what you own or are allowed to test.
- VulnProbe never sends destructive payloads.
- `--dry-run` plans, never sends.
- Redirects to other domains are never followed (open-redirect protection).
- Per-host rate limiting + `429` backoff protect the target.

---

## 8. Where things live

| Want to… | Look at |
|----------|---------|
| Understand the engine | `engine/` (`loader.py`, `scanner.py`, `matchers.py`, `extractors.py`, `ratelimiter.py`) |
| Change the DB schema | `database.py` |
| Change reports | `reporter.py` |
| Add templates | `templates/<category>/` |
| Learn the full schema | `TEMPLATES.md` |

Happy (authorized) hunting!
