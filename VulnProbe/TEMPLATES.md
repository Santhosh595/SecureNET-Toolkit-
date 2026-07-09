# TEMPLATES.md — Authoring VulnProbe Templates

This guide documents the VulnProbe template schema, the six matcher types, and
how to write, test, and contribute your own templates. The schema is
**Nuclei-compatible** at the concept level (id/info/requests/matchers) with a
few VulnProbe-specific safety fields.

---

## 1. Full schema reference

```yaml
id: unique-template-id            # REQUIRED. lowercase slug, unique across all templates
name: Human Readable Name         # REQUIRED
description: >                     # REQUIRED. What this detects & why
  Detects ...
author: SecureNET                 # OPTIONAL. defaults to SecureNET
severity: HIGH                    # REQUIRED. CRITICAL|HIGH|MEDIUM|LOW|INFO
category: exposed-panels          # OPTIONAL. inferred from folder if omitted
tags: [admin, panel, exposure]    # OPTIONAL. list of strings
references:                        # OPTIONAL. list of URLs
  - https://owasp.org/www-project-top-ten/

safe: true                        # OPTIONAL. ONLY if a request is non-GET.
safe_reason: >                    # REQUIRED when safe: true. Why it's read-only.

requests:                          # REQUIRED. list (1..50)
  - method: GET                    # GET (default) | HEAD | POST | OPTIONS
    path: [/admin, /administrator] # string or list (max 20 paths)
    headers:                       # OPTIONAL. merged over global headers
      User-Agent: "..."
    follow_redirects: true         # OPTIONAL. default false (open-redirect safe)
    timeout: 10                    # OPTIONAL. seconds
    matchers:                      # REQUIRED (or `matcher`)
      operator: OR                 # AND|OR within the block
      conditions:                  # list of matcher conditions
        - type: status
          values: [200, 302]
        - type: word
          part: body
          words: [admin, login]
          condition: AND
    matchers_condition: AND        # OPTIONAL. how multiple blocks combine
    extractors:                    # OPTIONAL. capture values on match
      - type: regex
        name: title
        part: body
        pattern: "<title>(.*?)</title>"

remediation: >                     # OPTIONAL. shown in reports & dashboard
  Restrict access to internal IPs...
```

### Validation rules (loader enforces these)

- `id` must be a slug and **globally unique** — duplicate IDs are a hard error.
- `severity` must be one of `critical/high/medium/low/info`.
- `path` is a string or list; **max 20 entries** per request.
- `matchers` (or `matcher`) is required; each matcher must have a valid `type`.
- Non-GET methods require `safe: true` **and** a `safe_reason`.
- Invalid templates print a `[WARN]` and are skipped; the scan continues.

---

## 2. Matcher type reference

### Type 1 — `status`
Match HTTP status codes.
```yaml
- type: status
  values: [200, 302, 401]
  negate: false          # if true, matches when status is NOT in values
```

### Type 2 — `word`
Match words/phrases in a response part.
```yaml
- type: word
  part: body             # body | header | all
  words: [admin, dashboard, "control panel"]
  condition: AND         # AND = all must appear; OR = any
  case_insensitive: true
```

### Type 3 — `regex`
Match a regular expression.
```yaml
- type: regex
  part: body
  pattern: "(admin|administrator|control\.panel)"
  case_insensitive: true
  group: 1              # optional capture-group index
```

### Type 4 — `size`
Match response body size (bytes).
```yaml
- type: size
  comparison: lt        # gt | lt | eq | gte | lte
  size: 1048576         # 1 MiB
```

### Type 5 — `binary`
Match raw bytes (hex-encoded). Useful for magic-byte / file-type leaks.
```yaml
- type: binary
  hex: "25504446"       # %PDF magic bytes
  negate: false
```
> Note: Nuclei uses `part: body` for binary; VulnProbe matches the whole
> response body bytes.

### Type 6 — `header`
Match a specific header name + value.
```yaml
- type: header
  header: Server
  values: ["Apache", "nginx"]
  condition: OR
  case_insensitive: true
  negate: false
```

---

## 3. Combining matchers

Within a `matchers` block, `operator: AND|OR` controls how the `conditions`
combine. Across multiple matcher blocks, `matchers_condition: AND|OR` controls
how blocks combine.

```yaml
requests:
  - method: GET
    path: [/admin]
    matchers:
      operator: OR
      conditions:
        - type: status
          values: [200, 302]
        - type: word
          part: body
          words: [admin, login]
          condition: AND
    matchers_condition: AND
```

A template is **triggered** if *any* path matches.

---

## 4. Extractors

Run after a match to pull values into the finding.

```yaml
extractors:
  - type: regex
    name: title
    part: body
    pattern: "<title>(.*?)</title>"
  - type: kval
    name: server
    part: header
    key: Server
```

`regex` captures `group` (default first group) or the whole match. `kval`
extracts a header value or `key=value` from the body.

---

## 5. Common patterns

### Detect a version in a header
```yaml
- type: header
  header: Server
  values: ["Apache", "nginx"]
  condition: OR
- type: regex
  part: header
  pattern: "(Apache/[0-9]|nginx/[0-9])"
  case_insensitive: true
```

### Match a JSON response body
```yaml
- type: word
  part: body
  words: ['"version"', '"debug"']
  condition: AND
- type: regex
  part: body
  pattern: '"debug"\s*:\s*true'
```

### Detect exposed sensitive file (size guard)
```yaml
- type: status
  values: [200]
- type: size
  comparison: lt
  size: 1048576
```

---

## 6. How to test a template before submitting

1. **Dry run** to confirm paths/headers are built correctly:
   ```bash
   python main.py https://test-target.example.com --dry-run
   ```
2. **Validate** the YAML in the dashboard (*Template Library → Validate YAML*)
   or programmatically:
   ```python
   from engine.loader import validate_template, TemplateError
   import yaml
   try:
      validate_template(yaml.safe_load(open("my.yaml")), filename="my.yaml")
   except TemplateError as e:
      print("INVALID:", e)
   ```
3. **Run against a local mock** (see `_smoketest.py`) so you don't hit a real
   host during development.
4. Confirm the **severity** and **remediation** text are accurate.

---

## 7. Contribution guide

- Place new templates under `templates/<category>/<id>.yaml`.
- Use a descriptive, unique `id` (kebab-case).
- Set an appropriate `severity` and add relevant `tags`.
- Always include `remediation`.
- Keep requests **read-only**; justify any non-GET with `safe:` + `safe_reason`.
- Run the loader test (`from engine import load_templates; load_templates()`)
  and ensure **0 errors**.
- Open a PR with a short description of what the template detects.

---

## 8. Annotated examples

### Example A — exposed panel (status + word, OR)
```yaml
id: exposed-jenkins-dashboard
name: Exposed Jenkins Dashboard
description: Detects publicly accessible Jenkins dashboards.
author: SecureNET
severity: HIGH
category: exposed-panels
tags: [jenkins, ci, exposure]
requests:
  - method: GET
    path: [/jenkins, /, /login]
    matchers:
      operator: OR
      conditions:
        - type: status
          values: [200, 302]
        - type: word
          part: body
          words: [jenkins, dashboard]
          condition: OR
    extractors:
      - type: regex
        name: title
        part: body
        pattern: "<title>(.*?)</title>"
remediation: >
  Restrict Jenkins behind VPN/SSO and disable anonymous read access.
```

### Example B — version leak (header, AND)
```yaml
id: server-header-version
name: Server Header Version Disclosure
description: Server header leaks software version.
author: SecureNET
severity: LOW
category: version-leak
tags: [server, version, disclosure]
requests:
  - method: GET
    path: [/]
    matchers:
      operator: AND
      conditions:
        - type: status
          values: [200, 301, 302, 403, 404]
        - type: header
          header: Server
          values: ["Apache", "nginx", "Microsoft-IIS"]
          condition: OR
        - type: regex
          part: header
          pattern: "(Apache/[0-9]|nginx/[0-9]|Microsoft-IIS/[0-9])"
          case_insensitive: true
remediation: >
  Normalize/strip Server and X-Powered-By headers at the proxy layer.
```

### Example C — sensitive file (status + size + extractor)
```yaml
id: exposed-env-file
name: Exposed .env File
description: Detects exposed environment/.env files.
author: SecureNET
severity: CRITICAL
category: sensitive-files
tags: [env, secrets, exposure]
requests:
  - method: GET
    path: [/.env, /.env.example]
    follow_redirects: false
    matchers:
      operator: AND
      conditions:
        - type: status
          values: [200]
        - type: size
          comparison: lt
          size: 1048576
    extractors:
      - type: regex
        name: snippet
        part: body
        pattern: "(password|secret|key|token|DB_|aws_)"
remediation: >
  Never commit .env to VCS; block web access to dotfiles; rotate leaked secrets.
```
