# TechFinger Signatures

Signatures live in `signatures/*.json` (one file per category) so the
community can add detections **without touching Python code**.

## Signature format

```json
{
  "id": "tech-001",
  "name": "WordPress",
  "category": "cms",
  "confidence": 90,
  "indicators": [
    {
      "source": "header",
      "field": "x-powered-by",
      "pattern": "WordPress",
      "confidence_weight": 80
    },
    {
      "source": "body",
      "pattern": "/wp-content/",
      "confidence_weight": 90
    },
    {
      "source": "meta",
      "attribute": "generator",
      "pattern": "WordPress (.*)",
      "version_group": 1,
      "confidence_weight": 100
    },
    {
      "source": "cookie",
      "name_pattern": "wordpress_.*",
      "confidence_weight": 70
    }
  ],
  "version_patterns": [
    {"source": "meta", "attribute": "generator", "regex": "WordPress ([\\d.]+)"},
    {"source": "body", "regex": "\\?ver=([\\d.]+)"}
  ],
  "cve_check": {"lookup_key": "wordpress", "version_required": true},
  "risk_if_version_below": {"value": "6.4.2", "severity": "HIGH", "reason": "..."},
  "risk_if_version_exposed": "MEDIUM",
  "tags": ["cms", "php", "blog", "open-source"],
  "website": "https://wordpress.org"
}
```

## Fields

| Field | Meaning |
|-------|---------|
| `id` | Stable rule ID (e.g. `CMS-001`). |
| `name` | Display name of the technology. |
| `category` | `server` / `framework` / `cms` / `cdn` / `analytics` / `jslibs` / `security`. |
| `confidence` | Baseline confidence (0-100). |
| `indicators[]` | Matching clues (see below). |
| `version_patterns[]` | Ordered regexes; first match wins. |
| `cve_check` | `{lookup_key, version_required}` → key into `data/tech_cve_map.json`. |
| `risk_if_version_below` | Flag severity if detected version < `value`. |
| `risk_if_version_exposed` | Default risk when a version is exposed. |
| `tags`, `website` | Metadata for display. |

### Indicator `source` values

`header` · `body` · `cookie` · `meta`

For `header`/`meta`, set `field` (header name lowercased, or meta `attribute`).
For `cookie`, set `name_pattern` (regex on cookie name).

### Indicator `pattern`

- Regex matched against the chosen source text.
- Use `version_group` (1-based) to capture a version from the match.
- Empty/`".*"` pattern = presence-only (field just needs to exist).

## Confidence scoring

- Each matching indicator contributes its `confidence_weight`.
- Final confidence = **highest single weight** (not additive).
- If **3+** indicators match → +10 boost (capped 100).
- Labels: `CERTAIN` 90-100 · `LIKELY` 70-89 · `POSSIBLE` 50-69 · `UNCERTAIN` <50.

## CVE correlation

`data/tech_cve_map.json` maps `lookup_key` → list of
`{affected, cve, severity, cvss_score, description}`.
`affected` uses semver ranges (`"<6.4.2"`, `">=1.0.0"`).
If the detected version matches → the CVE is flagged.

## Security-header signatures (`security_headers.json`)

These use `header_name` + `pass_if_present` + `fail_severity`.
They render as a PASS/FAIL grid in the CLI and dashboard.

## Adding a signature

1. Append a JSON object to the right `signatures/<category>.json`.
2. If it has CVEs, add an entry to `data/tech_cve_map.json`.
3. (Optional) add a favicon hash in `data/favicon_hashes.json`.

No code changes required.
