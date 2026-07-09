# VulnProbe — LEARN.md

## What problem does VulnProbe solve?

Before you harden or attack a web app you need a fast, repeatable read-only
inventory of what is *exposed*. Nuclei templates let you encode each check as a
small YAML file: send a request, evaluate matchers, record a finding. VulnProbe
shows the mechanism with 60 built-in templates across 8 categories and a CLI +
dashboard, all sending only read-only HTTP requests.

## Key concept — template + matcher evaluation

Each template pairs a set of request paths with **multi-condition matchers**.
VulnProbe sends the request, then evaluates matchers in two layers:

- **within a block**: `operator: AND|OR` combines the `conditions`.
- **across blocks**: `matchers_condition: AND|OR` combines blocks.

A template is triggered when *any* path matches. Six matcher types are
supported: `status`, `word`, `regex`, `size`, `binary`, `header`. Extractors
(`regex` / `kval`) pull values out of a match for the report.

## Analogy

Think of VulnProbe as **a bouncer checking a club's front door against a
checklist**: each checklist item (template) looks for one tell — an exposed
admin panel, a leaked `.git/config`, a version string in the Server header. The
bouncer only *looks* (read-only GET); they never go inside or move anything.

## Read-only by design

VulnProbe only sends GET/HEAD/OPTIONS by default — it never probes, fuzzes, or
writes. A non-GET request requires `safe: true` *and* a `safe_reason`. The
`--dry-run` flag plans every request and sends nothing. Redirects to other
hosts are never followed (open-redirect protection), and per-host rate limiting
plus `429` backoff protect the target.

## Try it

```bash
source .venv/bin/activate
python main.py https://your-authorized-target.example.com --dry-run
python main.py https://your-authorized-target.example.com --severity high,critical
```

See `TEMPLATES.md` for the full schema and how to write your own template, and
`README.md` for the dashboard and API reference.
