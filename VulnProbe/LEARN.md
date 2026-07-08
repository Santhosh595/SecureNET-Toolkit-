# VulnProbe — LEARN.md

## What problem does VulnProbe solve?

Large attack-surface scanners (like Nuclei) run thousands of checks against a target. VulnProbe
teaches the *core idea* with a tiny, readable engine: **send a templated request, then check the
response against rules.** You write the rules in YAML, not Python, so non-coders can add checks.

## The matcher model (key concept)

A finding is produced when one or more **matchers** pass:

| Matcher | What it checks | Example |
|---------|----------------|---------|
| `status` | HTTP response code | `[200, 403]` |
| `word`   | Substring in body/headers | `"API_KEY"` |
| `regex`  | Regular expression match | `"nginx/[0-9]"` |

`matchers-condition: and` requires *all* matchers; `or` requires *any*.

## Analogy

Think of a template as a **form you fill in before knocking on a door**: "Go to `/admin`, and if
the door is open (HTTP 200) or says 'no entry' (403), write it down." VulnProbe visits the door,
reads the response, and notes the result.

## Why read-only?

Real scanners can send dangerous payloads. VulnProbe only sends safe GET/HEAD-style probes, so it
can be run continuously against your own infrastructure without risk.
