# CloudSentry — LEARN.md

## What problem does CloudSentry solve?

Cloud misconfiguration is the #1 cause of breaches (open S3 buckets, root keys, missing MFA).
Tools like Prowler run hundreds of read-only checks against your cloud accounts. CloudSentry shows
the pattern with a small, extensible check registry.

## Key concept — the check registry

Each check is a function decorated with `@register(id, title, severity, provider)`. The engine
loops over registered checks, runs them, and records `PASS` / `WARN` / `FAIL` / `INFO`. To add a
check you write one function and one decorator line — no engine changes.

## Analogy

Think of CloudSentry as a **safety inspector with a clipboard**. For each room (account/resource)
it asks one yes/no question from the list. It never moves furniture — it only reports what it sees.

## Safe by default

No credentials = no API calls = `INFO` results. This guarantees the tool can never accidentally
change cloud state; it only *reads*.
