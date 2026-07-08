# ImgScan — LEARN.md

## What problem does ImgScan solve?

Containers bundle hundreds of libraries, and many ship with known CVEs. Trivy scans images and
dependency manifests against vulnerability databases. ImgScan teaches the core loop: **collect a
list of components + versions, then match them against CVE rules.**

## Key concept — version range matching

A CVE rule says "component X below version Y is vulnerable." ImgScan parses version strings into
tuples and compares them (`_version_in_range`). This is the same idea behind every scanner's
database lookup, just minified.

## Analogy

Think of ImgScan as a **recall checker**. You hand it your shopping list (dependencies); it checks
each item against the recall notices (CVE rules) and flags anything on the unsafe list.

## Why offline rules?

Shipping the full NVD is heavy. ImgScan keeps a tiny illustrative rule set and prefers `pip-audit`
when available, so it runs anywhere without network access.
