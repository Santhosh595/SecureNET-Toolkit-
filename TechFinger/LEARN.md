# TechFinger — LEARN.md

## What problem does TechFinger solve?

Before attacking or defending a web app you need to know what it's built from. WhatWeb fingerprints
thousands of technologies from response signatures. TechFinger shows the mechanism with a compact
rule set and regex matching.

## Key concept — signature matching

Each rule pairs a technology with a pattern and a location (header / body / cookie / server).
TechFinger builds per-location "haystacks" once, then runs regexes against the right one. This is
how real fingerprinting tools separate "PHP revealed in a cookie" from "nginx in the Server header."

## Analogy

Think of TechFinger as a **detective reading clues at a doorway**: the doormat (server header),
the welcome mat text (body), and the mailbox label (cookies) each hint at who lives inside.

## Read-only by design

TechFinger only sends a single GET and reads the response — it never probes, fuzzes, or writes.
