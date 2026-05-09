# bounty-brain

Practical bug bounty reference sheets, hunting notes, and methodology breakdowns.

This repo is where I consolidate what I learn from labs, real hunting sessions, writeups, and manual testing into focused guides for specific vulnerability classes.

The goal is not to create generic cheat sheets.

The goal is to build useful mental models for finding real bugs.

---

## Current Topics

### IDOR / Broken Access Control

A practical master class sheet focused on understanding IDOR beyond simply changing IDs in URLs.

Covers:

- Core IDOR mental model
- Direct and indirect references
- Read-time vs write-time IDOR
- Second-order access control issues
- Object references
- Testing methodology
- Real hunting checklist

### XSS

A focused XSS sheet covering quick reference concepts, sources/sinks, and an automation pipeline for reflected and DOM XSS testing.

Covers:

- Reflected XSS
- Stored XSS
- DOM XSS
- Sources and sinks
- Endpoint collection
- Parameter filtering
- Manual validation workflow

---

## Why This Exists

I’m building LoganSec in public while learning bug bounty hunting and web application security.

Instead of letting notes stay scattered across videos, labs, writeups, and hunting sessions, I use this repo to turn them into structured references I can actually reuse.

---

## Focus Areas

- Bug bounty methodology
- Web application security
- Recon and attack surface mapping
- IDOR / Broken Access Control
- XSS
- Business logic testing
- Authentication and authorization flows
- Practical hunting workflows

---

## Disclaimer

Everything in this repository is for educational purposes and authorized security testing only.

Do not test systems you do not own or do not have explicit permission to assess.
