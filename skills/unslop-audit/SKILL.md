---
name: unslop-audit
description: Audit a codebase for the production failures typical of AI-generated software - hardcoded secrets, disabled row level security, IDOR and missing authorization, unvalidated inputs, missing error handling and rate limits, N+1 queries and unindexed columns, hallucinated dependencies, duplicated patch-on-patch code, and missing tests or version control. Use when the user asks to audit, review, harden, or production-check a codebase, mentions vibe coding cleanup, asks "is this safe to ship", or is preparing an AI-built app for real users. Read-only - never edits code.
license: Apache-2.0
compatibility: Designed for Claude Code. Uses python3 when available and degrades to grep-based scanning when it is not.
---

# unslop-audit

## Overview

AI code generation optimizes for a working demo, not for software that survives
a thousand users. This skill finds the resulting gaps and reports them with
evidence: file, line, the offending snippet, and the concrete way each one fails
in production.

**Never edit code in this skill.** Remediation belongs to `unslop-fix`.

## Procedure

### 1. Scan

The scanner detects the stack itself. Do not ask the user what they built with.

```bash
python3 skills/unslop-audit/scripts/scan.py . --out .unslop/findings.json --json
```

It always exits 0 and always writes a coverage block. If `python3` is missing,
say so plainly and run the reduced pass in
[references/no-python-fallback.md](references/no-python-fallback.md), then record
the reduced coverage in the report.

Add `.unslop/` to `.gitignore` if it is not already there, and tell the user you
did it. The report is a list of live vulnerabilities in their app; committing it
to a public repository would publish the exploit guide.

### 2. Verify before reporting

The scanner emits most findings as `SUSPECTED`. Promote one to `CONFIRMED` only
after opening the file and confirming the defect is real **in context**. Discard
what does not survive that read.

A false positive costs more trust than a missed P3 costs coverage. When you are
not sure, leave it `SUSPECTED` and say why.

For every finding you keep, write the failure scenario in the user's own terms:
what an attacker or a traffic spike actually does. Not "IDOR in the orders
route" but "change 1042 to 1043 in the URL and you read another customer's
order."

### 3. Run the semantic passes

The scanner cannot see intent, and absence of a check is invisible to a regex.
Work through [references/semantic-passes.md](references/semantic-passes.md),
which covers D5, D6, D7, A1, A4, R4, R6, R7, R8, C1, C7, C8, H4, and X4 - plus
P4, which needs the ecosystem's own auditor (`npm audit --json`, `pip-audit`).

Scope the reading to route handlers, server actions, middleware, data-access
modules, and fetching components. Do not read the whole tree.

### 4. Verify dependencies

```bash
python3 skills/unslop-audit/scripts/verify_deps.py . --out .unslop/findings.json
```

This is the only step that uses the network. Offline is fine - it records the
gap and moves on. A dependency that does not resolve is a P0: the model invented
the name, and the first attacker to register it owns your next install.

### 5. Load the stack notes that apply

Read only the notes matching the detected stack:
[supabase](references/stack-notes/supabase.md),
[firebase](references/stack-notes/firebase.md),
[nextjs](references/stack-notes/nextjs.md),
[vercel](references/stack-notes/vercel.md),
[express-node](references/stack-notes/express-node.md),
[python-web](references/stack-notes/python-web.md),
[orm](references/stack-notes/orm.md).

### 6. Report

Write `.unslop/AUDIT.md` in this order: verdict, at most five blocking items,
everything else grouped by domain, the fix plan by class, suspected findings,
coverage, and a short closing section from
[references/prompting-discipline.md](references/prompting-discipline.md).

If a previous `.unslop/findings.json` exists, lead with the diff - "22 fixed, 3
new, 5 unchanged" - instead of restating the whole list.

In chat, say only: the verdict, the blocking findings, the three fix-plan counts,
and the offer to run the fix pass. Do not paste the report into the conversation.

## Rules

- **Evidence or silence.** No finding without a file, a line, and a snippet.
- **Report what you did not scan.** Every cap, skip, and unavailable tool goes in
  the coverage section. A partial scan that reads as clean is the worst outcome
  this skill can produce.
- **Never invent a finding to look thorough**, and never soften a P0 to be
  agreeable. If the app is genuinely fine, say so and list what you checked.
- **Stay in scope.** This is an audit of code that exists, not a redesign.

## Reference

- [Check catalog](references/check-catalog.md) - all 64 checks with severities
- [Semantic passes](references/semantic-passes.md)
- [Prompting discipline](references/prompting-discipline.md)
- [No-python fallback](references/no-python-fallback.md)
