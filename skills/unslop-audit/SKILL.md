---
name: unslop-audit
description: Audit a codebase for the production failures typical of AI-generated software - hardcoded secrets, disabled row level security, IDOR and missing authorization, unvalidated inputs, missing error handling and rate limits, N+1 queries and unindexed columns, hallucinated dependencies, duplicated patch-on-patch code, and missing tests or version control. Use when the user asks to audit, review, harden, or production-check a codebase, mentions vibe coding cleanup, asks "is this safe to ship", or is preparing an AI-built app for real users. Read-only - never edits code.
license: MIT
compatibility: Designed for Claude Code. Uses python3 when available and degrades to grep-based scanning when it is not.
---

# unslop-audit

## Overview

AI code generation optimizes for a working demo, not for software that survives
a thousand users. This skill finds the resulting gaps and reports them with
evidence: file, line, the offending snippet, and the concrete way it fails in
production.

The audit is read-only. It never edits code. Remediation is `unslop-fix`.
