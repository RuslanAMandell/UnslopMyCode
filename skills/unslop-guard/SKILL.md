---
name: unslop-guard
description: Install and run pre-ship guardrails that stop new AI-generated slop from re-entering a codebase - a warn-only pre-commit hook that blocks only on secrets, and a GitHub Actions workflow that runs the unslop audit on pull requests and fails on critical findings. Use when the user asks to prevent regressions, add a pre-commit or CI security check, or gate deploys on an audit.
license: MIT
---

# unslop-guard

## Overview

Auditing once is a snapshot. This skill installs the two guardrails that keep the
codebase clean: a pre-commit hook that refuses only commits containing secrets,
and a CI workflow that fails a pull request on P0 findings. Both are opt-in and
both default to warning rather than blocking, because a gate that blocks on
style is a gate people delete.
