---
name: unslop-guard
description: Install and run pre-ship guardrails that stop new AI-generated slop from re-entering a codebase - a warn-only pre-commit hook that blocks only on secrets, and a GitHub Actions workflow that runs the unslop audit on pull requests and fails on critical findings. Use when the user asks to prevent regressions, add a pre-commit or CI security check, or gate deploys on an audit.
license: Apache-2.0
---

# unslop-guard

## Overview

Auditing once is a snapshot. This skill installs the two guardrails that keep a
codebase from re-accumulating what the audit just cleared, and provides the
pre-ship gate to run before a deploy.

Both guardrails default to warning rather than blocking. A gate that blocks on
style is a gate people delete, and a deleted gate protects nothing.

## Pre-ship gate

Run the scan, then the gate. This is the only unslop command that exits
non-zero, which is what makes it usable in a deploy script:

```bash
python3 skills/unslop-audit/scripts/scan.py . --out .unslop/findings.json
python3 skills/unslop-audit/scripts/gate.py .unslop/findings.json --fail-on P0
```

`--fail-on` accepts `P0` (default), `P1`, `P2`, or `P3`. `--only S1,S2,S3,S4`
narrows it to a specific set of checks.

## Install the pre-commit hook

```bash
cp skills/unslop-guard/assets/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The hook blocks a commit **only** when a secret is about to be committed
(`S1`-`S4`). Everything else prints as advice and the commit proceeds. Bypass
with `git commit --no-verify`.

The hook needs to find the scanner. It looks at `$UNSLOP_SCAN` first, then the
default plugin install path. Tell the user which one applies to their setup
rather than guessing.

## Install the CI workflow

```bash
mkdir -p .github/workflows
cp skills/unslop-guard/assets/unslop-audit.yml .github/workflows/
```

The workflow runs on pull requests and pushes to `main`, fails only on P0, and
uploads `findings.json` as an artifact so a reviewer can read the full result
without rerunning it. Dependency verification is `continue-on-error` because a
registry outage must not fail someone's build.

## Rules

- Ask before writing into `.git/hooks/` or `.github/workflows/`. Both are
  repository-wide and affect everyone on the team, not just the person asking.
- Never raise the default threshold above P0 without being asked. A CI gate that
  fails on hygiene findings gets disabled within a week.
- If the repository already has a pre-commit hook, do not overwrite it. Show the
  user the snippet to add and let them merge it.
