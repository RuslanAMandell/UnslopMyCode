---
name: unslop-fix
description: Apply remediations from an unslop audit report. Fixes mechanically safe issues automatically on a dedicated branch with one commit per finding, proposes patches for issues that need a single human decision, and lists the credential rotations and dashboard changes that only a person can perform. Use after unslop-audit, or when the user asks to fix, remediate, harden, or clean up the findings from a codebase audit.
license: MIT
---

# unslop-fix

## Overview

Applies the fix plan from `.unslop/findings.json`, split by fix class. Never
rewrites a security boundary on a guess, and never claims an action it did not
perform.

## Preconditions

1. `.unslop/findings.json` exists. If not, run `unslop-audit` first.
2. The working tree is clean. On a dirty working tree, stop and ask - an
   interleaved diff is unreviewable, and unreviewable changes are the failure
   mode this whole plugin exists to prevent.
3. Record whether the project's test command already passes. A failure that
   predates your work must not be attributed to your commits.
4. Create and switch to `unslop/fixes`.

## Pass 1 - `auto`

Apply every `auto` finding without asking per item. **One commit per finding**,
message `fix(unslop): <ID> <short summary>`.

If a test command exists, run it after each commit. On failure: revert that one
commit, reclassify the finding as `assisted`, and keep going. Do not debug
someone else's failing test inside a fix pass.

Recipes: [references/fix-recipes.md](references/fix-recipes.md).

## Pass 2 - `assisted`

For each finding, give the user, in one message: the finding, the single
question you need answered, and the patch you will apply once answered. Batch
the questions so they can be answered in one sitting.

Never guess an ownership column, a role model, or an allowed origin. If the
answer is not in the codebase and the user has not given it, the finding stays
open and goes in the summary. A wrong RLS policy is worse than a missing one,
because it looks fixed.

## Pass 3 - `manual`

Print the checklist. For each item: what to do, where, and why nobody else can
do it.

Credential rotation is the common case, and it is the one place where a
convincing-looking fix is a lie. **Deleting it from HEAD does not rotate it** -
the value is still in the history and in every clone anyone has already made.
Say that explicitly. Never write "rotated" for something you did not rotate.

## Close

Summarize three numbers: fixed, deferred, still owned by the user. Leave the
branch for review. Do not merge, do not push, and do not open a pull request
unless asked.

## Rules

- One concern per commit. A fix that touches a second concern is two commits.
- No refactoring alongside a fix. Adjacent mess is out of scope.
- If a fix has **failed twice**, revert and hand it to the user with what you
  learned. Do not stack a third attempt. Stacking patches is the behavior that
  produced these findings in the first place.
- Prefer the smallest change that closes the finding. This is not the moment to
  upgrade a framework.
