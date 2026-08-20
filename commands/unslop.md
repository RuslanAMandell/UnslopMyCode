---
description: Audit this codebase for the production failures AI code generation leaves behind, then offer to fix them
---

Run the `unslop-audit` skill on the current repository.

When it finishes, report in chat: the verdict, the blocking findings, and the
three fix-plan counts. Nothing else — do not paste the report into the
conversation; it is written to `.unslop/AUDIT.md`.

Then ask whether to run the fix pass. If yes, run the `unslop-fix` skill.

If `.unslop/findings.json` already exists from a previous run, lead with what
changed since then rather than restating the whole list.
