---
name: unslop-fix
description: Apply remediations from an unslop audit report. Fixes mechanically safe issues automatically on a dedicated branch with one commit per finding, proposes patches for issues that need a single human decision, and lists the credential rotations and dashboard changes that only a person can perform. Use after unslop-audit, or when the user asks to fix, remediate, harden, or clean up the findings from a codebase audit.
license: MIT
---

# unslop-fix

## Overview

Applies the fix plan produced by `unslop-audit`, split by fix class: `auto`
changes land without per-item prompting, `assisted` changes are proposed with a
written patch and applied on confirmation, and `manual` items are listed with
exact instructions. Never rewrites a security boundary on a guess.
