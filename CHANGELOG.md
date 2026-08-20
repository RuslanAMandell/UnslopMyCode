# Changelog

## 0.1.0 (unreleased)

First release. Licensed under Apache 2.0.

- 64 checks across 10 domains: secrets, data and access control, authentication,
  reliability, cost and performance, supply chain, observability, AI rot,
  deployment, and tests.
- `unslop-audit`: read-only scan, verification pass, semantic passes, and a
  verdict-first report with a coverage section.
- `unslop-fix`: remediation split by fix class (`auto` / `assisted` / `manual`),
  on a dedicated branch, one commit per finding.
- `unslop-guard`: severity gate, warn-only pre-commit hook that blocks only on
  secrets, and a GitHub Actions workflow.
- `/unslop` command as the single front door.
- Dependency verification against the npm and PyPI registries, with
  Damerau-Levenshtein typosquat detection and offline degradation.
- Vulnerable and clean fixtures with a precision/recall gate in CI: 34/34 recall
  on planted defects, zero false positives on the clean twin.
