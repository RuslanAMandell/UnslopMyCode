# Changelog

Users install the tag named in `.claude-plugin/marketplace.json`. `main` is the
working branch and is never installed directly.

## 0.2.1

- Install clones over HTTPS. The previous release used a source type that
  clones over SSH, which failed on any machine without a key configured.

## 0.2.0

- Releases are pinned to a git tag, so work on `main` no longer reaches users.
- Checks are scoped to the population they apply to: row level security only
  where Supabase is in use, permissive policies only when the grant covers
  writes, credential checks excluding values that are public by design.
- Structure checks skip test and fixture trees, treat scripts with a main guard
  as entrypoints, resolve `@/` path aliases, and apply the size check to source
  files only. Test files still count as importers.
- Commit-history depth is not reported for shallow clones, which is every CI
  checkout.
- Relicensed to Apache 2.0.
- Fixed a marketplace install failure caused by declaring components in both
  `plugin.json` and the marketplace entry.
- `research/verify_sample.py` reports skipped repositories instead of dropping
  them silently.

## 0.1.0

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
