# UnslopMyCode

[![ci](https://github.com/RuslanAMandell/UnslopMyCode/actions/workflows/ci.yml/badge.svg)](https://github.com/RuslanAMandell/UnslopMyCode/actions/workflows/ci.yml)
[![checks](https://img.shields.io/badge/checks-64-blue)](skills/unslop-audit/references/check-catalog.md)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#)
[![license](https://img.shields.io/badge/license-Apache--2.0-black)](LICENSE)

**Find the production failures your AI coding tool left behind, then fix the safe ones automatically.**

A Claude Code plugin. 64 checks for exposed secrets, disabled row level security,
IDOR, missing error handling, runaway query costs, hallucinated packages, and the
duplicate-file rot that iterative prompting leaves in a codebase.

```bash
/plugin marketplace add RuslanAMandell/UnslopMyCode
/plugin install unslop@unslop-my-code
```

Then, in the repo you want checked:

```bash
/unslop
```

No config file. No API key. No install step. The scanner is Python standard
library only and detects your stack itself.

## What it looks like

```
Verdict: DO NOT SHIP, 5 critical issues

  D1  Table `profiles` has row level security disabled
      supabase/migrations/0001_init.sql:1
      With RLS off, the public anon key reads and writes every row. This is the
      most common way vibe-coded apps leak their entire user database.

  D3  service_role key reachable from client code
      src/lib/supabase.ts:4
      The service role key bypasses every RLS policy. Shipped to the browser it
      is a full database takeover.

  auto      9 fixes apply with no further input
  assisted  14 need one answer each
  manual    5 need you (credential rotation, dashboard settings)

  Run the fix pass? [y/N]
```

Full unedited example: [docs/example-report.md](docs/example-report.md).

## What it checks

64 checks, 10 domains. [Full catalog](skills/unslop-audit/references/check-catalog.md).

| Domain | # | Examples |
|---|---|---|
| **Secrets** | 6 | Hardcoded keys, secrets behind `NEXT_PUBLIC_`, `.env` not ignored, secrets in git history |
| Data and **access control** | 9 | RLS off, `using (true)` policies, service_role in the browser, IDOR, public buckets |
| Auth and session | 6 | Unauthenticated mutations, JWT bypass, cookie flags, no login rate limit, weak hashing |
| The **unhappy path** | 9 | No error boundary, unchecked `fetch`, no timeouts, swallowed errors, no validation |
| **Cost** and performance | 8 | N+1 queries, unindexed columns, unbounded selects, 2s polling, uncapped fan-out |
| **Supply chain** | 5 | Packages that do not exist, typosquats, missing lockfile, install scripts |
| **Observability** | 5 | Secrets in logs, stack traces sent to clients, no error tracking |
| **AI rot** | 8 | One-commit history, `Component-fixed.tsx` fossils, orphan modules, two ORMs |
| **Deployment** | 5 | Debug mode on, missing security headers, open redirects, unguarded admin routes |
| **Tests** | 3 | No tests, tests with no assertions, no CI |

Most tools in this space check the first three rows. **AI rot**, **cost**, and
**supply chain** are what iterative prompting actually breaks, and they are the
reason this exists.

## What we found running it on 280 real apps

We pointed it at 280 public repositories built with Lovable, Bolt, and v0, and
read 83,955 files. Full numbers in [research/results/REPORT.md](research/results/REPORT.md).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="research/results/domains-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="research/results/domains-light.svg">
  <img alt="Bar chart: share of 280 AI-generated repositories with at least one finding per domain. Tests 96.4%, AI rot 88.9%, Observability 77.9%, Unhappy path 77.1%, Deployment 71.8%, Supply chain 55.7%, Secrets 52.1%, Cost 37.1%, Auth 20.7%, Data and access control 14.6%." src="research/results/domains-light.svg">
</picture>

| | |
|---|---|
| **27.5%** | ship at least one critical, exploitable issue |
| **64.4%** | of the Supabase apps do (45 repos) |
| **10.7%** | committed a `.env` file to a public repo |
| **10.4%** | hardcoded a real provider credential in source |
| **6.8%** | created database tables with row level security never enabled |
| **46** | findings in the median repo |

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="research/results/critical-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="research/results/critical-light.svg">
  <img alt="Bar chart: share of 280 repositories shipping each critical defect. Committed .env file 10.7%, hardcoded credential 10.4%, tables without row level security 6.8%, SQL string interpolation 6.8%, secrets in logs 6.1%, permissive RLS policy 5.4%." src="research/results/critical-light.svg">
</picture>

Every figure is hand-verified. Findings were sampled at random per critical
check across three rounds and read individually, and each check is locked behind
regression tests built from real repository code. Sampling, scoping decisions,
and the limits of what these numbers support are documented in
[research/METHOD.md](research/METHOD.md).

Reproduce it yourself in about four minutes:

```bash
python3 research/collect_corpus.py --per-marker 100 > research/corpus.txt
python3 research/corpus_scan.py research/corpus.txt --workers 10
```

Aggregates only. Per-repository results are never published, because a public
map of which repo leaks which key is a disclosure, not a study.

### Corroborating research

| | |
|---|---|
| **45%** | of AI-generated code introduces an OWASP Top 10 flaw ([Veracode](https://www.veracode.com/blog/genai-code-security-report/)) |
| **170** | of 1,645 Lovable projects shipped without row level security ([CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757)) |
| **5%** | of package names in frontier-model output do not exist ([slopsquatting](https://en.wikipedia.org/wiki/Slopsquatting)) |

Asking the model to patch its own bug makes security *worse* with each round
([arXiv:2506.11022](https://arxiv.org/pdf/2506.11022)). That is why the report
ends with how to stop generating these in the first place.

## How it decides

**Severity.** `P0` exploitable now. `P1` exploitable with effort. `P2` breaks at
scale. `P3` rot that compounds.

**Confidence.** `CONFIRMED` means the code was opened and the defect verified.
Only those reach the main report. `SUSPECTED` goes in an appendix.

**Fix class.** `auto` applies without asking. `assisted` needs one answer only
you have, like which column owns a row. `manual` needs a human, like rotating a
key.

## What it will not do

- It is **not a penetration test** and never touches a running system.
- It will not rotate your credentials, and will not pretend it did. Deleting a
  key from HEAD does not un-leak it.
- It will not merge, push, or open a PR on its own.
- It will not guess at a security boundary. A wrong RLS policy is worse than a
  missing one, because it looks fixed.
- It will not quietly narrow its scope. Every skip and cap is printed in the
  report's coverage section.

## Tested

Two fixture apps, scanned on every commit ([details](tests/fixtures/README.md)):

| Fixture | Result |
|---|---|
| One planted defect per detectable check | **34 of 34** found, 100% required on every P0 |
| The same app, repaired | **0** findings. Any hit is a false positive and fails CI |

Building those fixtures caught nine real detector bugs before release, including
a P0 that fired on correct server-only code.

```bash
make check   # unit tests plus the precision and recall gate
```

## Also included

- `unslop-fix` applies the fix plan on a branch, one commit per finding, running
  your tests between each.
- `unslop-guard` installs a pre-commit hook that blocks only on secrets, plus a
  CI workflow that fails only on P0. Gates people delete protect nothing.

## Prior art

Good tools, all security-focused. This one adds cost, reliability, supply chain,
and rot.

- [funky-monkey/vibecoding-security-scanner](https://github.com/funky-monkey/vibecoding-security-scanner)
- [AgriciDaniel/claude-cybersecurity](https://github.com/AgriciDaniel/claude-cybersecurity)
- [trailofbits/skills](https://github.com/trailofbits/skills)
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review)

## Contributing

Every new check needs a catalog entry, a detector, a planted defect, a clean
counterpart, and a test. See [CONTRIBUTING.md](CONTRIBUTING.md).

Licensed under the [Apache License 2.0](LICENSE).
