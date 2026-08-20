# unslop-my-code

Audit an AI-generated codebase for the production failures vibe coding leaves
behind — then fix what is safe to fix automatically.

```
Verdict: DO NOT SHIP — 5 critical issues

  D1  Table `profiles` has row level security disabled
      supabase/migrations/0001_init.sql:1
      With RLS off, the public anon key reads and writes every row. This is the
      single most common way vibe-coded apps leak their entire user database.

  D3  service_role key reachable from client code
      src/lib/supabase.ts:4
      The service role key bypasses every RLS policy. Shipped to the browser it
      is a full database takeover.

  ...

  auto     — 9 fixes apply without further input
  assisted — 14 need one answer each
  manual   — 5 need you (credential rotation, dashboard settings)
```

A real, unedited example: [docs/example-report.md](docs/example-report.md).

## Why

AI coding tools produce working demos, not software that survives a thousand
users. The failures are not exotic — they are the same two dozen omissions every
time:

- **45%** of AI-generated code introduces an OWASP Top 10 vulnerability
  ([Veracode, 100+ models](https://www.veracode.com/blog/genai-code-security-report/)),
  at roughly **2.7×** the vulnerability density of human-written code.
- Of 100 audited vibe-coded apps, **41%** exposed secrets, **21%** had no
  authentication on API endpoints, and **12%** shipped database credentials
  readable from the frontend bundle.
- A scan of 1,645 Lovable showcase projects found **170** with inadequate row
  level security, exposing **303** endpoints — names, emails, addresses, payment
  data ([CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757)).
- **86%** of AI samples fail to defend against XSS; **88%** against log injection.
- Frontier models invent package names at **4.6–6.1%**, which is the
  [slopsquatting](https://en.wikipedia.org/wiki/Slopsquatting) attack surface.
- Iterative AI patching measurably *degrades* security with each round
  ([arXiv:2506.11022](https://arxiv.org/pdf/2506.11022)) — "patch the patch" is
  not neutral.

## Install

```
/plugin marketplace add RuslanAMandell/unslop-my-code
/plugin install unslop@unslop-my-code
```

Then, in the repository you want audited:

```
/unslop
```

No configuration, no API key, no `npm install`. The scanner is Python standard
library only, and it detects your stack itself.

## What it checks

64 checks across 10 domains — full list in
[the check catalog](skills/unslop-audit/references/check-catalog.md).

| Domain | Checks | Examples |
|---|---|---|
| **Secrets** and configuration | 6 | Hardcoded keys, secrets behind `NEXT_PUBLIC_`, `.env` not ignored, secrets in history |
| Data and **access control** | 9 | RLS disabled, `using (true)` policies, service_role in the browser, IDOR, public buckets |
| Authentication and session | 6 | Unauthenticated mutations, JWT bypass, cookie flags, no login rate limit, weak hashing |
| Reliability and the **unhappy path** | 9 | No error boundary, unchecked `fetch`, no timeouts, swallowed errors, no validation |
| **Cost** and performance | 8 | N+1 queries, unindexed columns, unbounded selects, aggressive polling, fan-out |
| **Supply chain** | 5 | Hallucinated packages, typosquats, missing lockfile, install scripts |
| **Observability** | 5 | Secrets in logs, stack traces to clients, no error tracking |
| **AI rot** | 8 | Single-commit history, `Component-fixed.tsx` fossils, orphan modules, competing implementations |
| **Deployment** | 5 | Debug mode on, missing security headers, open redirects, unguarded admin routes |
| **Tests** | 3 | No tests, assertion-free tests, no CI |

The **AI rot** domain is the part no other tool looks at: the wreckage left by
iterative prompting rather than by any single bad line of code.

## How it decides

**Severity** — `P0` exploitable now · `P1` exploitable with effort or a
guaranteed cost event · `P2` breaks at scale · `P3` rot that compounds.

**Confidence** — `CONFIRMED` means the code was read and the defect verified;
those are the only findings in the main report. `SUSPECTED` means a pattern
matched but was not confirmed, and lives in an appendix.

**Fix class** — `auto` applies without asking (additive, reversible). `assisted`
needs one answer only you have, such as which column owns a row. `manual` needs
a human, such as rotating a leaked key.

## What it will not do

- It is **not a penetration test** and does not attack running systems.
- It will not rotate a credential for you, and will not pretend it did. Deleting
  a key from HEAD does not un-leak it.
- It will not merge, push, or open a pull request on its own.
- It will not guess at a security boundary. A wrong RLS policy is worse than a
  missing one, because it looks fixed.
- It will not silently narrow its scope. Every cap, skip, and unavailable tool
  is stated in the report's coverage section.

## How it is tested

Two fixtures, both scanned on every commit
([tests/fixtures](tests/fixtures/README.md)):

- **vulnerable-next-supabase** — a Next.js + Supabase app with one planted
  defect per scanner-detectable check. Current recall: **34/34**, with 100%
  required on every P0.
- **clean-next-supabase** — the same app, repaired. Any finding here is a false
  positive. Current count: **0**.

Building those fixtures found nine real detector bugs before any user could hit
them, including a P0 false positive on correct server-only code.

```bash
make check      # unit tests + the precision/recall gate
```

## Prior art

Credit where it is due — these are good tools, and this one is not a replacement
for them:

- [funky-monkey/vibecoding-security-scanner](https://github.com/funky-monkey/vibecoding-security-scanner) — 30+ checks with proof-of-concept exploits
- [AgriciDaniel/claude-cybersecurity](https://github.com/AgriciDaniel/claude-cybersecurity) — parallel specialist agents, OWASP and CWE coverage
- [trailofbits/skills](https://github.com/trailofbits/skills) — professional security research skills
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) — security review as a GitHub Action

Every one of them is a **security** scanner. This one also covers database cost
blowups, unhappy-path gaps, dependency hallucination, and the patch-on-patch rot
that iterative AI development leaves behind. Security is table stakes;
production-readiness is the rest of the job.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every new check needs a catalog entry, a
rule or detector, a planted defect in the vulnerable fixture, a clean
counterpart, and a test. `make check` must pass.

## License

MIT — see [LICENSE](LICENSE).
