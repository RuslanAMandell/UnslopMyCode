# UnslopMyCode Design Spec

**Date:** 2026-08-20
**Status:** Approved for planning
**Repo:** `RuslanAMandell/UnslopMyCode` (public, MIT)

## 1. Problem

AI coding tools ship working demos that fail as production software. The failures
are not exotic — they are the same two dozen omissions every time, because the
model optimizes for "it works for me" rather than "it runs safely for a thousand
users."

Measured evidence:

- 45% of AI-generated code introduces an OWASP Top 10 vulnerability (Veracode,
  100+ models); AI code carries ~2.7x the vulnerability density of human code.
- Of 100 audited vibe-coded apps: 41% exposed secrets or API keys, 21% had no
  authentication on API endpoints, 12% shipped Supabase credentials readable
  straight from the frontend bundle.
- A scan of 1,645 Lovable showcase projects found 170 with inadequate row level
  security, exposing 303 endpoints (names, emails, addresses, payment data,
  third-party keys) — the CVE-2025-48757 pattern.
- 86% of AI samples fail to defend against XSS; 88% against log injection.
- Broken Access Control is A01:2025 and is the single most common flaw in
  AI-generated apps: routes and queries generated with no ownership check.
- Frontier models hallucinate package names at 4.6-6.1%; 127 invented names were
  produced by all five models tested, which is the slopsquatting attack surface.
- Iterative AI patching measurably *degrades* security with each round
  (arXiv 2506.11022) — "patching the patch" is not neutral, it is negative.

Existing tools address the security half only. `vibecoding-security-scanner`,
`vibe-guardian`, `claude-cybersecurity`, `trailofbits/skills`, and
`claude-code-security-review` are all vulnerability scanners. None of them look at
database cost blowups, unhappy-path gaps, dependency hallucination, duplicated
patch-on-patch code, or missing version control. That is the gap this fills.

## 2. What this is

A Claude Code plugin that audits a codebase for the full set of production
failures characteristic of AI-generated software, then fixes what can be fixed
safely and hands back a short list of the decisions only a human can make.

### Non-goals

- Not a replacement for a professional penetration test.
- Not a linter. It does not enforce style, formatting, or naming.
- Not a generic SAST engine. It targets the specific, recurring failure modes of
  AI-generated web applications.
- Not a runtime monitor. Static analysis plus config inspection only.
- Does not perform live exploitation against deployed systems.

## 3. Design principles

These are the acceptance criteria for every decision in this document. A feature
that violates one of them is cut.

1. **One command, one decision.** The user types `/unslop`. They answer at most a
   handful of questions. They do not orchestrate a pipeline.
2. **Zero config.** No config file, no API key, no `npm install`, no flags
   required. Stack is auto-detected.
3. **Never dump.** The report leads with a verdict and the blocking items. Volume
   goes to an appendix and to JSON.
4. **Evidence or silence.** A finding without a file:line, a code snippet, and a
   concrete failure scenario does not get reported at CONFIRMED confidence.
5. **Degrade, never fail.** Missing `python3`, no network, unknown framework,
   giant repo — each downgrades capability and says so. None abort the run.
6. **Honest coverage.** Every skip, cap, or truncation is stated in the report.
   Silent partial coverage reads as "you're clean" and is the worst failure mode
   this tool could have.
7. **Fix what is safe, escalate what is not.** Never guess at a security
   boundary. Never fake an ops action.

## 4. User journeys

### 4.1 First run

```
User: /unslop

→ Detects: Next.js 15 + Supabase + Vercel, pnpm, 214 source files
→ Runs deterministic scan (≈8s)
→ Verifies findings by reading the implicated code
→ Writes .unslop/AUDIT.md and .unslop/findings.json, adds .unslop/ to .gitignore

Verdict: DO NOT SHIP — 3 critical issues

  1. service_role key in src/lib/supabase.ts:4 — bundled to the browser.
     Anyone viewing your site can read and write every table.
  2. Table `profiles` has RLS disabled (supabase/migrations/0002_init.sql:12).
     Every user row is readable by any anon key holder.
  3. GET /api/orders/[id] returns any order by id with no ownership check
     (src/app/api/orders/[id]/route.ts:9). Change 1042 to 1043, read a stranger's
     order.

  Also found: 12 high, 19 medium, 23 hygiene. Full list in .unslop/AUDIT.md.

  I can auto-fix 22 of these safely right now. 6 need one answer from you.
  3 need you to rotate credentials — I cannot do that for you.

  Run the fix pass? [y/N]
```

### 4.2 Fix pass

Creates branch `unslop/fixes`. Applies `auto` class fixes, one commit per
finding, running the project's test command between commits where one exists.
Then presents the `assisted` items as a batch of single questions with a patch
already written for each. Then prints the `manual` checklist. Ends with a
summary and the branch left for the user to review and merge.

### 4.3 Re-run

Diffs against the previous `findings.json`:

```
Since last run: 22 fixed, 3 new, 5 unchanged.
New: hardcoded Stripe key in src/app/checkout/actions.ts:31 (P0)
```

### 4.4 Guard

`/unslop-guard install` writes an opt-in pre-commit hook (warn-only; blocks only
on a secret about to be committed) and a GitHub Action that runs the audit on
pull requests and fails only on P0.

## 5. Architecture

Hybrid: deterministic scanners produce candidates, Claude verifies and performs
the semantic passes that pattern matching cannot.

```
/unslop (command)
   │
   ├─► stack fingerprint ──► loads only the matching stack adapter notes
   │
   ├─► scripts/scan.py  (python3 stdlib only, no network by default)
   │      └─► findings.json : deterministic candidates, each SUSPECTED
   │
   ├─► scripts/verify_deps.py (network, optional, cached)
   │      └─► hallucinated / typosquat / unlockfiled dependencies
   │
   ├─► Claude verification pass
   │      ├─ opens each candidate's file, confirms or discards
   │      └─ promotes SUSPECTED → CONFIRMED with snippet + failure scenario
   │
   ├─► Claude semantic passes (regex cannot do these)
   │      ├─ D5 ownership checks / IDOR
   │      ├─ D6 client-only authorization
   │      ├─ R4 trust-boundary validation
   │      ├─ C1 N+1 query intent
   │      └─ H4 competing implementations of one concern
   │
   └─► report writer ──► .unslop/AUDIT.md + .unslop/findings.json
```

Rationale for hybrid over pure-prompt: reproducibility and testability. The
deterministic layer can be measured against fixtures for precision and recall;
a pure-prompt skill cannot. Rationale for hybrid over multi-agent fan-out: cost
and determinism, with no measurable coverage gain for this check set.

### 5.1 Skills

| Skill | Purpose |
|---|---|
| `unslop-audit` | Fingerprint, scan, verify, report. Never edits code. |
| `unslop-fix` | Apply fixes from a report by fix class, on a branch, per-finding commits. |
| `unslop-guard` | Install pre-commit hook + CI workflow; run as a pre-ship gate. |

`commands/unslop.md` is the single front door and chains audit → offer → fix.
The skills remain independently invocable for composition.

## 6. Check catalog

64 checks across 10 domains. Each check has a stable ID, a severity, a fix class,
and a detection method (`static` = scanner, `semantic` = Claude, `config` = file
parse, `net` = registry lookup).

### Severity

| Level | Meaning |
|---|---|
| P0 | Exploitable now, or actively leaking. Blocks ship. |
| P1 | Exploitable with modest effort, or a guaranteed outage/cost event. |
| P2 | Breaks at scale, burns money, or loses data under load. |
| P3 | Rot and hygiene. Compounds into future P0s. |

### Confidence

`CONFIRMED` (code read and verified) → main report. `SUSPECTED` (pattern matched,
unverified or ambiguous) → appendix. Nothing is reported without one of the two.

### Fix class

`auto` (additive, reversible, no happy-path behavior change) · `assisted`
(patch written, needs one human fact) · `manual` (ops or judgment action).

### S — Secrets and configuration

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| S1 | Hardcoded provider credentials (`sk-`, `AKIA`, `ghp_`, `service_role` JWT, `-----BEGIN * PRIVATE KEY`) plus high-entropy string heuristic | P0 | manual | static |
| S2 | Sensitive value behind a client-exposed prefix (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`) | P0 | assisted | static |
| S3 | `.env`, `.env.local`, `*.pem`, `credentials.json` not covered by `.gitignore` | P0 | auto | config |
| S4 | Secret present in git history even if removed from HEAD | P0 | manual | static |
| S5 | Env vars referenced in code but absent from `.env.example` (deploy-time surprise) | P2 | auto | static |
| S6 | Source maps emitted to production build output | P2 | auto | config |

### D — Data layer and access control

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| D1 | Table created without RLS enabled (Supabase/Postgres migrations) | P0 | assisted | config |
| D2 | RLS policy that is effectively open (`USING (true)`, `TO public` on write) | P0 | assisted | config |
| D3 | `service_role` / admin key referenced from client-reachable code | P0 | assisted | static |
| D4 | Storage bucket set public, or no bucket policy | P0 | assisted | config |
| D5 | Route fetches a record by user-supplied id with no ownership predicate (IDOR) | P0 | assisted | semantic |
| D6 | Authorization enforced only in client components; server route unguarded | P0 | assisted | semantic |
| D7 | Request body spread directly into an insert/update (mass assignment) | P1 | assisted | semantic |
| D8 | SQL built by string interpolation of user input | P0 | assisted | static |
| D9 | Firestore/Firebase rules allow read/write true | P0 | assisted | config |

### A — Authentication and session

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| A1 | Mutating API route with no authentication check | P0 | assisted | semantic |
| A2 | JWT verification skipped, `alg: none` accepted, or default/empty secret | P0 | assisted | static |
| A3 | Session cookie missing `httpOnly` / `secure` / `sameSite` | P1 | auto | static |
| A4 | No rate limit on login, signup, or password reset | P1 | assisted | semantic |
| A5 | `CORS: *` combined with credentials, or wildcard on an authenticated API | P1 | auto | static |
| A6 | Password stored without a modern KDF, or a hand-rolled hash | P0 | assisted | static |

### R — Reliability and the unhappy path

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| R1 | No React error boundary anywhere in the tree | P1 | auto | static |
| R2 | `fetch`/HTTP call with no response status check | P1 | assisted | static |
| R3 | Network call with no timeout and no abort signal | P1 | auto | static |
| R4 | No schema validation at a trust boundary (route handler / server action) | P1 | assisted | semantic |
| R5 | Empty `catch`, or catch that only logs and continues into the happy path | P1 | assisted | static |
| R6 | No rate limiting on any public endpoint | P1 | assisted | semantic |
| R7 | UI fetch path with no loading and no error state | P2 | assisted | semantic |
| R8 | Unbounded list render / no pagination on a growing collection | P2 | assisted | semantic |
| R9 | Unhandled promise rejection / floating promise on a critical path | P2 | auto | static |

### C — Cost and performance

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| C1 | Awaited query inside a loop (N+1) | P2 | assisted | semantic |
| C2 | Column used in `where`/`join`/`order by` with no matching index in migrations | P2 | auto | static |
| C3 | Unbounded `select *` with no `limit` on a growing table | P2 | assisted | static |
| C4 | Unbounded loop, recursion, or `while(true)` inside a serverless handler | P1 | assisted | static |
| C5 | Sub-30s `setInterval` polling an API or database | P2 | assisted | static |
| C6 | No cache headers or revalidation on a cacheable route | P2 | assisted | static |
| C7 | No concurrency cap / no batching on a fan-out call site | P2 | assisted | semantic |
| C8 | Full-table read used to compute a count or aggregate | P2 | assisted | semantic |

### P — Supply chain

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| P1 | Dependency that does not exist on the registry (hallucinated package) | P0 | manual | net |
| P2 | Dependency one edit-distance from a far more popular package (typosquat) | P1 | manual | net |
| P3 | No lockfile, or lockfile out of sync with the manifest | P1 | auto | config |
| P4 | Known CVEs reported by the ecosystem audit tool | P1 | assisted | net |
| P5 | Dependency with an install/postinstall script | P2 | manual | config |

### O — Observability

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| O1 | Secret, token, or PII passed to a log call | P0 | auto | static |
| O2 | Stack trace or internal error returned in an HTTP response body | P1 | auto | static |
| O3 | `console.log` used as production logging; no structured logger | P3 | assisted | static |
| O4 | No error tracking integration | P2 | manual | config |
| O5 | No health check endpoint | P3 | auto | config |

### H — AI rot

The differentiating domain. These are artifacts of how the code was produced.

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| H1 | No git repository, or entire codebase in a single commit | P1 | auto | config |
| H2 | Near-duplicate files (`X-fixed.tsx`, `X-new.ts`, `X2.py`, `X copy.js`) — patch-on-patch fossils | P2 | assisted | static |
| H3 | Orphan module: nothing imports it, not an entrypoint | P3 | assisted | static |
| H4 | Competing implementations of one concern (multiple auth helpers, two HTTP clients, two ORMs, two state libraries) | P2 | assisted | semantic |
| H5 | Mock data, stub, or `TODO`/`FIXME` on a production code path | P1 | assisted | static |
| H6 | Large commented-out code blocks | P3 | auto | static |
| H7 | File over the size threshold (default 600 lines) — the context-rot signal | P3 | manual | static |
| H8 | Copy-pasted logic block repeated 3+ times with edits | P3 | assisted | static |

### X — Deployment and headers

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| X1 | Debug mode enabled, or `NODE_ENV` not production in deploy config | P1 | auto | config |
| X2 | Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) | P1 | auto | config |
| X3 | Redirect target taken from user input (open redirect) | P1 | assisted | static |
| X4 | Admin or internal route with no guard | P0 | assisted | semantic |
| X5 | Preview/staging deployment with no access protection | P1 | manual | config |

### T — Tests

| ID | Check | Sev | Fix | Method |
|---|---|---|---|---|
| T1 | No test files, or a test script that is a placeholder | P2 | manual | config |
| T2 | Test files that contain no assertions | P3 | manual | static |
| T3 | No CI workflow | P2 | auto | config |

### Prompt discipline

Not a check. `references/prompting-discipline.md` plus a short closing section in
the report explaining the production process that avoids re-accumulating the
findings: specify schema, authorization model, and error contract before
generating; decompose instead of mega-prompting; commit a checkpoint before each
prompt; when a fix fails twice, revert and re-specify rather than stacking a
third patch (grounded in the measured security degradation of iterative
patching).

## 7. Report format

`.unslop/AUDIT.md`:

1. **Verdict** — one line. `DO NOT SHIP`, `SHIP WITH CAUTION`, or `CLEAR`.
2. **Blocking** — at most 5 items. Each: what, file:line, snippet, the concrete
   failure scenario in plain language, the fix, the fix class.
3. **Fix plan** — counts by class: auto / assisted / manual.
4. **Everything else** — grouped by domain, one line each, collapsed.
5. **Suspected** — unverified candidates, clearly labeled.
6. **Coverage** — what was scanned, what was skipped and why, what was capped.
7. **How not to get here again** — the prompt-discipline section.

`.unslop/findings.json` carries the full structured set for tooling and for the
re-run diff. Schema is versioned (`schemaVersion`).

`.unslop/` is added to `.gitignore` on first run. The report enumerates live
vulnerabilities; committing it to a public repository would be a disclosure.

## 8. Fix protocol

1. Refuse to run on a dirty working tree without explicit confirmation.
2. Create branch `unslop/fixes` from HEAD.
3. Apply all `auto` fixes. One commit per finding, message `fix(unslop): <ID> <summary>`.
4. If a test command exists, run it after each commit. A failing test reverts
   that commit and reclassifies the finding as `assisted`.
5. Present `assisted` findings as single questions, each with the patch already
   written. Apply on confirmation.
6. Print the `manual` checklist with exact instructions (which key to rotate,
   which dashboard setting to change).
7. Never rewrite a security boundary on a guess. Never claim a credential was
   rotated. Deleting a committed secret from HEAD does not rotate it, and the
   report says so.
8. Summary: what changed, what did not, what the user still owns.

## 9. Scanner implementation

- `python3` standard library only. No pip install, ever.
- Walks the tree honoring `.gitignore` plus a built-in ignore set
  (`node_modules`, `.next`, `dist`, `build`, `venv`, `.venv`, `target`,
  `vendor`, `.git`, binary and minified files).
- Per-file size cap (default 2 MB) and total file cap (default 20,000), both
  reported when hit.
- Emits `findings.json` with `schemaVersion`, per-finding `id`, `severity`,
  `confidence`, `fixClass`, `file`, `line`, `snippet`, `evidence`.
- Target: under 15 seconds on a 1,000-file repository.
- `verify_deps.py` is the only network user: batched registry lookups, on-disk
  cache, hard timeout, and a clean skip with a coverage note when offline.
- If `python3` is unavailable, the skill runs a reduced grep/ripgrep pass and
  states the reduced coverage in the report.

## 10. Stack adapters

`references/stack-notes/` holds per-stack specifics, loaded only when the
fingerprint matches: `supabase.md`, `firebase.md`, `nextjs.md`, `vercel.md`,
`express-node.md`, `python-fastapi-django.md`, `prisma-drizzle.md`.

Fingerprinting reads manifests, lockfiles, config files, and directory shape. An
unrecognized stack still gets every stack-agnostic check, with the gap noted.

## 11. Testing

Credibility rests on this section.

- `tests/fixtures/vulnerable-next-supabase/` — a real, runnable Next.js +
  Supabase app with every planted defect documented in `expected.json`
  (check ID → file → line).
- `tests/fixtures/clean-next-supabase/` — the same app, corrected. Any finding
  here is a false positive.
- `tests/run-tests.sh` computes precision and recall against both fixtures and
  fails CI if recall on P0 checks drops below 100% or precision on the clean
  fixture drops below 95%.
- Fixture apps carry a prominent `README` marking them intentionally vulnerable,
  are excluded from any published package, and contain no real credentials —
  only obviously fake, non-resolvable values.
- `make check` runs frontmatter validation, scanner unit tests, and the fixture
  suite locally, mirroring CI.

## 12. Repository structure

```
UnslopMyCode/
├── .claude-plugin/{marketplace.json,plugin.json}
├── commands/unslop.md
├── skills/
│   ├── unslop-audit/{SKILL.md,references/,scripts/,assets/}
│   ├── unslop-fix/{SKILL.md,references/}
│   └── unslop-guard/{SKILL.md,assets/{pre-commit,unslop.yml}}
├── tests/{fixtures/,run-tests.sh}
├── .github/workflows/ci.yml
├── AGENTS.md CONTRIBUTING.md README.md LICENSE CHANGELOG.md Makefile
└── docs/superpowers/specs/
```

Conformance to the Agent Skills spec: `name` matches the directory, lowercase and
hyphenated; `description` states what and when with trigger keywords; each
`SKILL.md` stays under 500 lines with detail pushed to `references/`.

## 13. Distribution

```
/plugin marketplace add RuslanAMandell/UnslopMyCode
/plugin install unslop@unslop-my-code
```

Also usable by copying `skills/unslop-audit/` into `~/.claude/skills/`. MIT
licensed. Versioned in `plugin.json` with a maintained `CHANGELOG.md`.

## 14. Failure modes and degradation

| Condition | Behavior |
|---|---|
| No `python3` | Reduced grep pass; coverage gap stated |
| No network | Dependency checks skipped; stated |
| Unknown stack | Stack-agnostic checks only; stated |
| Repo over file cap | Scans to cap, names what was skipped |
| Dirty working tree at fix time | Refuses without explicit confirmation |
| Test command fails pre-existing | Fix pass records the baseline and does not attribute the failure to its own commits |
| No findings | `CLEAR` verdict plus an explicit list of what was checked, so it never reads as an empty scan |

## 15. Milestones

1. Repo skeleton, plugin manifests, README, LICENSE, CI wiring.
2. `scan.py` with the `static`/`config` checks; `findings.json` schema.
3. Vulnerable and clean fixtures; precision/recall harness in CI.
4. `unslop-audit` SKILL.md, verification pass, semantic passes, report writer.
5. `verify_deps.py` and the supply-chain domain.
6. `unslop-fix` with the fix-class protocol.
7. `unslop-guard`, hook and Action templates.
8. Stack adapter notes; prompt-discipline reference.
9. Docs pass, example report, publish public.
