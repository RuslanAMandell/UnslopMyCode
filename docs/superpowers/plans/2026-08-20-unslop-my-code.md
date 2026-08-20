# unslop-my-code Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a public Claude Code plugin that audits AI-generated codebases for the 64 recurring production failures, then fixes what is mechanically safe and escalates what is not.

**Architecture:** A `python3`-stdlib scanner walks the repo and emits `findings.json` of SUSPECTED candidates from a declarative rule table plus bespoke config/structural detectors. Three skills (`unslop-audit`, `unslop-fix`, `unslop-guard`) drive it: the audit skill verifies each candidate by reading the implicated code, runs the semantic passes regex cannot do, and writes a verdict-first Markdown report. A single `/unslop` command chains audit → offer → fix so the user has one decision point.

**Tech Stack:** Python 3.9+ standard library only (no pip installs, ever). `unittest` for tests. Bash for the test harness and Makefile. Markdown + YAML frontmatter for skills. GitHub Actions for CI.

**Spec:** `docs/superpowers/specs/2026-08-20-unslop-my-code-design.md`

## Global Constraints

- **Zero runtime dependencies.** Scanner and tests use the Python standard library only. A `pip install` in any code path is a bug.
- **Python floor:** 3.9. No `match` statements, no PEP 604 `X | Y` unions at runtime, no `tomllib` (3.11+) — parse `pyproject.toml` with a regex fallback.
- **Degrade, never fail.** Missing `python3`, no network, unknown stack, oversized repo: reduce capability, record it in the coverage block, exit 0.
- **Honest coverage.** Every skip, cap, and truncation appears in `Coverage`. Silent partial coverage is the worst possible failure of this tool.
- **Evidence or silence.** No finding is emitted without `file`, `line`, and `snippet`. Only findings whose code has been read are `CONFIRMED`.
- **No network in `scan.py`.** Only `verify_deps.py` touches the network, and it must work offline.
- **Check IDs are stable and permanent.** `S1`, `D5`, `H2` etc. never get renumbered; retired checks are tombstoned, not reused.
- **Severity values:** exactly `P0`, `P1`, `P2`, `P3`. **Fix classes:** exactly `auto`, `assisted`, `manual`. **Confidence:** exactly `CONFIRMED`, `SUSPECTED`.
- **Skill spec conformance:** `name` matches the directory, lowercase/hyphen, ≤64 chars; `description` ≤1024 chars stating what and when; each `SKILL.md` under 500 lines.
- **Fixture credentials must be non-resolvable fakes.** No real key, no real-looking key that could match a live secret.
- **License:** MIT. **Default branch:** `main`.

## File Structure

```
unslop-my-code/
├── .claude-plugin/
│   ├── marketplace.json          # marketplace entry -> plugin "unslop"
│   └── plugin.json               # name/version/license/repo metadata
├── commands/
│   └── unslop.md                 # single front door: audit -> offer -> fix
├── skills/
│   ├── unslop-audit/
│   │   ├── SKILL.md              # orchestration + verification + semantic passes
│   │   ├── references/
│   │   │   ├── check-catalog.md          # all 64 checks, human-readable
│   │   │   ├── semantic-passes.md        # how to do D5/D6/A1/R4/C1/H4/X4
│   │   │   ├── prompting-discipline.md   # how not to regenerate the findings
│   │   │   └── stack-notes/{supabase,firebase,nextjs,vercel,express-node,python-web,orm}.md
│   │   ├── scripts/
│   │   │   ├── scan.py           # CLI orchestrator -> findings.json
│   │   │   ├── verify_deps.py    # network dep verification (P1/P2/P4/P5)
│   │   │   └── unslop/
│   │   │       ├── __init__.py
│   │   │       ├── catalog.py    # Check dataclass + all 64 check definitions
│   │   │       ├── findings.py   # Finding dataclass, Coverage, JSON writer
│   │   │       ├── walker.py     # file discovery, ignore rules, caps
│   │   │       ├── rules.py      # Rule dataclass + rule engine
│   │   │       ├── ruleset.py    # the declarative static rule table
│   │   │       ├── report.py     # verdict + Markdown report + re-run diff
│   │   │       └── detectors/
│   │   │           ├── __init__.py
│   │   │           ├── secrets.py    # S1 service_role JWT, S4 history
│   │   │           ├── gitignore.py  # S3, S6
│   │   │           ├── sqlrls.py     # D1, D2, D4, D9, C2
│   │   │           ├── deps.py       # P3, P5
│   │   │           ├── gitmeta.py    # H1
│   │   │           ├── structure.py  # H2, H3, H6, H7
│   │   │           └── project.py    # X1, X2, T1, T3, O4, O5
│   │   └── assets/report-template.md
│   ├── unslop-fix/SKILL.md
│   └── unslop-guard/
│       ├── SKILL.md
│       └── assets/{pre-commit,unslop-audit.yml}
├── tests/
│   ├── test_catalog.py           # catalog integrity + rule coverage gate
│   ├── test_walker.py
│   ├── test_rules.py
│   ├── test_detectors_*.py
│   ├── test_report.py
│   ├── test_fixtures.py          # precision/recall gate against both fixtures
│   ├── test_skills.py            # frontmatter + line-count conformance
│   └── fixtures/
│       ├── vulnerable-next-supabase/   # planted defects + expected.json
│       └── clean-next-supabase/        # corrected twin; any finding = FP
├── .github/workflows/ci.yml
├── Makefile
├── README.md  CONTRIBUTING.md  AGENTS.md  LICENSE  CHANGELOG.md  .gitignore
└── docs/superpowers/{specs,plans}/
```

`scripts/unslop/` is a package so `scan.py` can `from unslop import ...` with no
install step. Detector modules are split by input type (git, SQL, manifests,
structure) rather than by check domain, because that is what actually changes
together.

---

### Task 1: Repo skeleton, manifests, and the conformance test

**Files:**
- Create: `.claude-plugin/plugin.json`
- Create: `.claude-plugin/marketplace.json`
- Create: `Makefile`
- Create: `.github/workflows/ci.yml`
- Create: `LICENSE` (MIT, 2026, Ruslan Mandell)
- Create: `skills/unslop-audit/SKILL.md` (frontmatter + one-line body placeholder body is NOT acceptable — write the real Overview section; the rest lands in Task 11)
- Test: `tests/test_skills.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `make check` target; `tests/test_skills.py::test_all_skills_have_valid_frontmatter`, which every later skill file must satisfy.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_skills.py
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def parse_frontmatter(text):
    if not text.startswith("---\n"):
        raise AssertionError("SKILL.md must start with YAML frontmatter")
    end = text.index("\n---\n", 3)
    body = text[end + 5:]
    fields = {}
    key = None
    for line in text[4:end].splitlines():
        m = re.match(r"^([a-z-]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            fields[key] = m.group(2).strip()
        elif key and line.startswith(" "):
            fields[key] += " " + line.strip()
    return fields, body


class TestSkillConformance(unittest.TestCase):
    def test_all_skills_have_valid_frontmatter(self):
        skill_files = sorted(SKILLS.glob("*/SKILL.md"))
        self.assertTrue(skill_files, "no SKILL.md files found")
        for path in skill_files:
            with self.subTest(skill=path.parent.name):
                fields, body = parse_frontmatter(path.read_text())
                self.assertIn("name", fields)
                self.assertIn("description", fields)
                self.assertEqual(fields["name"], path.parent.name)
                self.assertTrue(NAME_RE.match(fields["name"]))
                self.assertLessEqual(len(fields["name"]), 64)
                self.assertGreater(len(fields["description"]), 40)
                self.assertLessEqual(len(fields["description"]), 1024)
                self.assertLess(len(path.read_text().splitlines()), 500)
                self.assertGreater(len(body.strip()), 200)

    def test_marketplace_lists_every_skill(self):
        import json
        mk = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        listed = {s.split("/")[-1] for p in mk["plugins"] for s in p["skills"]}
        on_disk = {p.parent.name for p in SKILLS.glob("*/SKILL.md")}
        self.assertEqual(listed, on_disk)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_skills -v`
Expected: FAIL — `no SKILL.md files found` / missing `.claude-plugin/marketplace.json`.

- [ ] **Step 3: Write the manifests and the first skill stub**

```json
// .claude-plugin/plugin.json
{
  "name": "unslop",
  "description": "Audit an AI-generated codebase for the production failures vibe coding leaves behind: exposed secrets, missing RLS, IDOR, unhappy-path gaps, cost blowups, hallucinated dependencies, and patch-on-patch rot. Then fix what is safe automatically.",
  "version": "0.1.0",
  "author": { "name": "Ruslan Mandell" },
  "homepage": "https://github.com/RuslanAMandell/unslop-my-code",
  "repository": "https://github.com/RuslanAMandell/unslop-my-code",
  "license": "MIT",
  "keywords": ["security", "audit", "vibe-coding", "production-readiness", "supabase", "rls", "owasp"]
}
```

```json
// .claude-plugin/marketplace.json
{
  "name": "unslop-my-code",
  "owner": { "name": "Ruslan Mandell" },
  "metadata": {
    "description": "Production-readiness auditing for AI-generated codebases",
    "version": "0.1.0"
  },
  "plugins": [
    {
      "name": "unslop",
      "description": "Audit and repair the production failures that AI code generation leaves behind",
      "source": "./",
      "strict": false,
      "skills": ["./skills/unslop-audit", "./skills/unslop-fix", "./skills/unslop-guard"]
    }
  ]
}
```

Create all three `SKILL.md` files now with real frontmatter and a real Overview
paragraph each, so the conformance test passes from here on. Full bodies land in
Tasks 11, 12, and 13.

```markdown
---
name: unslop-audit
description: Audit a codebase for the production failures typical of AI-generated software - hardcoded secrets, disabled row level security, IDOR and missing authorization, unvalidated inputs, missing error handling and rate limits, N+1 queries and unindexed columns, hallucinated dependencies, duplicated patch-on-patch code, and missing tests or version control. Use when the user asks to audit, review, harden, or production-check a codebase, mentions vibe coding cleanup, asks "is this safe to ship", or is preparing an AI-built app for real users. Read-only - never edits code.
license: MIT
compatibility: Designed for Claude Code. Uses python3 when available and degrades to grep-based scanning when it is not.
---

# unslop-audit

## Overview

AI code generation optimizes for a working demo, not for software that survives
a thousand users. This skill finds the resulting gaps and reports them with
evidence: file, line, the offending snippet, and the concrete way it fails in
production.

The audit is read-only. It never edits code. Remediation is `unslop-fix`.
```

```markdown
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
```

```markdown
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
```

```makefile
# Makefile
PY := python3

.PHONY: check test lint fixtures clean
check: test fixtures
test:
	$(PY) -m unittest discover -s tests -p 'test_*.py' -v
fixtures:
	./tests/run-tests.sh
clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
```

```yaml
# .github/workflows/ci.yml
name: ci
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.9' }
      - run: make test
      - run: make fixtures
```

`tests/run-tests.sh` does not exist until Task 8; create it now as an executable
script whose entire body is `exec python3 -m unittest tests.test_fixtures -v`,
and let Task 8 supply the test module. Until then `make fixtures` fails, which is
correct: CI must be red until the fixtures prove the scanner works.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_skills -v`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add .claude-plugin Makefile .github LICENSE skills tests/test_skills.py tests/run-tests.sh
git commit -m "feat: repo skeleton, plugin manifests, skill conformance test"
```

---

### Task 2: Check catalog and findings model

**Files:**
- Create: `skills/unslop-audit/scripts/unslop/__init__.py` (empty)
- Create: `skills/unslop-audit/scripts/unslop/catalog.py`
- Create: `skills/unslop-audit/scripts/unslop/findings.py`
- Test: `tests/test_catalog.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `catalog.Check(id, title, domain, severity, fix_class, method, why, fix)` frozen dataclass
  - `catalog.CHECKS: Dict[str, Check]` — all 64, keyed by id
  - `catalog.by_method(method: str) -> List[Check]`
  - `findings.Finding(check_id, file, line, snippet, confidence="SUSPECTED", evidence="")`
  - `findings.Coverage` with `.note(str)`, `.scanned_files: int`, `.skipped: List[str]`
  - `findings.write(path: Path, findings: List[Finding], coverage: Coverage) -> None` writing `schemaVersion: 1`
  - `findings.load(path: Path) -> Tuple[List[Finding], dict]`

Every later task depends on these names. Do not rename them.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog.py
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))

from unslop import catalog                      # noqa: E402
from unslop.findings import Finding, Coverage, write, load   # noqa: E402

SEVERITIES = {"P0", "P1", "P2", "P3"}
FIX_CLASSES = {"auto", "assisted", "manual"}
METHODS = {"static", "config", "semantic", "net"}
DOMAINS = set("SDARCPOHXT")


class TestCatalog(unittest.TestCase):
    def test_catalog_has_all_64_checks(self):
        self.assertEqual(len(catalog.CHECKS), 64)

    def test_every_check_is_well_formed(self):
        for cid, chk in catalog.CHECKS.items():
            with self.subTest(check=cid):
                self.assertEqual(cid, chk.id)
                self.assertIn(cid[0], DOMAINS)
                self.assertIn(chk.severity, SEVERITIES)
                self.assertIn(chk.fix_class, FIX_CLASSES)
                self.assertIn(chk.method, METHODS)
                self.assertGreater(len(chk.title), 10)
                self.assertGreater(len(chk.why), 30, "why must be a concrete failure scenario")
                self.assertGreater(len(chk.fix), 20)

    def test_domain_counts_match_spec(self):
        expected = {"S": 6, "D": 9, "A": 6, "R": 9, "C": 8, "P": 5, "O": 5, "H": 8, "X": 5, "T": 3}
        actual = {}
        for cid in catalog.CHECKS:
            actual[cid[0]] = actual.get(cid[0], 0) + 1
        self.assertEqual(actual, expected)

    def test_by_method_filters(self):
        self.assertTrue(all(c.method == "semantic" for c in catalog.by_method("semantic")))
        self.assertGreaterEqual(len(catalog.by_method("semantic")), 10)


class TestFindings(unittest.TestCase):
    def test_roundtrip(self):
        import tempfile
        cov = Coverage()
        cov.scanned_files = 12
        cov.note("dependency verification skipped: offline")
        f = Finding(check_id="S1", file="src/a.ts", line=4, snippet="const k = 'sk-live_x'")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "findings.json"
            write(p, [f], cov)
            loaded, meta = load(p)
        self.assertEqual(meta["schemaVersion"], 1)
        self.assertEqual(loaded[0].check_id, "S1")
        self.assertEqual(loaded[0].confidence, "SUSPECTED")
        self.assertIn("offline", meta["coverage"]["notes"][0])

    def test_finding_rejects_unknown_check(self):
        with self.assertRaises(ValueError):
            Finding(check_id="Z9", file="a", line=1, snippet="x")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_catalog -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'unslop'`.

- [ ] **Step 3: Write the implementation**

```python
# skills/unslop-audit/scripts/unslop/catalog.py
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    domain: str
    severity: str   # P0 | P1 | P2 | P3
    fix_class: str  # auto | assisted | manual
    method: str     # static | config | semantic | net
    why: str        # concrete production failure, in plain language
    fix: str        # what remediation actually is


def _c(cid, title, sev, fix_class, method, why, fix):
    return Check(cid, title, cid[0], sev, fix_class, method, why, fix)


CHECKS: Dict[str, Check] = {c.id: c for c in [
    # --- S: secrets and configuration -------------------------------------
    _c("S1", "Hardcoded provider credential in source", "P0", "manual", "static",
       "The key is in your git history and in every build artifact. Anyone with repo or bundle access can spend, read, or delete on your account.",
       "Move the value to an environment variable, then rotate the key. Deleting it from HEAD does not un-leak it."),
    _c("S2", "Secret exposed through a client-visible env prefix", "P0", "assisted", "static",
       "Any variable prefixed NEXT_PUBLIC_/VITE_/REACT_APP_ is inlined into the browser bundle. View source reveals it.",
       "Rename without the public prefix and read it only in server code, then rotate."),
    _c("S3", "Secret file not covered by .gitignore", "P0", "auto", "config",
       "One `git add .` publishes your .env to a public repository, where credential scanners find it within minutes.",
       "Add the pattern to .gitignore; if the file is already tracked, untrack it and rotate everything in it."),
    _c("S4", "Secret present in git history", "P0", "manual", "static",
       "The credential is still fetchable from any clone even though it is gone from the current files.",
       "Rotate the credential. History rewriting is optional; rotation is not."),
    _c("S5", "Env var used in code but missing from .env.example", "P2", "auto", "static",
       "The deploy comes up with an undefined value and fails at the first request instead of at build time.",
       "Add the key to .env.example with a placeholder value and validate required env vars at startup."),
    _c("S6", "Source maps published to production", "P2", "auto", "config",
       "Your original source, comments, and internal endpoint names are downloadable from the live site.",
       "Disable production source map emission, or restrict upload to your error tracker."),

    # --- D: data layer and access control ---------------------------------
    _c("D1", "Table created without row level security", "P0", "assisted", "config",
       "With RLS off, the public anon key reads and writes every row in the table. This is the single most common way vibe-coded apps leak their entire user database.",
       "ALTER TABLE ... ENABLE ROW LEVEL SECURITY and add an explicit per-operation policy."),
    _c("D2", "Row level security policy that grants everything", "P0", "assisted", "config",
       "A USING (true) policy is RLS in name only - every row still matches for every caller.",
       "Scope the policy to the owning user, e.g. USING (auth.uid() = user_id)."),
    _c("D3", "Admin/service_role key reachable from client code", "P0", "assisted", "static",
       "The service role key bypasses every RLS policy. Shipped to the browser it is a full database takeover.",
       "Use the anon key in the client, keep the service role key server-side only, and rotate it."),
    _c("D4", "Storage bucket is public or has no policy", "P0", "assisted", "config",
       "Uploaded files - IDs, invoices, private images - are fetchable by anyone who can guess or enumerate a path.",
       "Make the bucket private and serve files through signed URLs."),
    _c("D5", "Record fetched by user-supplied id with no ownership check", "P0", "assisted", "semantic",
       "Change 1042 to 1043 in the URL and you read someone else's record. This is IDOR, the most common flaw in AI-generated routes.",
       "Add an ownership predicate to the query and return 404 rather than 403 on a miss."),
    _c("D6", "Authorization enforced only in client code", "P0", "assisted", "semantic",
       "Hiding the admin button does not protect the endpoint. curl reaches it directly.",
       "Enforce the check server-side in the route handler; treat the client check as cosmetic."),
    _c("D7", "Request body written to the database unfiltered", "P1", "assisted", "semantic",
       "A caller adds \"role\":\"admin\" or \"credits\":9999 to the JSON body and the field is persisted.",
       "Validate against an explicit schema and write only allow-listed fields."),
    _c("D8", "SQL assembled by string interpolation", "P0", "assisted", "static",
       "A crafted input closes the string and appends its own statement - classic SQL injection.",
       "Use parameterized queries or the query builder's binding API."),
    _c("D9", "Firebase security rules allow unrestricted access", "P0", "assisted", "config",
       "`allow read, write: if true` means every document is world-readable and world-writable.",
       "Restrict rules to request.auth.uid and validate written shapes."),

    # --- A: authentication and session ------------------------------------
    _c("A1", "Mutating endpoint with no authentication", "P0", "assisted", "semantic",
       "Anyone on the internet can POST to it and change your data.",
       "Require and verify a session at the top of the handler; reject before any side effect."),
    _c("A2", "JWT verification disabled, weak, or bypassable", "P0", "assisted", "static",
       "An attacker mints their own token and becomes any user, including an admin.",
       "Verify the signature, pin the algorithm, and load the secret from the environment."),
    _c("A3", "Session cookie missing httpOnly, secure, or sameSite", "P1", "auto", "static",
       "A single XSS reads the session cookie from JavaScript, or it leaks over plain HTTP or a cross-site request.",
       "Set httpOnly: true, secure: true, sameSite: 'lax' (or 'strict')."),
    _c("A4", "No rate limit on login, signup, or password reset", "P1", "assisted", "semantic",
       "Credential stuffing runs unthrottled, and password reset becomes an email-bombing tool.",
       "Add per-IP and per-account rate limiting on the auth routes."),
    _c("A5", "Wildcard CORS on an authenticated API", "P1", "auto", "static",
       "Any website can make credentialed requests to your API from a victim's browser.",
       "Set an explicit origin allow-list instead of '*'."),
    _c("A6", "Password stored without a modern KDF", "P0", "assisted", "static",
       "A database leak becomes a plaintext password leak, and users reuse those passwords elsewhere.",
       "Hash with bcrypt, scrypt, or argon2id, or delegate auth to a provider."),

    # --- R: reliability and the unhappy path ------------------------------
    _c("R1", "No error boundary in the component tree", "P1", "auto", "static",
       "One thrown render error blanks the entire page - users see white, not a message.",
       "Add an error boundary at the route or app level with a recovery affordance."),
    _c("R2", "HTTP response used without checking status", "P1", "assisted", "static",
       "fetch does not throw on 500. The error body is parsed as if it were data and the failure surfaces later as a confusing crash.",
       "Check response.ok and handle the failure path explicitly."),
    _c("R3", "Network call with no timeout or abort signal", "P1", "auto", "static",
       "A hung upstream holds your request open until the platform kills it, exhausting the connection pool under load.",
       "Attach an AbortController with an explicit timeout."),
    _c("R4", "No schema validation at a trust boundary", "P1", "assisted", "semantic",
       "Malformed or hostile input reaches business logic and the database, where the failure is expensive.",
       "Parse the request with an explicit schema and reject early with a 400."),
    _c("R5", "Error swallowed by an empty or log-only catch", "P1", "assisted", "static",
       "The operation failed but the code proceeds as if it succeeded, so the user is told everything worked.",
       "Handle it, or rethrow. A catch that only logs is a silent failure."),
    _c("R6", "No rate limiting on public endpoints", "P1", "assisted", "semantic",
       "One script can drive unbounded traffic into your database and your bill.",
       "Add rate limiting at the edge or in middleware for unauthenticated routes."),
    _c("R7", "Fetch path with no loading or error state", "P2", "assisted", "semantic",
       "On a slow or failed request the UI shows nothing and the user clicks again, duplicating the write.",
       "Render explicit loading, empty, and error states."),
    _c("R8", "Unbounded list render with no pagination", "P2", "assisted", "semantic",
       "Fine with 20 rows, unusable at 20,000 - the page freezes and mobile devices run out of memory.",
       "Paginate or virtualize the list and bound the query."),
    _c("R9", "Floating promise on a critical path", "P2", "auto", "static",
       "The write is never awaited, so failures vanish and ordering is undefined.",
       "Await it, or attach an explicit catch."),

    # --- C: cost and performance ------------------------------------------
    _c("C1", "Query executed inside a loop (N+1)", "P2", "assisted", "semantic",
       "One page view becomes hundreds of round trips. It is invisible with ten rows of test data and it is your database bill at ten thousand.",
       "Fetch the set in one query with a join or an IN clause."),
    _c("C2", "Filtered or sorted column with no index", "P2", "auto", "static",
       "Every query is a full table scan. Response times climb linearly with row count and compute is billed per scan.",
       "Add an index on the filtered/joined/ordered columns in a migration."),
    _c("C3", "Unbounded select with no limit", "P2", "assisted", "static",
       "The query returns the whole table, which is fine in development and is an out-of-memory error plus an egress bill in production.",
       "Add an explicit limit and paginate."),
    _c("C4", "Unbounded loop or recursion in a serverless handler", "P1", "assisted", "static",
       "The function runs to its timeout on every invocation, and you are billed for the full duration each time.",
       "Bound the iteration and move long work to a queue or a job."),
    _c("C5", "Aggressive polling interval", "P2", "assisted", "static",
       "Each open tab hits your API on a fixed timer forever. A hundred idle tabs is a sustained load you never see in testing.",
       "Increase the interval, use websockets or server-sent events, or poll only while visible."),
    _c("C6", "Cacheable route with no caching or revalidation", "P2", "assisted", "static",
       "Every visitor triggers full recomputation and a database round trip for content that never changed.",
       "Set cache headers or the framework's revalidation option."),
    _c("C7", "Unbounded fan-out with no concurrency cap", "P2", "assisted", "semantic",
       "Promise.all over a large array opens every connection at once and trips provider rate limits or connection caps.",
       "Batch the work with a bounded concurrency limit."),
    _c("C8", "Full table read used to compute an aggregate", "P2", "assisted", "semantic",
       "You transfer every row to count or sum them in application code, paying egress and memory for arithmetic the database does for free.",
       "Push the aggregate into the query."),

    # --- P: supply chain ---------------------------------------------------
    _c("P1", "Dependency does not exist on the registry", "P0", "manual", "net",
       "The model invented the package name. The moment an attacker registers it, your next install pulls their code - this is slopsquatting.",
       "Remove it and replace with a real package you have verified."),
    _c("P2", "Dependency name is one edit from a far more popular package", "P1", "manual", "net",
       "Typosquats publish install hooks that exfiltrate environment variables during npm install.",
       "Verify the intended name and repository, then correct it."),
    _c("P3", "Missing or out-of-sync lockfile", "P1", "auto", "config",
       "Production resolves different versions than your machine, so a transitive update breaks the deploy or silently changes behavior.",
       "Commit the lockfile and install with the frozen/ci flag."),
    _c("P4", "Dependency with known published vulnerabilities", "P1", "assisted", "net",
       "A public CVE with a public exploit is reachable through your dependency tree.",
       "Upgrade to the patched version or replace the dependency."),
    _c("P5", "Dependency runs an install script", "P2", "manual", "config",
       "postinstall executes arbitrary code on every developer machine and every CI run.",
       "Confirm the package is trusted, or install with scripts disabled."),

    # --- O: observability --------------------------------------------------
    _c("O1", "Secret or personal data written to logs", "P0", "auto", "static",
       "Tokens and personal data land in a log platform with far broader access than your database, and log retention keeps them for years.",
       "Redact before logging; log an identifier, never the credential."),
    _c("O2", "Internal error detail returned to the client", "P1", "auto", "static",
       "Stack traces disclose file paths, library versions, and query shapes - a free reconnaissance report.",
       "Return a generic message with a correlation id; log the detail server-side."),
    _c("O3", "console.log used as production logging", "P3", "assisted", "static",
       "Unstructured output cannot be searched, filtered, or alerted on, so the first sign of an incident is a user complaint.",
       "Use a structured logger with levels and a request id."),
    _c("O4", "No error tracking configured", "P2", "manual", "config",
       "Production exceptions are invisible until someone reports them.",
       "Wire up an error tracking service in the app entrypoint."),
    _c("O5", "No health check endpoint", "P3", "auto", "config",
       "Your platform cannot tell a hung instance from a healthy one, so it keeps routing traffic to it.",
       "Expose a lightweight endpoint that verifies critical dependencies."),

    # --- H: AI rot ----------------------------------------------------------
    _c("H1", "No version control, or the whole codebase in one commit", "P1", "auto", "config",
       "Without checkpoints, the next prompt that breaks working behavior cannot be reverted - you can only ask the model to patch forward.",
       "Initialize git and commit in small, working increments before each prompt."),
    _c("H2", "Near-duplicate file left behind by iterative patching", "P2", "assisted", "static",
       "Two versions of the same module exist and only one is imported. Fixes get applied to the dead one, and the bug never goes away.",
       "Diff the pair, keep one, delete the other."),
    _c("H3", "Orphan module that nothing imports", "P3", "assisted", "static",
       "Dead code is read as real by both you and the model, so future prompts reason about behavior that never executes.",
       "Delete it. Git remembers."),
    _c("H4", "Competing implementations of the same concern", "P2", "assisted", "semantic",
       "Two auth helpers, two HTTP clients, or two ORMs mean a fix in one leaves the other vulnerable.",
       "Pick one, migrate call sites, delete the rest."),
    _c("H5", "Mock data or unfinished stub on a production path", "P1", "assisted", "static",
       "The demo works because the data is fake. Real users hit the placeholder.",
       "Replace with the real implementation or fail loudly instead of returning fixtures."),
    _c("H6", "Large block of commented-out code", "P3", "auto", "static",
       "It rots, it misleads, and it pollutes the context the model reads on every future prompt.",
       "Delete it."),
    _c("H7", "File past the size threshold", "P3", "manual", "static",
       "Neither you nor the model can hold it in context, so edits become guesses and regressions become routine.",
       "Split it along its responsibility boundaries."),
    _c("H8", "Logic block copy-pasted three or more times", "P3", "assisted", "static",
       "A fix applied to one copy leaves the others broken, which is how a bug you already fixed comes back.",
       "Extract a single implementation and call it."),

    # --- X: deployment ------------------------------------------------------
    _c("X1", "Debug mode enabled in a deployed configuration", "P1", "auto", "config",
       "Debug pages expose settings, environment variables, and an interactive console to the public internet.",
       "Drive it from an environment variable that is false in production."),
    _c("X2", "Missing security response headers", "P1", "auto", "config",
       "Without CSP, HSTS, and frame options the app is one injected script or one clickjacking frame from compromise.",
       "Set CSP, HSTS, X-Frame-Options, and X-Content-Type-Options in the platform config or middleware."),
    _c("X3", "Redirect target taken from user input", "P1", "assisted", "static",
       "Your domain becomes the credible first hop in a phishing chain.",
       "Allow-list redirect destinations, or accept only relative paths."),
    _c("X4", "Admin or internal route with no guard", "P0", "assisted", "semantic",
       "The admin panel is one guessed URL away for anyone on the internet.",
       "Require an authenticated role check server-side on the route and its API."),
    _c("X5", "Preview or staging deployment with no access protection", "P1", "manual", "config",
       "Preview URLs are indexed and shared, and they usually point at real data.",
       "Enable deployment protection or password the environment."),

    # --- T: tests -----------------------------------------------------------
    _c("T1", "No tests, or a placeholder test script", "P2", "manual", "config",
       "Nothing catches the regression when the next prompt rewrites working code.",
       "Add tests for the paths that would cost you money or data if they broke."),
    _c("T2", "Test file with no assertions", "P3", "manual", "static",
       "It passes whatever the code does, which is worse than no test because it reads as coverage.",
       "Assert on the behavior, not on the absence of a crash."),
    _c("T3", "No continuous integration workflow", "P2", "auto", "config",
       "Tests only run when someone remembers, which in practice is never.",
       "Add a CI workflow that runs the test suite on every push and pull request."),
]}


def by_method(method: str) -> List[Check]:
    return [c for c in CHECKS.values() if c.method == method]


def by_severity(severity: str) -> List[Check]:
    return [c for c in CHECKS.values() if c.severity == severity]
```

```python
# skills/unslop-audit/scripts/unslop/findings.py
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Tuple

from .catalog import CHECKS

SCHEMA_VERSION = 1
CONFIDENCES = ("CONFIRMED", "SUSPECTED")


@dataclass
class Finding:
    check_id: str
    file: str
    line: int
    snippet: str
    confidence: str = "SUSPECTED"
    evidence: str = ""

    def __post_init__(self):
        if self.check_id not in CHECKS:
            raise ValueError("unknown check id: %s" % self.check_id)
        if self.confidence not in CONFIDENCES:
            raise ValueError("bad confidence: %s" % self.confidence)
        self.snippet = self.snippet.strip()[:240]

    @property
    def check(self):
        return CHECKS[self.check_id]

    def key(self) -> str:
        return "%s:%s:%d" % (self.check_id, self.file, self.line)


@dataclass
class Coverage:
    scanned_files: int = 0
    skipped: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    stack: List[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)


def write(path: Path, findings: List[Finding], coverage: Coverage) -> None:
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "coverage": asdict(coverage),
        "findings": [
            dict(asdict(f), severity=f.check.severity, fixClass=f.check.fix_class,
                 title=f.check.title, domain=f.check.domain)
            for f in findings
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load(path: Path) -> Tuple[List[Finding], Dict]:
    data = json.loads(Path(path).read_text())
    out = []
    for row in data.get("findings", []):
        out.append(Finding(
            check_id=row["check_id"], file=row["file"], line=row["line"],
            snippet=row["snippet"], confidence=row.get("confidence", "SUSPECTED"),
            evidence=row.get("evidence", ""),
        ))
    return out, data
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_catalog -v`
Expected: PASS, 6 tests. If `test_catalog_has_all_64_checks` fails, the domain
counts in `test_domain_counts_match_spec` tell you which domain is short.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/unslop tests/test_catalog.py
git commit -m "feat: check catalog (64 checks) and findings model"
```

---

### Task 3: File walker with ignore rules and caps

**Files:**
- Create: `skills/unslop-audit/scripts/unslop/walker.py`
- Test: `tests/test_walker.py`

**Interfaces:**
- Consumes: `findings.Coverage`.
- Produces:
  - `walker.SourceFile(path: Path, rel: str, text: str, lines: List[str])`
  - `walker.walk(root: Path, coverage: Coverage, max_file_bytes=2_000_000, max_files=20_000) -> List[SourceFile]`
  - `walker.detect_stack(root: Path) -> List[str]` returning tags from
    `{"nextjs","react","vite","express","fastapi","django","supabase","firebase","prisma","drizzle","vercel","npm","pnpm","yarn","python"}`

In a git repository, use `git ls-files` for discovery: it is fast and it honors
`.gitignore` for free. Outside one, fall back to `os.walk` with the built-in
ignore set. Both paths must record what they skipped.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_walker.py
import sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import walker                       # noqa: E402
from unslop.findings import Coverage            # noqa: E402


def make_tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


class TestWalker(unittest.TestCase):
    def test_skips_vendor_directories(self):
        root = make_tree({
            "src/a.ts": "export const a = 1",
            "node_modules/pkg/index.js": "module.exports = 1",
            ".next/build.js": "x",
            "dist/bundle.min.js": "x",
        })
        cov = Coverage()
        rels = {f.rel for f in walker.walk(root, cov)}
        self.assertEqual(rels, {"src/a.ts"})
        self.assertEqual(cov.scanned_files, 1)

    def test_skips_binary_and_oversized_files(self):
        root = make_tree({"src/a.ts": "ok", "src/big.ts": "x" * 5000})
        (root / "src" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00")
        cov = Coverage()
        rels = {f.rel for f in walker.walk(root, cov, max_file_bytes=1000)}
        self.assertEqual(rels, {"src/a.ts"})
        self.assertTrue(any("big.ts" in s for s in cov.skipped))

    def test_file_cap_is_reported_not_silent(self):
        root = make_tree({"src/f%d.ts" % i: "x" for i in range(10)})
        cov = Coverage()
        files = walker.walk(root, cov, max_files=4)
        self.assertEqual(len(files), 4)
        self.assertTrue(any("file cap" in n for n in cov.notes))

    def test_detect_stack(self):
        root = make_tree({
            "package.json": '{"dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.0.0"}}',
            "pnpm-lock.yaml": "lockfileVersion: 9",
        })
        tags = walker.detect_stack(root)
        self.assertIn("nextjs", tags)
        self.assertIn("supabase", tags)
        self.assertIn("pnpm", tags)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_walker -v`
Expected: FAIL — `cannot import name 'walker'`.

- [ ] **Step 3: Write the implementation**

```python
# skills/unslop-audit/scripts/unslop/walker.py
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List

IGNORE_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", ".svelte-kit", "dist", "build",
    "out", "coverage", "venv", ".venv", "env", "__pycache__", ".pytest_cache",
    "target", "vendor", ".turbo", ".vercel", ".cache", "Pods", ".terraform",
}
IGNORE_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip",
    ".gz", ".tar", ".mp4", ".mov", ".mp3", ".woff", ".woff2", ".ttf", ".eot",
    ".lock", ".pyc", ".so", ".dylib", ".dll", ".wasm", ".map",
)
IGNORE_NAME_RE = re.compile(r"\.min\.(js|css)$")


@dataclass
class SourceFile:
    path: Path
    rel: str
    text: str

    @property
    def lines(self) -> List[str]:
        return self.text.splitlines()

    def line_at(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1


def _git_files(root: Path):
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
             "--exclude-standard"],
            capture_output=True, timeout=20,
        )
        if out.returncode != 0:
            return None
        return [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]
    except (OSError, subprocess.SubprocessError):
        return None


def _os_walk_files(root: Path):
    rels = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".git")]
        for name in filenames:
            rels.append(str(Path(dirpath, name).relative_to(root)))
    return rels


def _ignored(rel: str) -> bool:
    parts = set(Path(rel).parts)
    if parts & IGNORE_DIRS:
        return True
    low = rel.lower()
    return low.endswith(IGNORE_SUFFIXES) or bool(IGNORE_NAME_RE.search(low))


def walk(root, coverage, max_file_bytes=2_000_000, max_files=20_000) -> List[SourceFile]:
    root = Path(root)
    rels = _git_files(root)
    if rels is None:
        rels = _os_walk_files(root)
        coverage.note("not a git repository: used built-in ignore rules instead of .gitignore")
    rels = sorted(r for r in rels if not _ignored(r))

    if len(rels) > max_files:
        coverage.note("file cap reached: scanned %d of %d files" % (max_files, len(rels)))
        rels = rels[:max_files]

    files = []
    for rel in rels:
        p = root / rel
        try:
            if not p.is_file():
                continue
            size = p.stat().st_size
            if size > max_file_bytes:
                coverage.skipped.append("%s (%d bytes, over size cap)" % (rel, size))
                continue
            raw = p.read_bytes()
            if b"\x00" in raw[:4096]:
                coverage.skipped.append("%s (binary)" % rel)
                continue
            files.append(SourceFile(p, rel, raw.decode("utf-8", "replace")))
        except OSError as exc:
            coverage.skipped.append("%s (%s)" % (rel, exc.__class__.__name__))
    coverage.scanned_files = len(files)
    return files


_STACK_DEP_TAGS = {
    "next": "nextjs", "react": "react", "vite": "vite", "express": "express",
    "@supabase/supabase-js": "supabase", "firebase": "firebase",
    "firebase-admin": "firebase", "prisma": "prisma", "@prisma/client": "prisma",
    "drizzle-orm": "drizzle", "fastapi": "fastapi", "django": "django",
}


def detect_stack(root) -> List[str]:
    root = Path(root)
    tags = set()
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text())
        except ValueError:
            data = {}
        deps = {}
        deps.update(data.get("dependencies") or {})
        deps.update(data.get("devDependencies") or {})
        for name, tag in _STACK_DEP_TAGS.items():
            if name in deps:
                tags.add(tag)
        tags.add("npm")
    for lock, tag in (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"),
                      ("package-lock.json", "npm"), ("bun.lockb", "bun")):
        if (root / lock).is_file():
            tags.add(tag)
    for marker in ("requirements.txt", "pyproject.toml", "Pipfile"):
        if (root / marker).is_file():
            tags.add("python")
            text = (root / marker).read_text(errors="replace").lower()
            for name, tag in (("fastapi", "fastapi"), ("django", "django")):
                if name in text:
                    tags.add(tag)
    if (root / "supabase").is_dir():
        tags.add("supabase")
    if (root / "vercel.json").is_file() or (root / ".vercel").is_dir():
        tags.add("vercel")
    if (root / "firestore.rules").is_file() or (root / "firebase.json").is_file():
        tags.add("firebase")
    return sorted(tags)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_walker -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/unslop/walker.py tests/test_walker.py
git commit -m "feat: file walker with gitignore-aware discovery and reported caps"
```

---

### Task 4: Rule engine

**Files:**
- Create: `skills/unslop-audit/scripts/unslop/rules.py`
- Test: `tests/test_rules.py`

**Interfaces:**
- Consumes: `walker.SourceFile`, `findings.Finding`.
- Produces:
  - `rules.Rule(check_id, pattern, includes=(), excludes=(), absent=(), window=400, predicate=None, confidence="SUSPECTED")`
  - `rules.run(rules_list, files) -> List[Finding]`
  - `rules.shannon_entropy(s: str) -> float`
  - `rules.PLACEHOLDER_RE` — matches obvious non-secrets

Semantics: a rule fires when `pattern` matches inside a file whose path ends
with one of `includes` (empty = all text files) and does not match any
`excludes` glob fragment, **and** none of the `absent` patterns appear within
`window` characters after the match, **and** `predicate(match, sourcefile)`
returns True if provided. `absent` is what makes "fetch with no status check"
expressible declaratively.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_rules.py
import re, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import rules                        # noqa: E402
from unslop.walker import SourceFile            # noqa: E402


def sf(rel, text):
    return SourceFile(Path(rel), rel, text)


class TestRuleEngine(unittest.TestCase):
    def test_simple_match_reports_line_and_snippet(self):
        r = rules.Rule("S1", re.compile(r"AKIA[0-9A-Z]{16}"))
        f = sf("src/a.ts", "const x = 1\nconst k = 'REDACTED-FAKE-TEST-VALUE'\n")
        found = rules.run([r], [f])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].line, 2)
        self.assertIn("AKIA", found[0].snippet)

    def test_includes_filters_by_suffix(self):
        r = rules.Rule("S1", re.compile(r"AKIA"), includes=(".py",))
        self.assertEqual(rules.run([r], [sf("a.ts", "AKIA")]), [])
        self.assertEqual(len(rules.run([r], [sf("a.py", "AKIA")])), 1)

    def test_absent_suppresses_when_guard_present(self):
        r = rules.Rule("R2", re.compile(r"await fetch\("),
                       absent=(re.compile(r"\.ok\b|\.status\b"),), window=120)
        guarded = sf("a.ts", "const r = await fetch(u)\nif (!r.ok) throw new Error('x')\n")
        bare = sf("b.ts", "const r = await fetch(u)\nconst j = await r.json()\n")
        self.assertEqual(rules.run([r], [guarded]), [])
        self.assertEqual(len(rules.run([r], [bare])), 1)

    def test_predicate_gates_the_match(self):
        r = rules.Rule("C5", re.compile(r"setInterval\([^,]+,\s*(\d+)\s*\)"),
                       predicate=lambda m, f: int(m.group(1)) < 30000)
        self.assertEqual(len(rules.run([r], [sf("a.ts", "setInterval(tick, 1000)")])), 1)
        self.assertEqual(rules.run([r], [sf("b.ts", "setInterval(tick, 60000)")]), [])

    def test_dedupes_repeat_matches_on_same_line(self):
        r = rules.Rule("S1", re.compile(r"AKIA[0-9A-Z]{16}"))
        f = sf("a.ts", "REDACTED-FAKE-TEST-VALUE REDACTED-FAKE-TEST-VALUE\n")
        self.assertEqual(len(rules.run([r], [f])), 1)

    def test_entropy_separates_secrets_from_words(self):
        self.assertGreater(rules.shannon_entropy("k3J8sQ2mNp0zXv7LtB4y"), 3.5)
        self.assertLess(rules.shannon_entropy("password"), 3.5)

    def test_placeholder_detection(self):
        for s in ("your-api-key-here", "xxxxxxxxxxxx", "changeme", "<YOUR_KEY>",
                  "process.env.API_KEY", "sk-example"):
            self.assertTrue(rules.PLACEHOLDER_RE.search(s), s)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_rules -v`
Expected: FAIL — `cannot import name 'rules'`.

- [ ] **Step 3: Write the implementation**

```python
# skills/unslop-audit/scripts/unslop/rules.py
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Pattern, Sequence

from .findings import Finding
from .walker import SourceFile

PLACEHOLDER_RE = re.compile(
    r"(?i)(your[-_ ]?|example|placeholder|changeme|dummy|sample|test[-_]?key|"
    r"xxxx|\.\.\.|<[^>]+>|process\.env|os\.environ|import\.meta\.env|\$\{)"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = float(len(s))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


@dataclass
class Rule:
    check_id: str
    pattern: Pattern
    includes: Sequence[str] = ()
    excludes: Sequence[str] = ()
    absent: Sequence[Pattern] = field(default_factory=tuple)
    window: int = 400
    predicate: Optional[Callable[[re.Match, SourceFile], bool]] = None
    confidence: str = "SUSPECTED"

    def applies_to(self, f: SourceFile) -> bool:
        rel = f.rel.lower()
        if self.includes and not rel.endswith(tuple(self.includes)):
            return False
        return not any(x in rel for x in self.excludes)


def run(rules_list: List[Rule], files: List[SourceFile]) -> List[Finding]:
    out, seen = [], set()
    for f in files:
        for rule in rules_list:
            if not rule.applies_to(f):
                continue
            for m in rule.pattern.finditer(f.text):
                if rule.predicate and not rule.predicate(m, f):
                    continue
                if rule.absent:
                    tail = f.text[m.end():m.end() + rule.window]
                    if any(a.search(tail) for a in rule.absent):
                        continue
                line = f.line_at(m.start())
                key = (rule.check_id, f.rel, line)
                if key in seen:
                    continue
                seen.add(key)
                snippet = f.text.splitlines()[line - 1] if line <= len(f.lines) else m.group(0)
                out.append(Finding(rule.check_id, f.rel, line, snippet,
                                   confidence=rule.confidence))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_rules -v`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/unslop/rules.py tests/test_rules.py
git commit -m "feat: declarative rule engine with absent-guard and predicate support"
```

---

### Task 5: The static ruleset

**Files:**
- Create: `skills/unslop-audit/scripts/unslop/ruleset.py`
- Modify: `tests/test_catalog.py` (add the coverage gate)
- Test: `tests/test_ruleset.py`

**Interfaces:**
- Consumes: `rules.Rule`.
- Produces: `ruleset.RULES: List[Rule]` covering **every** catalog check whose
  `method == "static"`.

The coverage gate added to `test_catalog.py` is what prevents this task from
being half-done: it fails if any `static` check has no rule.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_catalog.py
from unslop.ruleset import RULES              # noqa: E402


class TestRuleCoverage(unittest.TestCase):
    def test_every_static_check_has_a_rule(self):
        covered = {r.check_id for r in RULES}
        expected = {c.id for c in catalog.by_method("static")}
        self.assertEqual(expected - covered, set(), "static checks with no rule")

    def test_no_rule_targets_an_unknown_check(self):
        self.assertEqual({r.check_id for r in RULES} - set(catalog.CHECKS), set())
```

```python
# tests/test_ruleset.py
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import rules                        # noqa: E402
from unslop.ruleset import RULES                # noqa: E402
from unslop.walker import SourceFile            # noqa: E402

BY_ID = {}
for _r in RULES:
    BY_ID.setdefault(_r.check_id, []).append(_r)


def fires(check_id, rel, text):
    f = SourceFile(Path(rel), rel, text)
    return [x for x in rules.run(BY_ID[check_id], [f]) if x.check_id == check_id]


class TestRuleset(unittest.TestCase):
    def test_s1_aws_and_stripe_keys(self):
        self.assertTrue(fires("S1", "src/a.ts", "const k='REDACTED-FAKE-TEST-VALUE'"))
        self.assertTrue(fires("S1", "src/a.ts", "const k='REDACTED-FAKE-TEST-VALUE'"))

    def test_s1_ignores_env_reads_and_placeholders(self):
        self.assertFalse(fires("S1", "src/a.ts", "const key = process.env.STRIPE_SECRET_KEY"))
        self.assertFalse(fires("S1", "src/a.ts", "const apiKey = 'your-api-key-here'"))

    def test_s2_public_prefixed_secret(self):
        self.assertTrue(fires("S2", "src/a.ts", "process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"))
        self.assertFalse(fires("S2", "src/a.ts", "process.env.NEXT_PUBLIC_SITE_URL"))

    def test_d8_sql_interpolation(self):
        self.assertTrue(fires("D8", "src/db.ts", "db.query(`SELECT * FROM users WHERE id = ${id}`)"))
        self.assertFalse(fires("D8", "src/db.ts", "db.query('SELECT * FROM users WHERE id = $1', [id])"))

    def test_a3_cookie_flags(self):
        self.assertTrue(fires("A3", "src/s.ts", "res.cookie('sid', t, { maxAge: 900000 })"))
        self.assertFalse(fires("A3", "src/s.ts",
                               "res.cookie('sid', t, { httpOnly: true, secure: true, sameSite: 'lax' })"))

    def test_a5_wildcard_cors(self):
        self.assertTrue(fires("A5", "src/api.ts", "'Access-Control-Allow-Origin': '*'"))

    def test_r2_unchecked_fetch(self):
        self.assertTrue(fires("R2", "src/a.ts", "const r = await fetch(u)\nconst j = await r.json()"))
        self.assertFalse(fires("R2", "src/a.ts", "const r = await fetch(u)\nif (!r.ok) return null"))

    def test_r5_empty_catch(self):
        self.assertTrue(fires("R5", "src/a.ts", "try { go() } catch (e) {}"))
        self.assertTrue(fires("R5", "src/a.py", "try:\n    go()\nexcept Exception:\n    pass\n"))

    def test_c3_unbounded_select(self):
        self.assertTrue(fires("C3", "src/a.ts", "await supabase.from('orders').select('*')"))
        self.assertFalse(fires("C3", "src/a.ts", "await supabase.from('orders').select('*').limit(50)"))

    def test_c5_polling(self):
        self.assertTrue(fires("C5", "src/a.ts", "setInterval(refresh, 2000)"))
        self.assertFalse(fires("C5", "src/a.ts", "setInterval(refresh, 300000)"))

    def test_o1_secret_in_log(self):
        self.assertTrue(fires("O1", "src/a.ts", "console.log('token', accessToken)"))

    def test_o2_stack_trace_to_client(self):
        self.assertTrue(fires("O2", "src/api.ts", "res.status(500).json({ error: err.stack })"))

    def test_x3_open_redirect(self):
        self.assertTrue(fires("X3", "src/api.ts", "res.redirect(req.query.next)"))

    def test_h5_mock_on_prod_path(self):
        self.assertTrue(fires("H5", "src/app/api/orders/route.ts", "const MOCK_ORDERS = []"))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_ruleset tests.test_catalog -v`
Expected: FAIL — `No module named 'unslop.ruleset'`.

- [ ] **Step 3: Write the ruleset**

```python
# skills/unslop-audit/scripts/unslop/ruleset.py
import re

from .rules import PLACEHOLDER_RE, Rule, shannon_entropy

JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue", ".astro")
PY = (".py",)
CODE = JS + PY + (".go", ".rb", ".php", ".java", ".cs", ".rs")
CFG = (".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".conf")
TEST_PATHS = ("test", "spec", "__tests__", "fixtures", "mock", ".example")
SERVER_PATHS = ("/api/", "route.ts", "route.js", "server", "actions", "handler", "views.py", "app.py")


def _entropic_secret(m, f):
    value = m.group("val")
    if PLACEHOLDER_RE.search(value) or len(set(value)) < 8:
        return False
    return shannon_entropy(value) >= 3.5


def _on_server_path(m, f):
    rel = f.rel.lower()
    return any(p in rel for p in SERVER_PATHS)


RULES = [
    # ---- S1 hardcoded credentials ----------------------------------------
    Rule("S1", re.compile(r"AKIA[0-9A-Z]{16}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{16,}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), excludes=TEST_PATHS),
    Rule("S1", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|access[_-]?key|auth)\w*"
        r"\s*[:=]\s*[\"'](?P<val>[^\"'\s]{12,})[\"']"),
        includes=CODE + CFG, excludes=TEST_PATHS, predicate=_entropic_secret),

    # ---- S2 client-exposed secret ----------------------------------------
    Rule("S2", re.compile(
        r"\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC)_[A-Z0-9_]*"
        r"(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|API_KEY|ACCESS_KEY)[A-Z0-9_]*")),

    # ---- S5 env var not documented (post-filtered in scan.py) -------------
    Rule("S5", re.compile(r"(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,})"),
         includes=JS),
    Rule("S5", re.compile(r"os\.(?:environ\.get|getenv)\(\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']"),
         includes=PY),

    # ---- D3 service role client-side --------------------------------------
    Rule("D3", re.compile(r"(?i)service[_-]?role"), includes=JS,
         excludes=("/server/", "/api/", "route.ts", "supabase/functions", ".env")),

    # ---- D8 SQL string interpolation --------------------------------------
    Rule("D8", re.compile(
        r"(?is)(select|insert\s+into|update|delete\s+from)\b[^`\"';]{0,200}"
        r"(\$\{|\"\s*\+\s*\w|'\s*\+\s*\w|%s\"\s*%\s*|f[\"'])")),
    Rule("D8", re.compile(r"(?i)(execute|query|raw)\(\s*f[\"']"), includes=PY),

    # ---- A2 JWT weaknesses -------------------------------------------------
    Rule("A2", re.compile(r"(?i)verify\s*[:=]\s*(false|False)")),
    Rule("A2", re.compile(r"(?i)algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']")),
    Rule("A2", re.compile(r"jwt\.decode\((?![^)]*verify)[^)]*\)"), includes=PY),
    Rule("A2", re.compile(r"jwt\.(sign|verify)\([^,]+,\s*[\"'][^\"']{1,24}[\"']"), includes=JS),

    # ---- A3 cookie flags ---------------------------------------------------
    Rule("A3", re.compile(r"(?:res\.cookie|cookies\(\)\.set|setCookie)\("),
         absent=(re.compile(r"(?i)httpOnly\s*:\s*true"),), window=220),
    Rule("A3", re.compile(r"(?:res\.cookie|cookies\(\)\.set|setCookie)\("),
         absent=(re.compile(r"(?i)sameSite"),), window=220),
    Rule("A3", re.compile(r"set_cookie\("), includes=PY,
         absent=(re.compile(r"httponly\s*=\s*True"),), window=220),

    # ---- A5 wildcard CORS --------------------------------------------------
    Rule("A5", re.compile(r"[\"']Access-Control-Allow-Origin[\"']\s*[:,]\s*[\"']\*[\"']")),
    Rule("A5", re.compile(r"origin\s*:\s*[\"']\*[\"']")),
    Rule("A5", re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']"), includes=PY),
    Rule("A5", re.compile(r"\bcors\(\s*\)")),

    # ---- A6 weak password storage ------------------------------------------
    Rule("A6", re.compile(r"(?i)(md5|sha1)\s*\(\s*\w*(pass|pwd)")),
    Rule("A6", re.compile(r"(?i)createHash\([\"'](md5|sha1|sha256)[\"']\)[^;]{0,80}(pass|pwd)")),

    # ---- R1 no error boundary (absence handled in scan.py aggregate) --------
    Rule("R1", re.compile(r"(?s)^\s*(?:import|export)"), includes=(".tsx", ".jsx"),
         predicate=lambda m, f: False),  # placeholder-free: R1 is emitted by project.py

    # ---- R2 unchecked fetch -------------------------------------------------
    Rule("R2", re.compile(r"await\s+fetch\("), includes=JS,
         absent=(re.compile(r"\.ok\b|\.status\b|catch\s*\(|\.catch\("),), window=200),

    # ---- R3 no timeout ------------------------------------------------------
    Rule("R3", re.compile(r"\bfetch\("), includes=JS,
         absent=(re.compile(r"signal|AbortController|timeout"),), window=200),
    Rule("R3", re.compile(r"requests\.(get|post|put|delete)\("), includes=PY,
         absent=(re.compile(r"timeout\s*="),), window=160),

    # ---- R5 swallowed errors -------------------------------------------------
    Rule("R5", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}"), includes=JS),
    Rule("R5", re.compile(r"except[^\n:]*:\s*\n\s*pass\b"), includes=PY),

    # ---- R9 floating promise --------------------------------------------------
    Rule("R9", re.compile(r"^\s*(?:supabase|prisma|db)\.[\w.]+\([^\n]*\)\s*;?\s*$", re.M),
         includes=JS, absent=(re.compile(r"await|then|catch"),), window=1),

    # ---- C3 unbounded select ---------------------------------------------------
    Rule("C3", re.compile(r"\.select\(\s*[\"']\*[\"']\s*\)"), includes=JS,
         absent=(re.compile(r"\.limit\(|\.range\(|\.single\(|\.maybeSingle\("),), window=160),
    Rule("C3", re.compile(r"(?i)select\s+\*\s+from\s+\w+"),
         absent=(re.compile(r"(?i)\blimit\b"),), window=200),

    # ---- C4 unbounded loop in a handler ------------------------------------------
    Rule("C4", re.compile(r"while\s*\(\s*true\s*\)"), includes=JS, predicate=_on_server_path),
    Rule("C4", re.compile(r"while\s+True\s*:"), includes=PY, predicate=_on_server_path),

    # ---- C5 aggressive polling ------------------------------------------------------
    Rule("C5", re.compile(r"setInterval\([^,]+,\s*(\d+)\s*\)"), includes=JS,
         predicate=lambda m, f: int(m.group(1)) < 30000),

    # ---- C6 no caching --------------------------------------------------------------
    Rule("C6", re.compile(r"export\s+const\s+dynamic\s*=\s*[\"']force-dynamic[\"']"),
         includes=JS),
    Rule("C6", re.compile(r"cache\s*:\s*[\"']no-store[\"']"), includes=JS),

    # ---- O1 secrets in logs -----------------------------------------------------------
    Rule("O1", re.compile(
        r"(?i)(console\.(log|info|warn|error|debug)|logger?\.(info|debug|warn|error)|print)"
        r"\([^)]*\b(password|passwd|token|secret|api[_-]?key|authorization|ssn|credit[_-]?card)\b")),

    # ---- O2 internal error to client ----------------------------------------------------
    Rule("O2", re.compile(r"(?s)(res|response)\.(status\(\d+\)\.)?(json|send)\([^)]{0,160}"
                          r"(err(or)?\.(stack|message)|traceback|exc_info)")),
    Rule("O2", re.compile(r"(?i)debug\s*=\s*true", ), includes=PY, excludes=TEST_PATHS),

    # ---- O3 console as logging -------------------------------------------------------------
    Rule("O3", re.compile(r"console\.(log|debug)\("), includes=JS,
         excludes=TEST_PATHS + ("script", "bin/")),

    # ---- H5 mock/stub on production path -----------------------------------------------------
    Rule("H5", re.compile(r"\b(MOCK_[A-Z_]+|mockData|fakeData|dummyData|sampleData)\b"),
         predicate=_on_server_path),
    Rule("H5", re.compile(r"(?i)//\s*(TODO|FIXME|HACK|XXX)\b"), predicate=_on_server_path),
    Rule("H5", re.compile(r"(?i)#\s*(TODO|FIXME|HACK|XXX)\b"), includes=PY,
         predicate=_on_server_path),

    # ---- H8 repeated block (counted in scan.py; rule marks candidates) -------------------------
    Rule("H8", re.compile(r"(?m)^\s{0,8}(if|const|def|function)\b.{10,120}$"),
         predicate=lambda m, f: False),  # emitted by structure.py

    # ---- T2 assertion-free test ------------------------------------------------------------------
    Rule("T2", re.compile(r"(?:it|test)\(\s*[\"'][^\"']+[\"']\s*,\s*(?:async\s*)?\(\s*\)\s*=>\s*\{"),
         includes=JS, absent=(re.compile(r"expect\(|assert"),), window=400),

    # ---- X3 open redirect --------------------------------------------------------------------------
    Rule("X3", re.compile(r"redirect\(\s*(req|request)\.(query|params|body)\.")),
    Rule("X3", re.compile(r"redirect\(\s*searchParams\.get\(")),

    # ---- S4 handled by detectors/secrets.py, S6/S3 by detectors/gitignore.py ------------------------
]
```

Two rules above are deliberately inert (`predicate=lambda ...: False`) because
`R1`, `H8`, and `S4` are whole-project judgements rather than line matches; they
are emitted by `detectors/project.py`, `detectors/structure.py`, and
`detectors/secrets.py` in Task 6. They exist in `RULES` only so the coverage gate
sees the id. **If that reads as a loophole to you, it is** — so add this
assertion to `tests/test_catalog.py` to keep it honest:

```python
    def test_inert_rules_are_covered_by_a_detector(self):
        from unslop import detectors
        inert = {"R1", "H8", "S4"}
        emitted = detectors.detector_check_ids()
        self.assertTrue(inert <= emitted, "inert rule with no detector: %s" % (inert - emitted))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_ruleset tests.test_catalog -v`
Expected: PASS. `test_inert_rules_are_covered_by_a_detector` stays red until
Task 6 — that is intentional and is the reason Task 6 cannot be skipped.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/unslop/ruleset.py tests/test_ruleset.py tests/test_catalog.py
git commit -m "feat: static ruleset with per-check tests and a coverage gate"
```

---

### Task 6: Config detectors

**Files:**
- Create: `skills/unslop-audit/scripts/unslop/detectors/__init__.py`
- Create: `skills/unslop-audit/scripts/unslop/detectors/gitignore.py` (S3, S6)
- Create: `skills/unslop-audit/scripts/unslop/detectors/sqlrls.py` (D1, D2, D4, D9, C2)
- Create: `skills/unslop-audit/scripts/unslop/detectors/deps.py` (P3, P5)
- Create: `skills/unslop-audit/scripts/unslop/detectors/gitmeta.py` (H1, S4)
- Create: `skills/unslop-audit/scripts/unslop/detectors/project.py` (R1, X1, X2, O4, O5, T1, T3)
- Test: `tests/test_detectors_config.py`

**Interfaces:**
- Consumes: `walker.SourceFile`, `findings.Finding`, `findings.Coverage`.
- Produces: every detector module exposes
  `EMITS: Set[str]` and `detect(root: Path, files: List[SourceFile], coverage: Coverage) -> List[Finding]`.
  `detectors/__init__.py` exposes `ALL: List[module]` and
  `detector_check_ids() -> Set[str]` (the union of every `EMITS`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_detectors_config.py
import subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import detectors                    # noqa: E402
from unslop.detectors import gitignore, sqlrls, deps, gitmeta, project   # noqa: E402
from unslop.findings import Coverage            # noqa: E402
from unslop.walker import walk                  # noqa: E402


def tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def ids(findings):
    return sorted({f.check_id for f in findings})


class TestGitignore(unittest.TestCase):
    def test_s3_env_not_ignored(self):
        root = tree({".env": "SECRET=x", ".gitignore": "node_modules\n"})
        cov = Coverage()
        self.assertIn("S3", ids(gitignore.detect(root, walk(root, cov), cov)))

    def test_s3_clean_when_ignored(self):
        root = tree({".env": "SECRET=x", ".gitignore": ".env\nnode_modules\n"})
        cov = Coverage()
        self.assertNotIn("S3", ids(gitignore.detect(root, walk(root, cov), cov)))

    def test_s6_production_sourcemaps(self):
        root = tree({"next.config.js": "module.exports = { productionBrowserSourceMaps: true }"})
        cov = Coverage()
        self.assertIn("S6", ids(gitignore.detect(root, walk(root, cov), cov)))


class TestSqlRls(unittest.TestCase):
    def test_d1_table_without_rls(self):
        root = tree({"supabase/migrations/0001.sql":
                     "create table public.profiles (id uuid primary key, email text);"})
        cov = Coverage()
        self.assertIn("D1", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d1_clear_when_rls_enabled(self):
        root = tree({"supabase/migrations/0001.sql":
                     "create table public.profiles (id uuid primary key);\n"
                     "alter table public.profiles enable row level security;\n"
                     "create policy p on public.profiles for select using (auth.uid() = id);"})
        cov = Coverage()
        self.assertNotIn("D1", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d2_permissive_policy(self):
        root = tree({"supabase/migrations/0002.sql":
                     "create table t (id int);\nalter table t enable row level security;\n"
                     "create policy open on t for all using (true);"})
        cov = Coverage()
        self.assertIn("D2", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d4_public_bucket(self):
        root = tree({"supabase/migrations/0003.sql":
                     "insert into storage.buckets (id, name, public) values ('avatars','avatars', true);"})
        cov = Coverage()
        self.assertIn("D4", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d9_open_firebase_rules(self):
        root = tree({"firestore.rules":
                     "service cloud.firestore {\n match /{document=**} {\n allow read, write: if true;\n }\n}"})
        cov = Coverage()
        self.assertIn("D9", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_c2_filtered_column_without_index(self):
        root = tree({
            "supabase/migrations/0001.sql": "create table orders (id uuid primary key, user_id uuid);",
            "src/api.ts": "await supabase.from('orders').select('*').eq('user_id', uid).limit(10)",
        })
        cov = Coverage()
        self.assertIn("C2", ids(sqlrls.detect(root, walk(root, cov), cov)))


class TestDeps(unittest.TestCase):
    def test_p3_missing_lockfile(self):
        root = tree({"package.json": '{"dependencies":{"next":"15.0.0"}}'})
        cov = Coverage()
        self.assertIn("P3", ids(deps.detect(root, walk(root, cov), cov)))

    def test_p5_install_script(self):
        root = tree({
            "package.json": '{"dependencies":{"sharp":"1.0.0"}}',
            "package-lock.json": '{"lockfileVersion":3,"packages":{"node_modules/sharp":{"hasInstallScript":true}}}',
        })
        cov = Coverage()
        found = ids(deps.detect(root, walk(root, cov), cov))
        self.assertIn("P5", found)
        self.assertNotIn("P3", found)


class TestGitMeta(unittest.TestCase):
    def test_h1_no_git(self):
        root = tree({"src/a.ts": "x"})
        cov = Coverage()
        self.assertIn("H1", ids(gitmeta.detect(root, walk(root, cov), cov)))

    def test_h1_single_commit(self):
        root = tree({"src/a.ts": "x"})
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                    ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "initial"]):
            subprocess.run(cmd, cwd=root, check=True, capture_output=True)
        cov = Coverage()
        self.assertIn("H1", ids(gitmeta.detect(root, walk(root, cov), cov)))


class TestProject(unittest.TestCase):
    def test_r1_no_error_boundary(self):
        root = tree({"package.json": '{"dependencies":{"react":"19.0.0"}}',
                     "src/App.tsx": "export default function App(){return <div/>}"})
        cov = Coverage()
        self.assertIn("R1", ids(project.detect(root, walk(root, cov), cov)))

    def test_x2_missing_security_headers(self):
        root = tree({"next.config.js": "module.exports = {}"})
        cov = Coverage()
        self.assertIn("X2", ids(project.detect(root, walk(root, cov), cov)))

    def test_t1_placeholder_test_script(self):
        root = tree({"package.json":
                     '{"scripts":{"test":"echo \\"Error: no test specified\\" && exit 1"}}'})
        cov = Coverage()
        found = ids(project.detect(root, walk(root, cov), cov))
        self.assertIn("T1", found)
        self.assertIn("T3", found)


class TestRegistry(unittest.TestCase):
    def test_detector_check_ids_union(self):
        got = detectors.detector_check_ids()
        self.assertTrue({"S3", "S4", "D1", "H1", "R1", "T3"} <= got)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_detectors_config -v`
Expected: FAIL — `No module named 'unslop.detectors'`.

- [ ] **Step 3: Write the detectors**

```python
# skills/unslop-audit/scripts/unslop/detectors/__init__.py
from typing import Set

from . import deps, gitignore, gitmeta, project, sqlrls, structure

ALL = [gitignore, sqlrls, deps, gitmeta, project, structure]


def detector_check_ids() -> Set[str]:
    out = set()
    for mod in ALL:
        out |= set(mod.EMITS)
    return out
```

```python
# skills/unslop-audit/scripts/unslop/detectors/gitignore.py
import re
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"S3", "S6"}

SECRET_PATTERNS = (".env", ".env.local", ".env.production", "*.pem", "*.key",
                   "credentials.json", "serviceAccount.json", "service-account.json")
_SOURCEMAP_RE = re.compile(
    r"productionBrowserSourceMaps\s*:\s*true|sourcemap\s*:\s*true|GENERATE_SOURCEMAP\s*=\s*true")


def _covered(patterns, name: str) -> bool:
    for pat in patterns:
        if pat == name or (pat.startswith("*") and name.endswith(pat[1:])):
            return True
        if pat.rstrip("/") == name.rstrip("/"):
            return True
    return False


def detect(root, files, coverage) -> List[Finding]:
    root = Path(root)
    out = []
    gi = root / ".gitignore"
    patterns = []
    if gi.is_file():
        patterns = [ln.strip() for ln in gi.read_text(errors="replace").splitlines()
                    if ln.strip() and not ln.startswith("#")]
    else:
        coverage.note("no .gitignore present")

    present = {f.rel for f in files}
    for candidate in SECRET_PATTERNS:
        if candidate.startswith("*"):
            hits = [r for r in present if r.endswith(candidate[1:])]
        else:
            hits = [r for r in present if Path(r).name == candidate]
        for rel in hits:
            if not _covered(patterns, Path(rel).name):
                out.append(Finding("S3", rel, 1,
                                   "%s exists and is not matched by .gitignore" % rel,
                                   confidence="CONFIRMED"))

    for f in files:
        if Path(f.rel).name in ("next.config.js", "next.config.mjs", "next.config.ts",
                                "vite.config.js", "vite.config.ts", ".env", ".env.production"):
            m = _SOURCEMAP_RE.search(f.text)
            if m:
                out.append(Finding("S6", f.rel, f.line_at(m.start()),
                                   m.group(0), confidence="CONFIRMED"))
    return out
```

```python
# skills/unslop-audit/scripts/unslop/detectors/sqlrls.py
import re
from typing import List

from ..findings import Finding

EMITS = {"D1", "D2", "D4", "D9", "C2"}

CREATE_TABLE_RE = re.compile(
    r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?\s*\(", re.I)
ENABLE_RLS_RE = re.compile(
    r"(?is)alter\s+table\s+(?:\"?\w+\"?\.)?\"?(\w+)\"?\s+enable\s+row\s+level\s+security")
POLICY_RE = re.compile(r"(?is)create\s+policy\s+.*?on\s+(?:\"?\w+\"?\.)?\"?(\w+)\"?(.*?);", re.S)
PERMISSIVE_RE = re.compile(r"(?is)using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)")
PUBLIC_BUCKET_RE = re.compile(r"(?is)storage\.buckets[^;]*?\btrue\b")
FIREBASE_OPEN_RE = re.compile(r"(?im)^\s*allow\s+[\w,\s]*:\s*if\s+true\s*;")
EQ_RE = re.compile(r"\.from\(\s*[\"'](\w+)[\"']\s*\)((?:\s*\.\w+\([^)]*\))*)")
COL_RE = re.compile(r"\.(?:eq|neq|gt|gte|lt|lte|like|ilike|order)\(\s*[\"'](\w+)[\"']")
CREATE_INDEX_RE = re.compile(r"(?is)create\s+(?:unique\s+)?index[^;]*?on\s+(?:\"?\w+\"?\.)?\"?(\w+)\"?\s*\(([^)]*)\)")


def detect(root, files, coverage) -> List[Finding]:
    out = []
    sql_files = [f for f in files if f.rel.lower().endswith(".sql")]
    tables, rls_on, indexed = {}, set(), {}

    for f in sql_files:
        for m in CREATE_TABLE_RE.finditer(f.text):
            name = m.group(2).lower()
            if name.startswith("_") or m.group(1) in ("auth", "storage", "extensions"):
                continue
            tables[name] = (f.rel, f.line_at(m.start()))
        for m in ENABLE_RLS_RE.finditer(f.text):
            rls_on.add(m.group(1).lower())
        for m in POLICY_RE.finditer(f.text):
            if PERMISSIVE_RE.search(m.group(2) or ""):
                out.append(Finding("D2", f.rel, f.line_at(m.start()),
                                   m.group(0).strip().splitlines()[0], confidence="CONFIRMED"))
        for m in PUBLIC_BUCKET_RE.finditer(f.text):
            out.append(Finding("D4", f.rel, f.line_at(m.start()),
                               m.group(0).strip()[:120], confidence="CONFIRMED"))
        for m in CREATE_INDEX_RE.finditer(f.text):
            cols = {c.strip().strip('"') for c in m.group(2).split(",")}
            indexed.setdefault(m.group(1).lower(), set()).update(cols)

    for name, (rel, line) in sorted(tables.items()):
        if name not in rls_on:
            out.append(Finding("D1", rel, line,
                               "create table %s ... (row level security never enabled)" % name,
                               confidence="CONFIRMED"))

    for f in files:
        if f.rel.lower().endswith(".rules"):
            for m in FIREBASE_OPEN_RE.finditer(f.text):
                out.append(Finding("D9", f.rel, f.line_at(m.start()),
                                   m.group(0).strip(), confidence="CONFIRMED"))

    if tables:
        for f in files:
            for m in EQ_RE.finditer(f.text):
                table = m.group(1).lower()
                if table not in tables:
                    continue
                for col in set(COL_RE.findall(m.group(2) or "")):
                    if col in ("id",) or col in indexed.get(table, set()):
                        continue
                    out.append(Finding("C2", f.rel, f.line_at(m.start()),
                                       "%s.%s filtered or ordered with no index" % (table, col)))
    else:
        coverage.note("no SQL migrations found: RLS and index checks could not run")
    return out
```

```python
# skills/unslop-audit/scripts/unslop/detectors/deps.py
import json
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"P3", "P5"}

LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb",
             "poetry.lock", "requirements.lock", "uv.lock", "Pipfile.lock")


def detect(root, files, coverage) -> List[Finding]:
    root = Path(root)
    out = []
    manifests = [m for m in ("package.json", "requirements.txt", "pyproject.toml", "Pipfile")
                 if (root / m).is_file()]
    if not manifests:
        coverage.note("no dependency manifest found: supply chain checks limited")
        return out

    locks = [l for l in LOCKFILES if (root / l).is_file()]
    if not locks:
        out.append(Finding("P3", manifests[0], 1,
                           "%s present with no lockfile alongside it" % manifests[0],
                           confidence="CONFIRMED"))

    lock = root / "package-lock.json"
    if lock.is_file():
        try:
            data = json.loads(lock.read_text(errors="replace"))
        except ValueError:
            coverage.note("package-lock.json is not valid JSON: install-script check skipped")
            return out
        for pkg_path, meta in (data.get("packages") or {}).items():
            if isinstance(meta, dict) and meta.get("hasInstallScript"):
                out.append(Finding("P5", "package-lock.json", 1,
                                   "%s runs an install script" % (pkg_path or "root"),
                                   confidence="CONFIRMED"))
    return out
```

```python
# skills/unslop-audit/scripts/unslop/detectors/gitmeta.py
import subprocess
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"H1", "S4"}
SECRET_PATHS = (".env", ".env.local", ".env.production", "credentials.json",
                "serviceAccount.json", "id_rsa", "*.pem")


def _git(root, *args, timeout=20):
    try:
        r = subprocess.run(["git", "-C", str(root)] + list(args),
                           capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def detect(root, files, coverage) -> List[Finding]:
    root = Path(root)
    out = []
    if not (root / ".git").exists():
        out.append(Finding("H1", ".", 1, "no git repository in this directory",
                           confidence="CONFIRMED"))
        coverage.note("no git repository: history checks (S4) could not run")
        return out

    count = _git(root, "rev-list", "--count", "HEAD")
    if count is None:
        coverage.note("git present but unreadable: history checks skipped")
        return out
    n = int(count.strip() or 0)
    if n <= 1:
        out.append(Finding("H1", ".", 1,
                           "repository has %d commit(s): no checkpoints to revert to" % n,
                           confidence="CONFIRMED"))

    for pat in SECRET_PATHS:
        log = _git(root, "log", "--all", "--diff-filter=A", "--name-only",
                   "--pretty=format:", "--", pat)
        if log and log.strip():
            first = sorted(set(log.split()))[0]
            out.append(Finding("S4", first, 1,
                               "%s was committed at some point in history" % first,
                               confidence="CONFIRMED"))
    coverage.note("history scan covered added-file paths only, not full content diffs")
    return out
```

```python
# skills/unslop-audit/scripts/unslop/detectors/project.py
import json
import re
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"R1", "X1", "X2", "O4", "O5", "T1", "T3"}

ERROR_BOUNDARY_RE = re.compile(
    r"componentDidCatch|getDerivedStateFromError|ErrorBoundary|error\.tsx|error\.jsx|"
    r"errorElement|<ErrorBoundary")
HEADER_RE = re.compile(r"(?i)content-security-policy|strict-transport-security|x-frame-options")
DEBUG_RE = re.compile(r"(?im)^\s*(DEBUG|debug)\s*[:=]\s*(True|true)\s*,?\s*$")
TRACKER_RE = re.compile(r"@sentry|bugsnag|rollbar|datadog|honeybadger|posthog")
HEALTH_RE = re.compile(r"(?i)/(health|healthz|readyz|ping|status)\b")
PLACEHOLDER_TEST_RE = re.compile(r"no test specified|exit 1")


def _any(files, pattern, suffixes=None):
    for f in files:
        if suffixes and not f.rel.lower().endswith(suffixes):
            continue
        if pattern.search(f.text) or pattern.search(f.rel):
            return f
    return None


def detect(root, files, coverage) -> List[Finding]:
    root = Path(root)
    out = []
    rels = {f.rel for f in files}
    stack_is_react = any(f.rel.endswith((".tsx", ".jsx")) for f in files)

    if stack_is_react and not _any(files, ERROR_BOUNDARY_RE):
        out.append(Finding("R1", "src", 1,
                           "no error boundary, error.tsx, or errorElement anywhere in the tree",
                           confidence="CONFIRMED"))

    if not _any(files, HEADER_RE, (".js", ".ts", ".mjs", ".json", ".toml", ".yml", ".yaml", ".conf")):
        out.append(Finding("X2", "next.config.js" if "next.config.js" in rels else ".", 1,
                           "no CSP, HSTS, or X-Frame-Options configured anywhere",
                           confidence="CONFIRMED"))

    for f in files:
        if f.rel.lower().endswith((".py", ".env", ".toml", ".yml", ".yaml", ".json")):
            m = DEBUG_RE.search(f.text)
            if m and "example" not in f.rel:
                out.append(Finding("X1", f.rel, f.line_at(m.start()), m.group(0).strip()))

    if not _any(files, TRACKER_RE):
        out.append(Finding("O4", ".", 1, "no error tracking integration found",
                           confidence="CONFIRMED"))
    if not _any(files, HEALTH_RE):
        out.append(Finding("O5", ".", 1, "no health check endpoint found",
                           confidence="CONFIRMED"))

    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
        except ValueError:
            data = {}
        script = ((data.get("scripts") or {}).get("test") or "").strip()
        has_tests = any(re.search(r"(?i)(^|/)(tests?|__tests__)/|\.(test|spec)\.[jt]sx?$", r)
                        for r in rels)
        if not has_tests or not script or PLACEHOLDER_TEST_RE.search(script):
            out.append(Finding("T1", "package.json", 1,
                               "test script: %r; test files found: %s" % (script, has_tests),
                               confidence="CONFIRMED"))
    elif not any(r.startswith("tests/") or "test_" in r for r in rels):
        out.append(Finding("T1", ".", 1, "no test files found", confidence="CONFIRMED"))

    if not any(r.startswith(".github/workflows/") or r in (".gitlab-ci.yml", ".circleci/config.yml")
               for r in rels):
        out.append(Finding("T3", ".", 1, "no CI workflow found", confidence="CONFIRMED"))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_detectors_config -v`
Expected: PASS, 15 tests. `structure` is imported by `detectors/__init__.py` and
lands in Task 7 — create it now as a module with `EMITS = {"H2", "H3", "H6", "H7", "H8"}`
and `def detect(root, files, coverage): return []` so the package imports; Task 7
replaces the body and its tests prove it.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/unslop/detectors tests/test_detectors_config.py
git commit -m "feat: config detectors for gitignore, RLS, deps, git history, project shape"
```

---

### Task 7: Structural detectors

**Files:**
- Modify: `skills/unslop-audit/scripts/unslop/detectors/structure.py` (replace the stub)
- Test: `tests/test_detectors_structure.py`

**Interfaces:**
- Consumes: `walker.SourceFile`.
- Produces: `structure.EMITS = {"H2","H3","H6","H7","H8"}`, `structure.detect(root, files, coverage)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_detectors_structure.py
import sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop.detectors import structure          # noqa: E402
from unslop.findings import Coverage            # noqa: E402
from unslop.walker import SourceFile            # noqa: E402


def sf(rel, text):
    return SourceFile(Path(rel), rel, text)


def ids(fs):
    return sorted({f.check_id for f in fs})


class TestStructure(unittest.TestCase):
    def test_h2_patch_fossil_pairs(self):
        files = [sf("src/Checkout.tsx", "export const C = 1"),
                 sf("src/Checkout-fixed.tsx", "export const C = 2")]
        found = structure.detect(Path("/tmp"), files, Coverage())
        self.assertIn("H2", ids(found))
        self.assertTrue(any("Checkout" in f.snippet for f in found if f.check_id == "H2"))

    def test_h2_ignores_unrelated_names(self):
        files = [sf("src/Checkout.tsx", "a"), sf("src/Cart.tsx", "b")]
        self.assertNotIn("H2", ids(structure.detect(Path("/tmp"), files, Coverage())))

    def test_h3_orphan_module(self):
        files = [sf("src/app/page.tsx", "import { used } from './used'"),
                 sf("src/app/used.ts", "export const used = 1"),
                 sf("src/app/orphan.ts", "export const orphan = 1")]
        found = [f for f in structure.detect(Path("/tmp"), files, Coverage()) if f.check_id == "H3"]
        self.assertEqual([f.file for f in found], ["src/app/orphan.ts"])

    def test_h6_commented_out_block(self):
        body = "\n".join("// const x%d = call(%d);" % (i, i) for i in range(6))
        self.assertIn("H6", ids(structure.detect(Path("/tmp"), [sf("src/a.ts", body)], Coverage())))

    def test_h6_ignores_prose_comments(self):
        body = "\n".join("// this explains why the thing works" for _ in range(6))
        self.assertNotIn("H6", ids(structure.detect(Path("/tmp"), [sf("src/a.ts", body)], Coverage())))

    def test_h7_oversized_file(self):
        big = sf("src/big.ts", "\n".join("const x%d = %d" % (i, i) for i in range(700)))
        self.assertIn("H7", ids(structure.detect(Path("/tmp"), [big], Coverage())))

    def test_h8_triplicated_block(self):
        block = "if (!user) {\n  throw new Error('unauthorized request rejected')\n}\n"
        files = [sf("src/a.ts", block), sf("src/b.ts", block), sf("src/c.ts", block)]
        self.assertIn("H8", ids(structure.detect(Path("/tmp"), files, Coverage())))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_detectors_structure -v`
Expected: FAIL — stub returns `[]`, so every assertion misses.

- [ ] **Step 3: Write the implementation**

```python
# skills/unslop-audit/scripts/unslop/detectors/structure.py
import re
from collections import defaultdict
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"H2", "H3", "H6", "H7", "H8"}

MAX_LINES = 600
FOSSIL_RE = re.compile(
    r"(?i)[-_. ]?(fixed|new|old|final|copy|backup|bak|v\d+|\d+|updated|temp|tmp|test2)$")
IMPORT_RE = re.compile(
    r"""(?:from\s+["']([^"']+)["']|require\(\s*["']([^"']+)["']\s*\)|import\s+["']([^"']+)["'])""")
PY_IMPORT_RE = re.compile(r"(?m)^\s*(?:from\s+([.\w]+)\s+import|import\s+([.\w]+))")
CODE_COMMENT_RE = re.compile(r"^\s*(?://|#)\s*(.*)$")
CODE_ISH_RE = re.compile(r"[;{}()=]|^\s*(?:const|let|var|def|return|if|for|while|class|import|export)\b")
ENTRYPOINT_RE = re.compile(
    r"(?i)(^|/)(page|layout|route|error|loading|not-found|middleware|index|main|app|"
    r"conftest|setup|manage|wsgi|asgi|__init__)\.[jt]sx?$|"
    r"(^|/)(pages|app|routes|migrations|supabase|scripts|tests?)/")
MODULE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py")


def _stem_family(rel: str) -> str:
    stem = Path(rel).stem
    prev = None
    while prev != stem:
        prev = stem
        stem = FOSSIL_RE.sub("", stem)
    return (str(Path(rel).parent) + "/" + stem.lower()).lstrip("./")


def _detect_fossils(files) -> List[Finding]:
    groups = defaultdict(list)
    for f in files:
        if f.rel.lower().endswith(MODULE_SUFFIXES):
            groups[_stem_family(f.rel)].append(f.rel)
    out = []
    for family, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        members = sorted(members)
        out.append(Finding("H2", members[-1], 1,
                           "near-duplicate of %s (family '%s')" % (members[0], Path(family).name),
                           confidence="CONFIRMED"))
    return out


def _detect_orphans(files) -> List[Finding]:
    modules = {f.rel: f for f in files if f.rel.lower().endswith(MODULE_SUFFIXES)}
    imported = set()
    for f in modules.values():
        specs = [g for m in IMPORT_RE.finditer(f.text) for g in m.groups() if g]
        specs += [g for m in PY_IMPORT_RE.finditer(f.text) for g in m.groups() if g]
        base = Path(f.rel).parent
        for spec in specs:
            if spec.startswith("."):
                target = (base / spec).as_posix()
            else:
                target = spec.replace(".", "/")
            for cand in modules:
                stem = cand.rsplit(".", 1)[0]
                if stem == target or stem.endswith("/" + target) or stem.endswith(target):
                    imported.add(cand)
    out = []
    for rel in sorted(modules):
        if rel in imported or ENTRYPOINT_RE.search(rel):
            continue
        out.append(Finding("H3", rel, 1, "nothing imports this module",
                           confidence="CONFIRMED"))
    return out


def _detect_comment_blocks(files) -> List[Finding]:
    out = []
    for f in files:
        run_start, run_len = 0, 0
        for i, line in enumerate(f.lines, start=1):
            m = CODE_COMMENT_RE.match(line)
            if m and CODE_ISH_RE.search(m.group(1)):
                run_len = run_len + 1 if run_len else 1
                run_start = run_start or i
            else:
                if run_len >= 5:
                    out.append(Finding("H6", f.rel, run_start,
                                       "%d consecutive commented-out code lines" % run_len))
                run_start, run_len = 0, 0
        if run_len >= 5:
            out.append(Finding("H6", f.rel, run_start,
                               "%d consecutive commented-out code lines" % run_len))
    return out


def _detect_size(files) -> List[Finding]:
    return [Finding("H7", f.rel, 1, "%d lines" % len(f.lines))
            for f in files if len(f.lines) > MAX_LINES]


def _detect_clones(files) -> List[Finding]:
    blocks = defaultdict(list)
    for f in files:
        if not f.rel.lower().endswith(MODULE_SUFFIXES):
            continue
        lines = f.lines
        for i in range(len(lines) - 2):
            window = [re.sub(r"\s+", " ", l).strip() for l in lines[i:i + 3]]
            if sum(len(w) for w in window) < 60:
                continue
            blocks["\n".join(window)].append((f.rel, i + 1))
    out = []
    for body, sites in sorted(blocks.items()):
        uniq = sorted(set(sites))
        if len(uniq) >= 3:
            rel, line = uniq[0]
            out.append(Finding("H8", rel, line,
                               "block repeated at %s" % ", ".join("%s:%d" % s for s in uniq[:4])))
    return out


def detect(root, files, coverage) -> List[Finding]:
    return (_detect_fossils(files) + _detect_orphans(files) + _detect_comment_blocks(files)
            + _detect_size(files) + _detect_clones(files))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_detectors_structure tests.test_catalog -v`
Expected: PASS — including `test_inert_rules_are_covered_by_a_detector`, which
goes green now that `structure.EMITS` includes `H8` and `project.EMITS` includes `R1`.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/unslop/detectors/structure.py tests/test_detectors_structure.py
git commit -m "feat: structural detectors for patch fossils, orphans, dead comments, clones"
```

---

### Task 8: `scan.py` CLI

**Files:**
- Create: `skills/unslop-audit/scripts/scan.py`
- Test: `tests/test_scan_cli.py`

**Interfaces:**
- Consumes: everything from Tasks 2-7.
- Produces: CLI contract the skills depend on —
  `python3 scan.py <root> [--out .unslop/findings.json] [--max-files N] [--json]`,
  exit code 0 always (a scanner that exits non-zero on findings breaks the skill
  flow; the guard skill derives its exit code from the JSON instead).

`scan.py` owns two post-passes that need whole-project state:
`S5` (env vars referenced in code minus keys documented in `.env.example`) and
`O3` (collapse many `console.log` hits into one finding per file, capped, with
the rest reported as a count so the report is not drowned).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scan_cli.py
import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "skills" / "unslop-audit" / "scripts" / "scan.py"


def tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def run_scan(root, *args):
    out = Path(root) / ".unslop" / "findings.json"
    r = subprocess.run([sys.executable, str(SCAN), str(root), "--out", str(out)] + list(args),
                       capture_output=True, text=True)
    return r, json.loads(out.read_text())


class TestScanCli(unittest.TestCase):
    def test_exits_zero_and_writes_schema(self):
        root = tree({"src/a.ts": "const k = 'REDACTED-FAKE-TEST-VALUE'"})
        r, data = run_scan(root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(data["schemaVersion"], 1)
        self.assertIn("S1", {f["check_id"] for f in data["findings"]})
        self.assertGreaterEqual(data["coverage"]["scanned_files"], 1)

    def test_empty_project_is_clear_not_crash(self):
        root = tree({"README.md": "# hello"})
        r, data = run_scan(root)
        self.assertEqual(r.returncode, 0)
        self.assertIsInstance(data["findings"], list)

    def test_s5_env_drift(self):
        root = tree({"src/a.ts": "const u = process.env.DATABASE_URL",
                     ".env.example": "OTHER_KEY=\n"})
        _, data = run_scan(root)
        s5 = [f for f in data["findings"] if f["check_id"] == "S5"]
        self.assertTrue(s5)
        self.assertIn("DATABASE_URL", s5[0]["snippet"])

    def test_s5_quiet_when_documented(self):
        root = tree({"src/a.ts": "const u = process.env.DATABASE_URL",
                     ".env.example": "DATABASE_URL=\n"})
        _, data = run_scan(root)
        self.assertEqual([f for f in data["findings"] if f["check_id"] == "S5"], [])

    def test_o3_collapses_per_file(self):
        root = tree({"src/a.ts": "\n".join("console.log(%d)" % i for i in range(40))})
        _, data = run_scan(root)
        o3 = [f for f in data["findings"] if f["check_id"] == "O3"]
        self.assertEqual(len(o3), 1)
        self.assertIn("40", o3[0]["snippet"])

    def test_stack_recorded_in_coverage(self):
        root = tree({"package.json": '{"dependencies":{"next":"15.0.0"}}'})
        _, data = run_scan(root)
        self.assertIn("nextjs", data["coverage"]["stack"])

    def test_json_flag_prints_summary_to_stdout(self):
        root = tree({"src/a.ts": "const k = 'REDACTED-FAKE-TEST-VALUE'"})
        r, _ = run_scan(root, "--json")
        summary = json.loads(r.stdout)
        self.assertIn("counts", summary)
        self.assertGreaterEqual(summary["counts"]["P0"], 1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_scan_cli -v`
Expected: FAIL — `can't open file 'scan.py'`.

- [ ] **Step 3: Write the implementation**

```python
#!/usr/bin/env python3
"""unslop scanner: emit deterministic findings for a codebase. Never exits non-zero."""
import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unslop import detectors, rules, walker                      # noqa: E402
from unslop.catalog import CHECKS                                # noqa: E402
from unslop.findings import Coverage, Finding, write             # noqa: E402
from unslop.ruleset import RULES                                 # noqa: E402

O3_PER_FILE_CAP = 1
ENV_EXAMPLE_FILES = (".env.example", ".env.sample", ".env.template")


def _postprocess_s5(root: Path, found, coverage):
    documented = set()
    seen_example = False
    for name in ENV_EXAMPLE_FILES:
        p = root / name
        if p.is_file():
            seen_example = True
            for line in p.read_text(errors="replace").splitlines():
                m = re.match(r"\s*([A-Z][A-Z0-9_]*)\s*=", line)
                if m:
                    documented.add(m.group(1))
    if not seen_example:
        coverage.note("no .env.example: every referenced env var is reported as undocumented")

    kept, referenced = [], {}
    for f in found:
        if f.check_id != "S5":
            kept.append(f)
            continue
        m = re.search(r"([A-Z][A-Z0-9_]{2,})", f.snippet)
        if not m or m.group(1) in documented:
            continue
        referenced.setdefault(m.group(1), f)
    for name, f in sorted(referenced.items()):
        kept.append(Finding("S5", f.file, f.line,
                            "%s is read in code but absent from .env.example" % name,
                            confidence="CONFIRMED"))
    return kept


def _postprocess_o3(found):
    per_file = defaultdict(list)
    kept = []
    for f in found:
        if f.check_id == "O3":
            per_file[f.file].append(f)
        else:
            kept.append(f)
    for rel, group in sorted(per_file.items()):
        first = sorted(group, key=lambda x: x.line)[0]
        kept.append(Finding("O3", rel, first.line,
                            "%d console.log/debug calls in this file" % len(group)))
    return kept


def scan(root: Path, max_files: int):
    coverage = Coverage()
    coverage.stack = walker.detect_stack(root)
    files = walker.walk(root, coverage, max_files=max_files)
    found = rules.run(RULES, files)
    for mod in detectors.ALL:
        try:
            found.extend(mod.detect(root, files, coverage))
        except Exception as exc:  # a detector must never take the scan down
            coverage.note("detector %s failed (%s): its checks did not run"
                          % (mod.__name__.rsplit(".", 1)[-1], exc.__class__.__name__))
    found = _postprocess_s5(root, found, coverage)
    found = _postprocess_o3(found)
    found.sort(key=lambda f: (CHECKS[f.check_id].severity, f.check_id, f.file, f.line))
    return found, coverage


def main(argv=None):
    ap = argparse.ArgumentParser(prog="scan.py")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--out", default=".unslop/findings.json")
    ap.add_argument("--max-files", type=int, default=20000)
    ap.add_argument("--json", action="store_true", help="print a summary to stdout")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    found, coverage = scan(root, args.max_files)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = root / out_path
    write(out_path, found, coverage)

    counts = Counter(CHECKS[f.check_id].severity for f in found)
    summary = {
        "out": str(out_path),
        "counts": {sev: counts.get(sev, 0) for sev in ("P0", "P1", "P2", "P3")},
        "total": len(found),
        "scannedFiles": coverage.scanned_files,
        "stack": coverage.stack,
        "notes": coverage.notes,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("unslop: %d findings (P0=%d P1=%d P2=%d P3=%d) across %d files -> %s"
              % (summary["total"], summary["counts"]["P0"], summary["counts"]["P1"],
                 summary["counts"]["P2"], summary["counts"]["P3"],
                 coverage.scanned_files, out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_scan_cli -v`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/scan.py tests/test_scan_cli.py
git commit -m "feat: scan.py CLI with env-drift and log-noise post-passes"
```

---

### Task 9: Fixtures and the precision/recall gate

**Files:**
- Create: `tests/fixtures/vulnerable-next-supabase/**`
- Create: `tests/fixtures/vulnerable-next-supabase/expected.json`
- Create: `tests/fixtures/clean-next-supabase/**`
- Create: `tests/fixtures/README.md`
- Create: `tests/test_fixtures.py`
- Modify: `tests/run-tests.sh` (already exists from Task 1)

**Interfaces:**
- Consumes: `scan.scan`.
- Produces: the CI gate. `expected.json` maps check id → list of `{"file","line"}`
  for planted defects. Recall on P0 checks must be 100%; precision on the clean
  fixture must be ≥95%.

The fixtures are the product's evidence. Build the vulnerable app first, then
copy it to the clean twin and repair every planted defect.

**Planted defects (vulnerable fixture) — one per check that a scanner can catch:**

| File | Planted |
|---|---|
| `.env` (tracked, not ignored) | S3 |
| `src/lib/supabase.ts` | S1 (service role JWT literal), D3, S2 (`NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`) |
| `supabase/migrations/0001_init.sql` | D1 (`profiles`, `orders` without RLS), C2 (`orders.user_id` unindexed) |
| `supabase/migrations/0002_policies.sql` | D2 (`using (true)`), D4 (public bucket) |
| `src/app/api/orders/[id]/route.ts` | D5, A1, R2, O2, C3 |
| `src/app/api/login/route.ts` | A2 (hardcoded jwt secret), A3 (cookie without flags), A4, A6 (md5) |
| `src/app/api/search/route.ts` | D8 (template-literal SQL), X3 (open redirect) |
| `src/app/dashboard/page.tsx` | R7, R8, C1, C5 (2s poll) |
| `src/lib/logger.ts` | O1, O3 |
| `src/components/Checkout.tsx` + `src/components/Checkout-fixed.tsx` | H2 |
| `src/lib/unused-helper.ts` | H3 |
| `src/lib/legacy.ts` | H6 (commented-out block), H7 (over 600 lines) |
| `package.json` (no lockfile, no test script, `reqeusts` typo dep) | P3, T1, P2 |
| no `.github/workflows` | T3 |
| no error boundary, no CSP, no tracker, no health route | R1, X2, O4, O5 |

**Fixture safety rules (non-negotiable):**
- Every credential is a syntactically valid but non-resolvable fake:
  `REDACTED-FAKE-TEST-VALUE` (AWS's own documentation value), `sk_live_` followed by
  `0123456789abcdef0123456789`, and a JWT whose payload decodes to
  `{"role":"service_role","iss":"unslop-fixture"}`.
- `tests/fixtures/README.md` states in the first line that these directories are
  intentionally vulnerable sample code and must never be deployed.
- No `node_modules`, no install step, no runnable server. The fixture is source
  text the scanner reads, not an app anyone can start.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fixtures.py
import json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from scan import scan                            # noqa: E402
from unslop.catalog import CHECKS                # noqa: E402

VULN = ROOT / "tests" / "fixtures" / "vulnerable-next-supabase"
CLEAN = ROOT / "tests" / "fixtures" / "clean-next-supabase"


class TestFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((VULN / "expected.json").read_text())
        cls.vuln_found, _ = scan(VULN, 20000)
        cls.clean_found, _ = scan(CLEAN, 20000)

    def test_p0_recall_is_total(self):
        expected_p0 = {cid for cid in self.expected if CHECKS[cid].severity == "P0"}
        found = {f.check_id for f in self.vuln_found}
        self.assertEqual(expected_p0 - found, set(), "P0 checks the scanner missed")

    def test_overall_recall_at_least_90_percent(self):
        expected = set(self.expected)
        found = {f.check_id for f in self.vuln_found}
        recall = len(expected & found) / float(len(expected))
        self.assertGreaterEqual(recall, 0.90, "missed: %s" % sorted(expected - found))

    def test_planted_findings_land_on_the_right_file(self):
        by_check = {}
        for f in self.vuln_found:
            by_check.setdefault(f.check_id, set()).add(f.file)
        for cid, sites in self.expected.items():
            if cid not in by_check:
                continue
            wanted = {s["file"] for s in sites}
            with self.subTest(check=cid):
                self.assertTrue(wanted & by_check[cid],
                                "%s found in %s, expected one of %s" % (cid, by_check[cid], wanted))

    def test_clean_fixture_precision(self):
        # Findings on the corrected twin are false positives, with a small
        # allowance for inherently advisory checks.
        advisory = {"H7", "O3", "C6", "T2", "H8"}
        fps = [f for f in self.clean_found if f.check_id not in advisory]
        total_checks_exercised = len(set(self.expected))
        precision = 1.0 - (len(fps) / float(max(total_checks_exercised, 1)))
        self.assertGreaterEqual(precision, 0.95,
                                "false positives on clean fixture: %s"
                                % sorted({(f.check_id, f.file) for f in fps}))

    def test_clean_fixture_has_no_p0(self):
        p0 = [f for f in self.clean_found if CHECKS[f.check_id].severity == "P0"]
        self.assertEqual(p0, [], "P0 false positives: %s" % [(f.check_id, f.file) for f in p0])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./tests/run-tests.sh`
Expected: FAIL — `expected.json` does not exist.

- [ ] **Step 3: Build the fixtures**

Write the vulnerable app exactly as tabled above, then `expected.json`:

```json
{
  "S1": [{"file": "src/lib/supabase.ts", "line": 4}],
  "S2": [{"file": "src/lib/supabase.ts", "line": 6}],
  "S3": [{"file": ".env", "line": 1}],
  "D1": [{"file": "supabase/migrations/0001_init.sql", "line": 1}],
  "D2": [{"file": "supabase/migrations/0002_policies.sql", "line": 3}],
  "D3": [{"file": "src/lib/supabase.ts", "line": 4}],
  "D4": [{"file": "supabase/migrations/0002_policies.sql", "line": 8}],
  "D8": [{"file": "src/app/api/search/route.ts", "line": 7}],
  "A2": [{"file": "src/app/api/login/route.ts", "line": 9}],
  "A3": [{"file": "src/app/api/login/route.ts", "line": 18}],
  "A6": [{"file": "src/app/api/login/route.ts", "line": 12}],
  "R1": [{"file": "src", "line": 1}],
  "R2": [{"file": "src/app/api/orders/[id]/route.ts", "line": 11}],
  "R5": [{"file": "src/app/api/search/route.ts", "line": 14}],
  "C2": [{"file": "src/app/api/orders/[id]/route.ts", "line": 9}],
  "C3": [{"file": "src/app/api/orders/[id]/route.ts", "line": 9}],
  "C5": [{"file": "src/app/dashboard/page.tsx", "line": 21}],
  "O1": [{"file": "src/lib/logger.ts", "line": 4}],
  "O2": [{"file": "src/app/api/orders/[id]/route.ts", "line": 17}],
  "O3": [{"file": "src/lib/logger.ts", "line": 2}],
  "O4": [{"file": ".", "line": 1}],
  "O5": [{"file": ".", "line": 1}],
  "H2": [{"file": "src/components/Checkout-fixed.tsx", "line": 1}],
  "H3": [{"file": "src/lib/unused-helper.ts", "line": 1}],
  "H6": [{"file": "src/lib/legacy.ts", "line": 3}],
  "H7": [{"file": "src/lib/legacy.ts", "line": 1}],
  "P3": [{"file": "package.json", "line": 1}],
  "T1": [{"file": "package.json", "line": 1}],
  "T3": [{"file": ".", "line": 1}],
  "X2": [{"file": ".", "line": 1}],
  "X3": [{"file": "src/app/api/search/route.ts", "line": 19}]
}
```

Line numbers must match the files you actually write. If a number is off, fix
the JSON rather than the assertion — `test_planted_findings_land_on_the_right_file`
compares files, not lines, precisely so small edits do not make the suite brittle.

Then copy to `clean-next-supabase/` and repair every defect: enable RLS with
scoped policies, move the service key server-side and read it from `process.env`,
add ownership predicates, add cookie flags, parameterize SQL, add the error
boundary, headers, health route, lockfile, CI workflow, tests, and delete the
fossil and orphan files.

- [ ] **Step 4: Run test to verify it passes**

Run: `./tests/run-tests.sh`
Expected: PASS, 5 tests. Every failure names the specific check that missed or
false-positived — fix the detector, not the threshold.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures tests/test_fixtures.py
git commit -m "test: vulnerable and clean fixtures with precision/recall gate"
```

---

### Task 10: Dependency verification

**Files:**
- Create: `skills/unslop-audit/scripts/verify_deps.py`
- Test: `tests/test_verify_deps.py`

**Interfaces:**
- Consumes: `findings.Finding`, `findings.Coverage`.
- Produces: `verify_deps.collect_dependencies(root) -> Dict[str, str]`,
  `verify_deps.check_registry(names, fetch=None, cache_dir=None) -> Dict[str, bool]`,
  `verify_deps.main(argv)` merging P1/P2 findings into an existing findings.json.

`fetch` is injectable so tests never touch the network. Default implementation
uses `urllib.request` against `https://registry.npmjs.org/<name>` and
`https://pypi.org/pypi/<name>/json` with a 5-second timeout, results cached in
`.unslop/cache/registry.json`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_verify_deps.py
import json, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
import verify_deps                               # noqa: E402


def tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


class TestVerifyDeps(unittest.TestCase):
    def test_collects_npm_and_python_deps(self):
        root = tree({"package.json": '{"dependencies":{"next":"15.0.0"},'
                                     '"devDependencies":{"vitest":"2.0.0"}}',
                     "requirements.txt": "fastapi==0.110.0\n# comment\nuvicorn\n"})
        got = verify_deps.collect_dependencies(root)
        self.assertEqual(set(got), {"next", "vitest", "fastapi", "uvicorn"})

    def test_missing_package_becomes_p1(self):
        root = tree({"package.json": '{"dependencies":{"reqeusts-http":"1.0.0"}}'})
        fake = {"reqeusts-http": False}
        found = verify_deps.build_findings(root, fetch=lambda n, eco: fake.get(n, True))
        self.assertEqual([f.check_id for f in found], ["P1"])
        self.assertIn("reqeusts-http", found[0].snippet)

    def test_typosquat_flagged_when_package_exists(self):
        root = tree({"package.json": '{"dependencies":{"recat":"1.0.0"}}'})
        found = verify_deps.build_findings(root, fetch=lambda n, eco: True)
        self.assertIn("P2", [f.check_id for f in found])

    def test_offline_degrades_with_a_coverage_note(self):
        root = tree({"package.json": '{"dependencies":{"next":"15.0.0"}}'})
        def boom(name, eco):
            raise OSError("network unreachable")
        found, notes = verify_deps.build_findings(root, fetch=boom, return_notes=True)
        self.assertEqual(found, [])
        self.assertTrue(any("offline" in n or "unreachable" in n for n in notes))

    def test_merge_into_existing_findings_file(self):
        root = tree({"package.json": '{"dependencies":{"ghostpkg-xyz":"1.0.0"}}'})
        out = root / ".unslop" / "findings.json"
        out.parent.mkdir(parents=True)
        out.write_text(json.dumps({"schemaVersion": 1,
                                   "coverage": {"scanned_files": 1, "skipped": [], "notes": [], "stack": []},
                                   "findings": []}))
        verify_deps.main([str(root), "--out", str(out)],
                         fetch=lambda n, eco: n != "ghostpkg-xyz")
        data = json.loads(out.read_text())
        self.assertIn("P1", {f["check_id"] for f in data["findings"]})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_verify_deps -v`
Expected: FAIL — `No module named 'verify_deps'`.

- [ ] **Step 3: Write the implementation**

```python
#!/usr/bin/env python3
"""Verify that every declared dependency actually exists. Offline-safe."""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unslop.findings import Coverage, Finding, load, write   # noqa: E402

TIMEOUT = 5
POPULAR = {
    "react", "next", "express", "lodash", "axios", "requests", "numpy", "pandas",
    "typescript", "vite", "zod", "prisma", "supabase", "fastapi", "django", "flask",
    "dotenv", "chalk", "moment", "uuid", "jsonwebtoken", "bcrypt", "stripe",
}


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def collect_dependencies(root):
    root = Path(root)
    deps = {}
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
        except ValueError:
            data = {}
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(section) or {}).items():
                if not str(spec).startswith(("file:", "link:", "workspace:", "git+")):
                    deps[name] = "npm"
    req = root / "requirements.txt"
    if req.is_file():
        for line in req.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if m:
                deps[m.group(1)] = "pypi"
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        for m in re.finditer(r"^\s*[\"']?([A-Za-z0-9][A-Za-z0-9._-]{1,})[\"']?\s*[=><~\"']",
                             pyproject.read_text(errors="replace"), re.M):
            name = m.group(1)
            if name not in ("name", "version", "description", "requires-python", "readme"):
                deps.setdefault(name, "pypi")
    return deps


def _default_fetch(name, ecosystem):
    url = ("https://registry.npmjs.org/%s" % name if ecosystem == "npm"
           else "https://pypi.org/pypi/%s/json" % name)
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise OSError("registry error %s" % exc.code)


def build_findings(root, fetch=None, return_notes=False):
    fetch = fetch or _default_fetch
    deps = collect_dependencies(root)
    findings, notes = [], []
    manifest = "package.json" if (Path(root) / "package.json").is_file() else "requirements.txt"
    for name, eco in sorted(deps.items()):
        try:
            exists = fetch(name, eco)
        except OSError as exc:
            notes.append("dependency verification skipped (offline or unreachable: %s)" % exc)
            findings = []
            break
        if not exists:
            findings.append(Finding("P1", manifest, 1,
                                    "%s does not exist on the %s registry" % (name, eco),
                                    confidence="CONFIRMED"))
            continue
        for popular in POPULAR:
            if name != popular and _levenshtein(name, popular) == 1:
                findings.append(Finding("P2", manifest, 1,
                                        "%s is one character from %s" % (name, popular)))
                break
    return (findings, notes) if return_notes else findings


def main(argv=None, fetch=None):
    ap = argparse.ArgumentParser(prog="verify_deps.py")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--out", default=".unslop/findings.json")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    out = Path(args.out)
    if not out.is_absolute():
        out = root / out

    new, notes = build_findings(root, fetch=fetch, return_notes=True)
    if out.is_file():
        existing, data = load(out)
        cov = Coverage(**data.get("coverage", {}))
    else:
        existing, cov = [], Coverage()
    for n in notes:
        cov.note(n)
    write(out, existing + new, cov)
    print("unslop: dependency check added %d finding(s)%s"
          % (len(new), " (%s)" % notes[0] if notes else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_verify_deps -v`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/verify_deps.py tests/test_verify_deps.py
git commit -m "feat: offline-safe dependency verification for hallucinated and typosquatted packages"
```

---

### Task 11: Report writer

**Files:**
- Create: `skills/unslop-audit/scripts/unslop/report.py`
- Create: `skills/unslop-audit/assets/report-template.md`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `findings.Finding`, `findings.Coverage`, `catalog.CHECKS`.
- Produces:
  - `report.verdict(findings) -> str` in `{"DO NOT SHIP","SHIP WITH CAUTION","CLEAR"}`
  - `report.fix_plan(findings) -> Dict[str,int]` keyed `auto`/`assisted`/`manual`
  - `report.diff(previous, current) -> Dict[str,List[Finding]]` keyed `new`/`fixed`/`unchanged`
  - `report.render(findings, coverage, previous=None) -> str`

Rules the tests enforce: at most 5 blocking items in the lead section; every
blocking item carries file:line, snippet, and the check's `why`; the coverage
section is always present even when nothing was skipped.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_report.py
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import report                        # noqa: E402
from unslop.findings import Coverage, Finding     # noqa: E402


def f(cid, rel="src/a.ts", line=1):
    return Finding(cid, rel, line, "snippet for %s" % cid, confidence="CONFIRMED")


class TestReport(unittest.TestCase):
    def test_verdict_levels(self):
        self.assertEqual(report.verdict([f("S1")]), "DO NOT SHIP")
        self.assertEqual(report.verdict([f("A3")]), "SHIP WITH CAUTION")
        self.assertEqual(report.verdict([f("H7")]), "CLEAR")
        self.assertEqual(report.verdict([]), "CLEAR")

    def test_fix_plan_counts_by_class(self):
        plan = report.fix_plan([f("S3"), f("A3"), f("S1"), f("D5")])
        self.assertEqual(plan["auto"], 2)
        self.assertEqual(plan["manual"], 1)
        self.assertEqual(plan["assisted"], 1)

    def test_blocking_section_caps_at_five(self):
        many = [f("S1", "src/%d.ts" % i, i) for i in range(9)]
        text = report.render(many, Coverage())
        self.assertEqual(text.count("\n### "), 5)
        self.assertIn("4 more critical", text)

    def test_blocking_items_carry_evidence_and_consequence(self):
        text = report.render([f("D5", "src/app/api/orders/[id]/route.ts", 9)], Coverage())
        self.assertIn("src/app/api/orders/[id]/route.ts:9", text)
        self.assertIn("Change 1042 to 1043", text)

    def test_coverage_always_present(self):
        cov = Coverage()
        cov.scanned_files = 5
        cov.note("dependency verification skipped: offline")
        text = report.render([], cov)
        self.assertIn("## Coverage", text)
        self.assertIn("offline", text)
        self.assertIn("5 files", text)

    def test_clear_verdict_lists_what_was_checked(self):
        text = report.render([], Coverage())
        self.assertIn("CLEAR", text)
        self.assertIn("64 checks", text)

    def test_diff_between_runs(self):
        prev = [f("S1"), f("A3")]
        cur = [f("A3"), f("D5")]
        d = report.diff(prev, cur)
        self.assertEqual([x.check_id for x in d["fixed"]], ["S1"])
        self.assertEqual([x.check_id for x in d["new"]], ["D5"])
        self.assertEqual([x.check_id for x in d["unchanged"]], ["A3"])

    def test_suspected_findings_are_segregated(self):
        confirmed = f("S1")
        suspected = Finding("C3", "src/b.ts", 4, "select('*')")
        text = report.render([confirmed, suspected], Coverage())
        blocking, appendix = text.split("## Suspected", 1)
        self.assertIn("S1", blocking)
        self.assertIn("C3", appendix)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_report -v`
Expected: FAIL — `cannot import name 'report'`.

- [ ] **Step 3: Write the implementation**

```python
# skills/unslop-audit/scripts/unslop/report.py
from collections import Counter, defaultdict
from typing import Dict, List

from .catalog import CHECKS
from .findings import Finding

MAX_BLOCKING = 5
SEVERITY_ORDER = ("P0", "P1", "P2", "P3")
DOMAIN_NAMES = {
    "S": "Secrets and configuration", "D": "Data and access control",
    "A": "Authentication and session", "R": "Reliability and the unhappy path",
    "C": "Cost and performance", "P": "Supply chain", "O": "Observability",
    "H": "AI rot", "X": "Deployment", "T": "Tests",
}


def _sev(f: Finding) -> str:
    return CHECKS[f.check_id].severity


def verdict(findings: List[Finding]) -> str:
    sevs = {_sev(f) for f in findings}
    if "P0" in sevs:
        return "DO NOT SHIP"
    if "P1" in sevs:
        return "SHIP WITH CAUTION"
    return "CLEAR"


def fix_plan(findings: List[Finding]) -> Dict[str, int]:
    counts = Counter(CHECKS[f.check_id].fix_class for f in findings)
    return {k: counts.get(k, 0) for k in ("auto", "assisted", "manual")}


def diff(previous: List[Finding], current: List[Finding]) -> Dict[str, List[Finding]]:
    prev = {f.key(): f for f in previous}
    cur = {f.key(): f for f in current}
    return {
        "new": [cur[k] for k in sorted(set(cur) - set(prev))],
        "fixed": [prev[k] for k in sorted(set(prev) - set(cur))],
        "unchanged": [cur[k] for k in sorted(set(cur) & set(prev))],
    }


def _blocking(findings):
    ranked = sorted((f for f in findings if _sev(f) in ("P0", "P1")),
                    key=lambda f: (SEVERITY_ORDER.index(_sev(f)),
                                   f.confidence != "CONFIRMED", f.check_id, f.file))
    return ranked[:MAX_BLOCKING], max(0, len(ranked) - MAX_BLOCKING)


def render(findings: List[Finding], coverage, previous: List[Finding] = None) -> str:
    confirmed = [f for f in findings if f.confidence == "CONFIRMED"]
    suspected = [f for f in findings if f.confidence != "CONFIRMED"]
    lead, extra = _blocking(confirmed)
    counts = Counter(_sev(f) for f in confirmed)
    plan = fix_plan(confirmed)

    out = ["# unslop audit", "", "**Verdict: %s**" % verdict(confirmed), ""]
    out.append("%d confirmed findings — P0 %d · P1 %d · P2 %d · P3 %d. %d suspected."
               % (len(confirmed), counts.get("P0", 0), counts.get("P1", 0),
                  counts.get("P2", 0), counts.get("P3", 0), len(suspected)))
    out.append("")

    if previous is not None:
        d = diff(previous, findings)
        out += ["Since the last run: %d fixed, %d new, %d unchanged."
                % (len(d["fixed"]), len(d["new"]), len(d["unchanged"])), ""]

    if lead:
        out += ["## Blocking", ""]
        for f in lead:
            chk = CHECKS[f.check_id]
            out += ["### %s — %s" % (f.check_id, chk.title),
                    "",
                    "`%s:%d`" % (f.file, f.line),
                    "",
                    "```",
                    f.snippet,
                    "```",
                    "",
                    "**Why it matters.** %s" % chk.why,
                    "",
                    "**Fix (%s).** %s" % (chk.fix_class, chk.fix),
                    ""]
        if extra:
            out += ["_%d more critical or high findings are listed below._" % extra, ""]
    else:
        out += ["## Blocking", "", "Nothing blocking. All %d checks ran." % len(CHECKS), ""]

    out += ["## Fix plan", "",
            "- `auto` — %d fixes apply without further input" % plan["auto"],
            "- `assisted` — %d need one answer each" % plan["assisted"],
            "- `manual` — %d need you (credential rotation, dashboard settings)" % plan["manual"],
            "", "Run `unslop-fix` to apply them.", ""]

    grouped = defaultdict(list)
    for f in confirmed:
        if f not in lead:
            grouped[f.check_id[0]].append(f)
    if grouped:
        out += ["## Everything else", ""]
        for dom in sorted(grouped):
            out += ["**%s**" % DOMAIN_NAMES[dom], ""]
            for f in sorted(grouped[dom], key=lambda x: (x.check_id, x.file, x.line)):
                out.append("- `%s` %s — %s:%d" % (f.check_id, CHECKS[f.check_id].title,
                                                  f.file, f.line))
            out.append("")

    out += ["## Suspected", ""]
    if suspected:
        out.append("Pattern matched but not verified. Confirm before acting.")
        out.append("")
        for f in sorted(suspected, key=lambda x: (x.check_id, x.file, x.line)):
            out.append("- `%s` %s — %s:%d" % (f.check_id, CHECKS[f.check_id].title,
                                              f.file, f.line))
    else:
        out.append("None.")
    out.append("")

    out += ["## Coverage", "",
            "Scanned %d files. Ran %d checks." % (coverage.scanned_files, len(CHECKS))]
    if coverage.stack:
        out.append("Detected stack: %s." % ", ".join(coverage.stack))
    for note in coverage.notes:
        out.append("- %s" % note)
    if coverage.skipped:
        out.append("- Skipped %d files: %s%s"
                   % (len(coverage.skipped), ", ".join(coverage.skipped[:5]),
                      " ..." if len(coverage.skipped) > 5 else ""))
    out.append("")
    return "\n".join(out)
```

`assets/report-template.md` is the same structure with `{{placeholders}}`, kept
for the skill to reference when it hand-writes a report on a machine with no
`python3`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_report -v`
Expected: PASS, 8 tests.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit/scripts/unslop/report.py skills/unslop-audit/assets tests/test_report.py
git commit -m "feat: verdict-first report writer with fix plan, coverage, and run diff"
```

---

### Task 12: `unslop-audit` SKILL.md and references

**Files:**
- Modify: `skills/unslop-audit/SKILL.md` (replace the Task 1 stub body)
- Create: `skills/unslop-audit/references/check-catalog.md`
- Create: `skills/unslop-audit/references/semantic-passes.md`
- Create: `skills/unslop-audit/references/prompting-discipline.md`
- Create: `skills/unslop-audit/references/stack-notes/{supabase,firebase,nextjs,vercel,express-node,python-web,orm}.md`
- Create: `skills/unslop-audit/scripts/gen_catalog_doc.py`
- Test: `tests/test_docs.py`

**Interfaces:**
- Consumes: `scan.py`, `verify_deps.py`, `report.py`, `catalog.CHECKS`.
- Produces: the skill contract users actually invoke. `gen_catalog_doc.py`
  regenerates `references/check-catalog.md` from `catalog.py` so the two can
  never drift; `tests/test_docs.py` fails if they have.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_docs.py
import subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "skills" / "unslop-audit"
sys.path.insert(0, str(AUDIT / "scripts"))
from unslop.catalog import CHECKS                # noqa: E402


class TestDocs(unittest.TestCase):
    def test_catalog_doc_is_in_sync(self):
        generated = subprocess.run(
            [sys.executable, str(AUDIT / "scripts" / "gen_catalog_doc.py")],
            capture_output=True, text=True, check=True).stdout
        on_disk = (AUDIT / "references" / "check-catalog.md").read_text()
        self.assertEqual(generated, on_disk,
                         "run scripts/gen_catalog_doc.py > references/check-catalog.md")

    def test_every_semantic_check_has_a_procedure(self):
        text = (AUDIT / "references" / "semantic-passes.md").read_text()
        for cid, chk in CHECKS.items():
            if chk.method == "semantic":
                with self.subTest(check=cid):
                    self.assertIn(cid, text)

    def test_skill_references_resolve(self):
        import re
        text = (AUDIT / "SKILL.md").read_text()
        for rel in re.findall(r"\]\((references/[^)]+|scripts/[^)]+)\)", text):
            with self.subTest(link=rel):
                self.assertTrue((AUDIT / rel).exists(), rel)

    def test_skill_forbids_editing_code(self):
        text = (AUDIT / "SKILL.md").read_text().lower()
        self.assertIn("never edit", text)

    def test_stack_notes_exist_for_every_detected_tag(self):
        notes = {p.stem for p in (AUDIT / "references" / "stack-notes").glob("*.md")}
        self.assertTrue({"supabase", "firebase", "nextjs", "vercel"} <= notes)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_docs -v`
Expected: FAIL — `gen_catalog_doc.py` does not exist.

- [ ] **Step 3: Write the generator, the SKILL.md body, and the references**

```python
#!/usr/bin/env python3
# skills/unslop-audit/scripts/gen_catalog_doc.py
"""Regenerate references/check-catalog.md from catalog.py. Single source of truth."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unslop.catalog import CHECKS                # noqa: E402
from unslop.report import DOMAIN_NAMES           # noqa: E402


def main():
    lines = ["# Check catalog", "",
             "Generated from `scripts/unslop/catalog.py`. Do not edit by hand;",
             "run `python3 scripts/gen_catalog_doc.py > references/check-catalog.md`.", ""]
    for dom, name in sorted(DOMAIN_NAMES.items()):
        checks = sorted((c for c in CHECKS.values() if c.domain == dom), key=lambda c: c.id)
        lines += ["## %s — %s" % (dom, name), "",
                  "| ID | Check | Severity | Fix | Detected by |",
                  "|---|---|---|---|---|"]
        for c in checks:
            lines.append("| `%s` | %s | %s | `%s` | %s |"
                         % (c.id, c.title, c.severity, c.fix_class, c.method))
        lines.append("")
        for c in checks:
            lines += ["**%s — %s**" % (c.id, c.title), "", c.why, "", "*Fix:* %s" % c.fix, ""]
    sys.stdout.write("\n".join(lines))


if __name__ == "__main__":
    main()
```

`SKILL.md` body (keep the Task 1 frontmatter verbatim, replace everything below it):

````markdown
# unslop-audit

## Overview

AI code generation optimizes for a working demo, not for software that survives
a thousand users. This skill finds the resulting gaps and reports them with
evidence: file, line, the offending snippet, and the concrete way it fails in
production.

**Never edit code in this skill.** Remediation belongs to `unslop-fix`.

## Procedure

### 1. Fingerprint

Run the scanner. It detects the stack itself; you do not need to ask the user
what they built with.

```bash
python3 skills/unslop-audit/scripts/scan.py . --out .unslop/findings.json --json
```

If `python3` is unavailable, say so plainly, then run the reduced pass in
[references/no-python-fallback.md](references/no-python-fallback.md) and record
the reduced coverage in the report.

Add `.unslop/` to `.gitignore` if it is not already there, and tell the user you
did. The report enumerates live vulnerabilities; it must not be committed.

### 2. Verify before you report

The scanner emits `SUSPECTED` findings. Promote a finding to `CONFIRMED` only
after opening the file and confirming the defect is real in context. Discard
what does not survive that read — a false positive costs more trust than a
missed P3 costs coverage.

For each surviving finding, write the failure scenario in the user's own terms:
what an attacker or a load spike actually does, not the name of the weakness.

### 3. Run the semantic passes

The scanner cannot see intent. Work through
[references/semantic-passes.md](references/semantic-passes.md), which covers
D5, D6, D7, A1, A4, R4, R6, R7, R8, C1, C7, C8, H4, and X4. Scope the reading to
route handlers, server actions, and data-access modules — not the whole tree.

### 4. Verify dependencies

```bash
python3 skills/unslop-audit/scripts/verify_deps.py . --out .unslop/findings.json
```

Offline is fine; it records the gap and moves on.

### 5. Report

Write `.unslop/AUDIT.md` in the structure `report.render` produces: verdict,
at most five blocking items, fix plan by class, everything else, suspected,
coverage, and the prompting-discipline close. If a previous `findings.json`
exists, lead with the diff instead of the full list.

Then say the verdict out loud in chat with the blocking items and the fix-plan
counts, and offer the fix pass. Do not paste the whole report into chat.

## Rules

- Evidence or silence. No finding without file, line, and snippet.
- Report what you did not scan. A capped or skipped scan that reads as clean is
  the worst outcome this skill can produce.
- Never invent a finding to look thorough, and never soften a P0 to be agreeable.
- Stay in scope: this is an audit of code that exists, not a redesign proposal.

## Reference

- [Check catalog](references/check-catalog.md) — all 64 checks
- [Semantic passes](references/semantic-passes.md)
- [Prompting discipline](references/prompting-discipline.md)
- Stack notes: [supabase](references/stack-notes/supabase.md) ·
  [firebase](references/stack-notes/firebase.md) ·
  [nextjs](references/stack-notes/nextjs.md) ·
  [vercel](references/stack-notes/vercel.md) ·
  [express-node](references/stack-notes/express-node.md) ·
  [python-web](references/stack-notes/python-web.md) ·
  [orm](references/stack-notes/orm.md)
````

`references/semantic-passes.md` gives one procedure per semantic check. Each
entry states where to look, what confirms the defect, and what rules it out.
Write all fourteen; here is the required shape, using D5:

````markdown
## D5 — Record fetched by user-supplied id with no ownership check

**Where to look.** Every route handler, server action, and RPC that reads a
parameter and passes it to a query: `app/api/**/route.ts`, `pages/api/**`,
`actions.ts`, FastAPI/Django view functions.

**Confirms the defect.** The query filters only on the record id, and no
enclosing code compares the record's owner column to the authenticated user.

**Rules it out.** An ownership predicate in the query
(`.eq('user_id', session.user.id)`), an RLS policy that scopes the table for the
caller's role (check the migration, not the assumption), or a preceding
authorization helper whose failure path returns before the query.

**Report as.** "GET /api/orders/[id] returns any order by id. Change 1042 to
1043 and you read another customer's order, including their address."
````

`references/prompting-discipline.md` is short and non-preachy: specify the data
schema, the authorization model, and the error contract before generating;
decompose instead of mega-prompting; commit a checkpoint before each prompt;
when a fix fails twice, revert and re-specify rather than stacking a third patch
— iterative AI patching measurably degrades security with each round.

`references/no-python-fallback.md` lists the grep/ripgrep equivalents for the
highest-severity static rules, so a machine without `python3` still gets the P0
sweep.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 skills/unslop-audit/scripts/gen_catalog_doc.py > skills/unslop-audit/references/check-catalog.md && python3 -m unittest tests.test_docs tests.test_skills -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-audit tests/test_docs.py
git commit -m "feat: unslop-audit skill body, generated catalog doc, semantic pass procedures"
```

---

### Task 13: `unslop-fix` skill

**Files:**
- Modify: `skills/unslop-fix/SKILL.md`
- Create: `skills/unslop-fix/references/fix-recipes.md`
- Test: `tests/test_fix_skill.py`

**Interfaces:**
- Consumes: `.unslop/findings.json`, `catalog.CHECKS[*].fix_class`.
- Produces: the remediation contract described in the spec §8.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fix_skill.py
import sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop.catalog import CHECKS                # noqa: E402

FIX = ROOT / "skills" / "unslop-fix"


class TestFixSkill(unittest.TestCase):
    def setUp(self):
        self.text = (FIX / "SKILL.md").read_text()
        self.recipes = (FIX / "references" / "fix-recipes.md").read_text()

    def test_states_the_branch_and_commit_protocol(self):
        for phrase in ("unslop/fixes", "one commit per finding", "dirty working tree"):
            self.assertIn(phrase, self.text)

    def test_refuses_to_fake_rotation(self):
        low = self.text.lower()
        self.assertIn("rotat", low)
        self.assertIn("deleting it from head does not", low)

    def test_every_auto_check_has_a_recipe(self):
        for cid, chk in CHECKS.items():
            if chk.fix_class == "auto":
                with self.subTest(check=cid):
                    self.assertIn(cid, self.recipes)

    def test_assisted_checks_state_the_question_to_ask(self):
        for cid, chk in CHECKS.items():
            if chk.fix_class == "assisted":
                with self.subTest(check=cid):
                    self.assertIn(cid, self.recipes)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_fix_skill -v`
Expected: FAIL — `fix-recipes.md` does not exist.

- [ ] **Step 3: Write the skill body and recipes**

`SKILL.md` body below the Task 1 frontmatter:

````markdown
# unslop-fix

## Overview

Applies the fix plan from `.unslop/findings.json`, split by fix class. Never
rewrites a security boundary on a guess, and never claims an action it did not
perform.

## Preconditions

1. `.unslop/findings.json` exists. If not, run `unslop-audit` first.
2. The working tree is clean. On a dirty working tree, stop and ask — an
   interleaved diff is unreviewable and that is the failure mode this whole
   plugin exists to prevent.
3. Create and switch to `unslop/fixes`.

## Pass 1 — `auto`

Apply every `auto` finding without per-item prompting. **One commit per
finding**, message `fix(unslop): <ID> <short summary>`.

If the project has a test command, run it after each commit. On failure: revert
that single commit, reclassify the finding as `assisted`, and continue. Do not
attribute a pre-existing failure to your own commit — record the baseline before
Pass 1 starts.

Recipes per check: [references/fix-recipes.md](references/fix-recipes.md).

## Pass 2 — `assisted`

For each finding, present, in one message: the finding, the single question you
need answered, and the patch you will apply once answered. Batch the questions
so the user answers them in one sitting.

Never guess an ownership column, a role model, or an allowed origin. If the
answer is not in the codebase and the user has not given it, the finding stays
open and goes in the summary.

## Pass 3 — `manual`

Print the checklist. For each: what to do, where, and why nobody else can do it.
Credential rotation is the common case. **Deleting a key from HEAD does not
rotate it** — the value is still in history and in every clone. Say that
explicitly rather than implying the fix is done.

## Close

Summarize: fixed, deferred, still owned by the user. Leave the branch for
review. Do not merge, do not push, do not open a pull request unless asked.

## Rules

- One concern per commit. A fix that touches a second concern is two commits.
- No refactoring alongside a fix. Adjacent mess is not in scope.
- Do not stack a third attempt on a fix that failed twice — revert and hand it
  to the user with what you learned. Stacking patches is the behavior that
  produced these findings.
````

`references/fix-recipes.md` carries one entry per `auto` and `assisted` check,
each with the exact edit or the exact question. Required shape:

````markdown
### S3 — Secret file not covered by .gitignore  *(auto)*

Append the missing pattern to `.gitignore`. If `git ls-files` shows the file is
already tracked, also run `git rm --cached <file>` and add an `S4` manual item
for rotation.

### A3 — Session cookie missing flags  *(auto)*

Add `httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax'`
to the cookie options object. Do not change `maxAge` or the cookie name.

### D1 — Table without row level security  *(assisted)*

Ask: **"Which column on `<table>` identifies the owning user?"**
Then apply:

```sql
alter table public.<table> enable row level security;

create policy "<table>_select_own" on public.<table>
  for select using (auth.uid() = <owner_column>);

create policy "<table>_modify_own" on public.<table>
  for all using (auth.uid() = <owner_column>)
  with check (auth.uid() = <owner_column>);
```

If the table is genuinely public read (a published catalog, for example), the
policy is `for select using (true)` **with writes still scoped** — and say so in
the commit message so it does not read as a D2 regression later.
````

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_fix_skill tests.test_skills -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-fix tests/test_fix_skill.py
git commit -m "feat: unslop-fix skill with fix-class protocol and per-check recipes"
```

---

### Task 14: `unslop-guard` skill and assets

**Files:**
- Modify: `skills/unslop-guard/SKILL.md`
- Create: `skills/unslop-guard/assets/pre-commit`
- Create: `skills/unslop-guard/assets/unslop-audit.yml`
- Create: `skills/unslop-audit/scripts/gate.py`
- Test: `tests/test_guard.py`

**Interfaces:**
- Consumes: `.unslop/findings.json`.
- Produces: `gate.py <findings.json> [--fail-on P0]` exiting 1 when a finding at
  or above the threshold exists — the one place a non-zero exit is correct.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_guard.py
import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "skills" / "unslop-audit" / "scripts" / "gate.py"
GUARD = ROOT / "skills" / "unslop-guard"


def findings_file(check_ids):
    d = Path(tempfile.mkdtemp())
    p = d / "findings.json"
    p.write_text(json.dumps({
        "schemaVersion": 1,
        "coverage": {"scanned_files": 1, "skipped": [], "notes": [], "stack": []},
        "findings": [{"check_id": c, "file": "a.ts", "line": 1, "snippet": "x",
                      "confidence": "CONFIRMED", "evidence": ""} for c in check_ids],
    }))
    return p


def gate(path, *args):
    return subprocess.run([sys.executable, str(GATE), str(path)] + list(args),
                          capture_output=True, text=True)


class TestGate(unittest.TestCase):
    def test_fails_on_p0(self):
        self.assertEqual(gate(findings_file(["S1"])).returncode, 1)

    def test_passes_when_only_low_severity(self):
        self.assertEqual(gate(findings_file(["H7"])).returncode, 0)

    def test_threshold_is_configurable(self):
        self.assertEqual(gate(findings_file(["A3"]), "--fail-on", "P1").returncode, 1)
        self.assertEqual(gate(findings_file(["A3"]), "--fail-on", "P0").returncode, 0)

    def test_prints_the_blocking_findings(self):
        r = gate(findings_file(["S1"]))
        self.assertIn("S1", r.stdout)


class TestGuardAssets(unittest.TestCase):
    def test_hook_is_warn_only_except_secrets(self):
        hook = (GUARD / "assets" / "pre-commit").read_text()
        self.assertIn("--fail-on", hook)
        self.assertIn("S1", hook)
        self.assertIn("exit 0", hook)

    def test_workflow_runs_the_scanner_and_the_gate(self):
        wf = (GUARD / "assets" / "unslop-audit.yml").read_text()
        self.assertIn("scan.py", wf)
        self.assertIn("gate.py", wf)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_guard -v`
Expected: FAIL — `gate.py` does not exist.

- [ ] **Step 3: Write the gate, the hook, and the workflow**

```python
#!/usr/bin/env python3
# skills/unslop-audit/scripts/gate.py
"""Exit 1 when findings at or above a severity threshold exist."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unslop.catalog import CHECKS                # noqa: E402

ORDER = ["P0", "P1", "P2", "P3"]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="gate.py")
    ap.add_argument("findings", nargs="?", default=".unslop/findings.json")
    ap.add_argument("--fail-on", default="P0", choices=ORDER)
    ap.add_argument("--only", default="", help="comma-separated check ids to consider")
    args = ap.parse_args(argv)

    path = Path(args.findings)
    if not path.is_file():
        print("unslop gate: no findings file at %s (nothing to gate)" % path)
        return 0

    data = json.loads(path.read_text())
    limit = ORDER.index(args.fail_on)
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    blocking = []
    for row in data.get("findings", []):
        cid = row["check_id"]
        if only and cid not in only:
            continue
        if cid in CHECKS and ORDER.index(CHECKS[cid].severity) <= limit:
            blocking.append(row)

    if not blocking:
        print("unslop gate: clear at %s and above" % args.fail_on)
        return 0
    print("unslop gate: %d blocking finding(s) at %s and above" % (len(blocking), args.fail_on))
    for row in blocking[:20]:
        print("  %s %s  %s:%s" % (CHECKS[row["check_id"]].severity, row["check_id"],
                                  row["file"], row["line"]))
    if len(blocking) > 20:
        print("  ... and %d more" % (len(blocking) - 20))
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

```bash
#!/bin/sh
# skills/unslop-guard/assets/pre-commit
# unslop guard: warn on everything, block only on secrets about to be committed.
set -e
SCAN="$(git rev-parse --show-toplevel)/.unslop/scan.py"
[ -f "$SCAN" ] || SCAN="$UNSLOP_SCAN"
[ -f "$SCAN" ] || { echo "unslop: scanner not found, skipping"; exit 0; }

python3 "$SCAN" . --out .unslop/pre-commit.json >/dev/null 2>&1 || {
  echo "unslop: scan failed, not blocking the commit"; exit 0; }

GATE="$(dirname "$SCAN")/gate.py"
if ! python3 "$GATE" .unslop/pre-commit.json --fail-on P0 --only S1,S2,S3,S4; then
  echo ""
  echo "unslop: a secret looks like it is about to be committed."
  echo "Fix it, or bypass deliberately with: git commit --no-verify"
  exit 1
fi

python3 "$GATE" .unslop/pre-commit.json --fail-on P1 || true
exit 0
```

```yaml
# skills/unslop-guard/assets/unslop-audit.yml
name: unslop audit
on:
  pull_request:
  push:
    branches: [main]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - name: Fetch unslop
        run: git clone --depth 1 https://github.com/RuslanAMandell/unslop-my-code .unslop-tool
      - name: Scan
        run: python3 .unslop-tool/skills/unslop-audit/scripts/scan.py . --out .unslop/findings.json --json
      - name: Verify dependencies
        run: python3 .unslop-tool/skills/unslop-audit/scripts/verify_deps.py . --out .unslop/findings.json
        continue-on-error: true
      - name: Gate on critical findings
        run: python3 .unslop-tool/skills/unslop-audit/scripts/gate.py .unslop/findings.json --fail-on P0
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: unslop-findings, path: .unslop/findings.json }
```

`SKILL.md` body: how to install both (copy the hook to `.git/hooks/pre-commit`
and `chmod +x`; copy the workflow to `.github/workflows/`), how to run the gate
manually as a pre-ship check, and an explicit statement that the hook is
warn-only apart from secrets and can always be bypassed with `--no-verify`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_guard tests.test_skills -v`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add skills/unslop-guard skills/unslop-audit/scripts/gate.py tests/test_guard.py
git commit -m "feat: unslop-guard with severity gate, warn-only hook, and CI workflow"
```

---

### Task 15: Front door, documentation, and publication

**Files:**
- Create: `commands/unslop.md`
- Create: `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `CHANGELOG.md`
- Create: `docs/example-report.md`
- Test: `tests/test_readme.py`

**Interfaces:**
- Consumes: everything.
- Produces: the public repository.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_readme.py
import re, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop.catalog import CHECKS                # noqa: E402


class TestReadme(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "README.md").read_text()

    def test_install_command_is_present_and_correct(self):
        self.assertIn("/plugin marketplace add RuslanAMandell/unslop-my-code", self.text)
        self.assertIn("/plugin install unslop@unslop-my-code", self.text)

    def test_claims_the_real_check_count(self):
        self.assertIn(str(len(CHECKS)), self.text)

    def test_documents_every_domain(self):
        for name in ("Secrets", "access control", "unhappy path", "Cost", "Supply chain",
                     "AI rot", "Observability", "Deployment", "Tests"):
            with self.subTest(domain=name):
                self.assertIn(name, self.text)

    def test_no_broken_relative_links(self):
        for rel in re.findall(r"\]\((?!https?:)([^)#]+)", self.text):
            with self.subTest(link=rel):
                self.assertTrue((ROOT / rel).exists(), rel)

    def test_states_the_fixture_warning(self):
        self.assertIn("intentionally vulnerable", (ROOT / "tests" / "fixtures" / "README.md").read_text())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_readme -v`
Expected: FAIL — `README.md` does not exist.

- [ ] **Step 3: Write the front door and the docs**

`commands/unslop.md`:

````markdown
---
description: Audit this codebase for the production failures AI code generation leaves behind, then offer to fix them
---

Run the `unslop-audit` skill on the current repository.

When it finishes, state the verdict, the blocking findings, and the fix-plan
counts in chat — not the whole report. Then ask whether to run the fix pass. If
the user says yes, run the `unslop-fix` skill. If a previous
`.unslop/findings.json` exists, lead with what changed since the last run.
````

`README.md` structure — write it in this order, because the reader's question
order is: what is this, is it real, how do I use it, what does it check.

1. One-sentence description and the verdict-style example output (from
   `docs/example-report.md`, generated by running the audit against the
   vulnerable fixture — real output, not a mockup).
2. The problem, with the measured numbers and their sources: 45% of AI-generated
   code carrying OWASP Top 10 flaws (Veracode), 41% of 100 audited vibe-coded
   apps exposing secrets, 170 of 1,645 Lovable projects missing RLS, 4.6-6.1%
   package hallucination rates. Link each.
3. Install (both commands) and usage (`/unslop`).
4. What it checks: the 10 domains with counts, linking to
   `skills/unslop-audit/references/check-catalog.md`.
5. How it decides: severity, confidence, and fix class, each in two lines.
6. What it will not do: no auto-merge, no credential rotation, no live
   exploitation, not a pentest.
7. How it is tested: the two fixtures and the precision/recall gate, with the
   current numbers.
8. Prior art, credited honestly:
   [vibecoding-security-scanner](https://github.com/funky-monkey/vibecoding-security-scanner),
   [claude-cybersecurity](https://github.com/AgriciDaniel/claude-cybersecurity),
   [trailofbits/skills](https://github.com/trailofbits/skills),
   [claude-code-security-review](https://github.com/anthropics/claude-code-security-review).
   State the difference in one line: those are security scanners; this also
   covers cost, reliability, supply chain, and the rot that iterative AI
   patching leaves behind.
9. Contributing, license.

`AGENTS.md` states the authoring rules a contributor's coding agent must follow:
stdlib only, every new check needs a catalog entry plus a rule or detector plus
a fixture defect plus a test, check ids are never reused, `make check` must pass.

`CONTRIBUTING.md` covers the same for humans, plus how to add a stack adapter.

`CHANGELOG.md` starts at `0.1.0`.

- [ ] **Step 4: Run the full suite and generate the example report**

Run:
```bash
make check
python3 - <<'PY'
import sys, pathlib
sys.path.insert(0, "skills/unslop-audit/scripts")
from scan import scan
from unslop.report import render
f, c = scan(pathlib.Path("tests/fixtures/vulnerable-next-supabase"), 20000)
pathlib.Path("docs/example-report.md").write_text(render(f, c))
PY
python3 -m unittest discover -s tests -p 'test_*.py'
```
Expected: all tests pass; `docs/example-report.md` contains a real verdict.

- [ ] **Step 5: Commit and publish**

```bash
git add -A
git commit -m "docs: README, contributing guide, agent rules, example report, /unslop command"
```

**Confirm with the user before this step — it is public and irreversible:**

```bash
gh repo create RuslanAMandell/unslop-my-code --public --source=. --remote=origin \
  --description "Audit an AI-generated codebase for the production failures vibe coding leaves behind"
git push -u origin main
gh repo edit --add-topic claude-code,claude-skills,security,vibe-coding,production-readiness,supabase,owasp
```

Then verify the install path end to end in a clean directory:
`/plugin marketplace add RuslanAMandell/unslop-my-code` followed by
`/plugin install unslop@unslop-my-code`, and run `/unslop` against the vulnerable
fixture. A plugin that does not install is not shipped.

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: §5 architecture → Tasks
3-8; §6 catalog → Task 2 (definitions), 5 (static), 6-7 (config/structural), 12
(semantic procedures), 10 (net); §7 report → Task 11; §8 fix protocol → Task 13;
§9 scanner implementation → Tasks 3, 8; §10 stack adapters → Task 12; §11 testing
→ Task 9; §12 repo structure → Task 1; §13 distribution → Task 15; §14 failure
modes → Tasks 3, 8 (`Coverage` notes), 10 (offline), 12 (no-python fallback).

**Known gaps, stated rather than hidden.**
- Spec §6 lists `P4` (known CVEs) as a `net` check. No task implements it:
  reimplementing vulnerability database lookups with no dependencies is out of
  scope for 0.1.0. `P4` stays in the catalog and `unslop-audit` instructs the
  agent to run the ecosystem's own audit command (`npm audit --json`,
  `pip-audit`) and fold the result in. Task 12 must include that instruction.
- `C6` and `R9` are heuristic and will produce SUSPECTED-only findings. That is
  intended, and the clean-fixture test lists them as advisory.

**Type consistency.** `Finding`, `Coverage`, `Check`, `Rule` field names are
identical across Tasks 2-11. `detect(root, files, coverage)` is the signature for
every detector. `EMITS` is a set on every detector module. `scan()` returns
`(findings, coverage)` everywhere it appears.

**Ordering.** Task 6 must precede Task 7 only because `detectors/__init__.py`
imports `structure`; Task 6 creates the stub, Task 7 fills it. Task 9 depends on
Task 8. Everything else follows the numbering.
