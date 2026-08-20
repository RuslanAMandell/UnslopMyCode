# Method

## Corpus

283 public repositories, sampled through the GitHub code search API by the build
markers each AI app builder leaves behind:

| Marker | Tool | Repos |
|---|---|---|
| `lovable-tagger` in `package.json` | Lovable | 99 |
| `bolt.new` in `README.md` | Bolt | 100 |
| `v0.dev` in `README.md` | v0 | 84 |

Forks excluded. 281 cloned successfully; 2 failed and are excluded from every
number.

This is a convenience sample of *public* projects, not a random sample of all
AI-generated software. Projects whose authors published them to GitHub may be
more or less careful than those who did not. That limit applies to every number
here.

## Scanning

Each repo is cloned shallow (`--depth 1`) and scanned with the same code the
plugin ships.

## Scoping decisions

Raw scanner output is not evidence. A random sample of findings per critical
check was read by hand against the source file it points at. Those readings set
where each check draws its line. Each check below states what it measures and
the population or shape it is bounded to.

| Checks | What the check measures | Why it is bounded that way |
|---|---|---|
| `D1`, `D2`, `D4` | Row level security, measured only in repositories where Supabase is in use | RLS is the authorization control Supabase expects. A self-hosted Postgres app that authorizes in its own backend is not misconfigured for lacking it. |
| `D2` | A permissive policy, counted only when the grant covers writes | Public read on published content is a deliberate design choice. |
| `S1` | Hardcoded provider credentials, excluding Supabase anon keys | Anon keys are signed JWTs that ship to the browser by design. The `service_role` key is the one that matters, and it is still counted. |
| `S1` | Hardcoded provider credentials, excluding values that are structurally not secrets: CSS selectors, dotted identifiers, camelCase words, enum members, URLs, template placeholders | A credential is an opaque high-entropy string. These shapes are identifiers, and an identifier is not a secret. |
| `S2` | Secrets behind a client-visible env prefix, excluding token names that are public by design (Paddle client tokens, Google Analytics measurement ids) | Reaching the browser is what those values are for. |
| `D8` | SQL assembled by interpolation, requiring a real statement shape (`SELECT..FROM`, `UPDATE..SET`, `INSERT INTO`, `DELETE FROM`) plus interpolation of a non-constant | Interpolation of a module constant is not injection, and the statement shape is what separates a query from prose that happens to contain a SQL keyword. |
| `O1` | Sensitive data written to logs, requiring a sensitive identifier to be passed to the call | A word such as "token" inside a message string is text. Nothing sensitive leaves the process. |
| `H2`, `H3`, `H6`, `H7`, `H8` | Structure, with test and fixture trees skipped, scripts carrying a main guard treated as entrypoints, imports resolved through configured path aliases (`@/`), and the file-size check applied to source files only | Fixtures are repetitive on purpose. Nothing imports an entrypoint, by definition. A long prose file is not a long module. |
| `H1`, `S4` | Excluded from every statistic | Both read version-control history, and a shallow clone carries none. |

Each boundary is covered by a regression test built from a verbatim string taken
from a corpus repository: `TestIdentifierVsProse`, `TestPublicCredentialScoping`
and `TestUrlAndInstructionScoping` in `tests/test_ruleset.py`,
`TestTestPathAwareness` and `TestDatabaseCheckScoping` in
`tests/test_detectors_config.py`, and `TestPathAliasResolution` and
`TestEntrypointAndProseScoping` in `tests/test_detectors_structure.py`.

Within these boundaries, 27.4% of the 281 repositories carry at least one
critical finding.

## What these numbers support

- The prevalence figures are **lower bounds on the checked population and upper
  bounds per check**: the scanner reports `SUSPECTED` until an agent verifies a
  finding by reading the code, and the published figures are unverified scanner
  output apart from the hand-read samples described above.
- `S3` (a committed `.env`) and `D9` (`allow read, write: if true`) are
  structural facts about a file, so they are effectively exact.
- `D1`, `D2`, `D4` are measured only against repositories where Supabase is
  actually in use.
- `D8` detects *interpolated* SQL. Without taint analysis it cannot prove the
  interpolated value is attacker-controlled, so it overstates injection.
- `A6`, `O1` and `D3` are known to over-report. The hand-read samples put the
  residual over-count at roughly one in four for `A6` and lower for the others.

## What they do not support

- Nothing here says AI-generated code is worse than human-written code. There is
  no human-written control group in this study.
- Nothing here is a claim about any individual repository or author.
- The absence of a finding is not evidence of safety. The scanner checks 64
  specific things.
