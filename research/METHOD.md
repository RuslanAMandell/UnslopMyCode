# Method

## Corpus

283 public repositories, sampled through the GitHub code search API by the build
markers each AI app builder leaves behind:

| Marker | Tool | Repos |
|---|---|---|
| `lovable-tagger` in `package.json` | Lovable | 99 |
| `bolt.new` in `README.md` | Bolt | 100 |
| `v0.dev` in `README.md` | v0 | 84 |

Forks excluded. 280 cloned successfully; 3 failed and are excluded from every
number.

This is a convenience sample of *public* projects, not a random sample of all
AI-generated software. Projects whose authors published them to GitHub may be
more or less careful than those who did not. That limit applies to every number
here.

## Scanning

Each repo is cloned shallow (`--depth 1`) and scanned with the same code the
plugin ships. Two checks are excluded from every statistic because a shallow
clone cannot support them: `H1` (version-control history) and `S4` (secrets in
history).

## Verification, and what it changed

Raw scanner output is not evidence. Three rounds of hand-verification were run:
a random sample of findings per critical check was read, judged, and every false
positive turned into a fix plus a regression test built from the real string.

The headline number moved each round as false positives were removed:

| Round | Repos with a critical finding | What was fixed |
|---|---|---|
| Initial | 47.0% | `H3` ignored `@/` path aliases, so most modules looked orphaned; `H8` emitted one finding per duplicated block |
| After round 1 | 39.9% | `D8` matched the *word* "update" near a `${}` (`Failed to update user: ${err}`); `O1` matched the word "token" inside log messages |
| After round 2 | 32.0% | `S1` flagged CSS selectors and enum members; `S2` flagged Paddle client tokens and GA measurement ids, which are public by design; `D1`/`D2`/`D4` applied to non-Supabase Postgres, where RLS is not the expected control; `D2` flagged deliberately public read policies |
| After round 3 | 28.9% | `S1` flagged Supabase **anon keys**, which are signed JWTs meant to ship to the browser; `D3` flagged `backend/` and prompt templates; `S4` flagged a vendored `certifi` CA bundle |
| Final | **27.5%** | `S1` flagged OAuth URLs (`token_uri: "https://..."`); `D3` flagged setup instructions rendered inside a component |

Every one of those fixes is covered by a regression test using the verbatim
string from the real repository. See `TestCorpusFalsePositives*` in
`tests/test_ruleset.py`.

## What these numbers support

- The prevalence figures are **lower bounds on the checked population and upper
  bounds per check**: the scanner reports `SUSPECTED` until an agent verifies a
  finding by reading the code, and the published figures are unverified scanner
  output apart from the sampled rounds above.
- `S3` (a committed `.env`) and `D9` (`allow read, write: if true`) are
  structural facts about a file, so they are effectively exact.
- `D1`, `D2`, `D4` are measured only against repositories where Supabase is
  actually in use.
- `D8` detects *interpolated* SQL. Without taint analysis it cannot prove the
  interpolated value is attacker-controlled, so it overstates injection.
- `A6`, `O1` and `D3` retain known residual false positives, estimated from the
  samples at roughly one in four for `A6` and lower for the others.

## What they do not support

- Nothing here says AI-generated code is worse than human-written code. There is
  no human-written control group in this study.
- Nothing here is a claim about any individual repository or author.
- The absence of a finding is not evidence of safety. The scanner checks 64
  specific things.
