# Fixtures — intentionally vulnerable sample code

**These directories contain deliberately insecure code. Never deploy them, never
copy from them, and never run them against real infrastructure.** They exist so
the scanner's precision and recall can be measured in CI.

- `vulnerable-next-supabase/` — a Next.js + Supabase app with one planted defect
  per scanner-detectable check. `expected.json` lists what was planted.
- `clean-next-supabase/` — the same app with every defect repaired. Any finding
  here is a false positive and fails the build.

## Credential safety

Every credential-shaped value is a random, non-resolvable fake. The fixtures
deliberately avoid provider-prefixed shapes (`AKIA…`, `sk_live_…`, PEM headers)
so that publishing this repository does not trip secret-scanning push
protection. Those provider patterns are covered by unit tests in
`tests/test_ruleset.py`, where the prefixes are concatenated at runtime.

Neither fixture has a lockfile or `node_modules`, and neither is runnable. They
are source text for the scanner to read, not an application.
