# unslop audit

**Verdict: DO NOT SHIP**

20 confirmed findings - P0 5, P1 3, P2 7, P3 5. 28 suspected.

## Blocking

### D1 - Table created without row level security

`supabase/migrations/0001_init.sql:1`

```
create table profiles ... (row level security never enabled)
```

**Why it matters.** With RLS off, the public anon key reads and writes every row in the table. This is the single most common way vibe-coded apps leak their entire user database.

**Fix (assisted).** ALTER TABLE ... ENABLE ROW LEVEL SECURITY and add an explicit per-operation policy.

### D2 - Row level security policy that grants everything

`supabase/migrations/0002_policies.sql:3`

```
create policy "orders_all_access" on public.orders
```

**Why it matters.** A USING (true) policy is RLS in name only - every row still matches for every caller.

**Fix (assisted).** Scope the policy to the owning user, e.g. USING (auth.uid() = user_id).

### D4 - Storage bucket is public or has no policy

`supabase/migrations/0002_policies.sql:6`

```
storage.buckets (id, name, public)
  values ('invoices', 'invoices', true
```

**Why it matters.** Uploaded files - IDs, invoices, private images - are fetchable by anyone who can guess or enumerate a path.

**Fix (assisted).** Make the bucket private and serve files through signed URLs.

### S3 - Secret file not covered by .gitignore

`.env:1`

```
.env exists and is not matched by .gitignore
```

**Why it matters.** One `git add .` publishes your .env to a public repository, where credential scanners find it within minutes.

**Fix (auto).** Add the pattern to .gitignore; if the file is already tracked, untrack it and rotate everything in it.

### S4 - Secret present in git history

`.env:1`

```
.env was committed at some point in history
```

**Why it matters.** The credential is still fetchable from any clone even though it is gone from the current files.

**Fix (manual).** Rotate the credential. History rewriting is optional; rotation is not.

_3 more critical or high findings are listed below._

## Everything else

**AI rot**

- `H2` Near-duplicate file left behind by iterative patching - src/components/Checkout-fixed.tsx:1
- `H3` Orphan module that nothing imports - src/components/Checkout-fixed.tsx:1
- `H3` Orphan module that nothing imports - src/components/Checkout.tsx:1
- `H3` Orphan module that nothing imports - src/lib/logger.ts:1
- `H3` Orphan module that nothing imports - src/lib/unused-helper.ts:1

**Observability**

- `O4` No error tracking configured - .:1
- `O5` No health check endpoint - .:1

**Supply chain**

- `P3` Missing or out-of-sync lockfile - package.json:1

**Reliability and the unhappy path**

- `R1` No error boundary in the component tree - src:1

**Secrets and configuration**

- `S5` Env var used in code but missing from .env.example - src/lib/supabase.ts:6
- `S5` Env var used in code but missing from .env.example - src/lib/supabase.ts:9
- `S6` Source maps published to production - next.config.js:4

**Tests**

- `T1` No tests, or a placeholder test script - package.json:1
- `T3` No continuous integration workflow - .:1

**Deployment**

- `X2` Missing security response headers - next.config.js:1

## Fix plan

- `auto` - 9 fixes apply without further input
- `assisted` - 8 need one answer each
- `manual` - 3 need you (credential rotation, dashboard settings)

Run `unslop-fix` to apply them.

## Suspected

Pattern matched but not verified. Confirm before acting.

- `A2` JWT verification disabled, weak, or bypassable - src/app/api/login/route.ts:20
- `A3` Session cookie missing httpOnly, secure, or sameSite - src/app/api/login/route.ts:22
- `A6` Password stored without a modern KDF - src/app/api/login/route.ts:9
- `C2` Filtered or sorted column with no index - src/app/api/login/route.ts:12
- `C2` Filtered or sorted column with no index - src/app/api/orders/[id]/route.ts:9
- `C2` Filtered or sorted column with no index - src/app/dashboard/page.tsx:9
- `C3` Unbounded select with no limit - src/app/api/login/route.ts:13
- `C3` Unbounded select with no limit - src/app/api/orders/[id]/route.ts:10
- `C3` Unbounded select with no limit - src/app/api/search/route.ts:7
- `C3` Unbounded select with no limit - src/app/dashboard/page.tsx:9
- `C3` Unbounded select with no limit - src/app/dashboard/page.tsx:12
- `C5` Aggressive polling interval - src/app/dashboard/page.tsx:20
- `D3` Admin/service_role key reachable from client code - src/lib/supabase.ts:6
- `D8` SQL assembled by string interpolation - src/app/api/search/route.ts:7
- `H6` Large block of commented-out code - src/lib/legacy.ts:5
- `H7` File past the size threshold - src/lib/legacy.ts:1
- `O1` Secret or personal data written to logs - src/lib/logger.ts:3
- `O1` Secret or personal data written to logs - src/lib/logger.ts:4
- `O2` Internal error detail returned to the client - src/app/api/orders/[id]/route.ts:18
- `O3` console.log used as production logging - src/lib/legacy.ts:10
- `O3` console.log used as production logging - src/lib/logger.ts:2
- `R2` HTTP response used without checking status - src/app/api/orders/[id]/route.ts:13
- `R3` Network call with no timeout or abort signal - src/app/api/orders/[id]/route.ts:13
- `R5` Error swallowed by an empty or log-only catch - src/app/api/search/route.ts:11
- `S1` Hardcoded provider credential in source - src/lib/supabase.ts:4
- `S2` Secret exposed through a client-visible env prefix - .env:3
- `S2` Secret exposed through a client-visible env prefix - src/lib/supabase.ts:6
- `X3` Redirect target taken from user input - src/app/api/search/route.ts:15

## Coverage

Scanned 17 files. Ran 64 checks.
Detected stack: nextjs, npm, react, supabase.

- history scan covered added-file paths only, not full content diffs
- no .env.example: every referenced env var is reported as undocumented
